use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};
use toppy_core::audit::{
    append_event_signed, default_audit_log_path, now_unix_ms, ship_entry,
    verify_chain_with_signing_key, AuditEvent, AuditShipConfig,
};
use toppy_core::auth::{extract_jwt_identity, AuthIdentity};
use toppy_core::config::{ClientAuthConfig, SessionRateLimit};
use toppy_core::oidc;
use toppy_core::policy::{Decision, Policy, Target};
use toppy_core::rate::TokenBucket;
use url::Url;

use bytes::Bytes;
use h3::ext::Protocol;

use h3::quic::StreamId;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use toppy_proto::masque::{HttpDatagram, CONNECT_UDP_CONTEXT_ID};
mod rate_copy;

/// Toppy command-line interface
#[derive(Parser)]
#[command(name = "toppy", author, version, about = "Toppy CLI for managing MASQUE connections", long_about = None)]
struct Cli {
    /// Subcommands for the CLI
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run diagnostic checks and output a report in JSON
    Doctor {
        /// Output JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Acquire and cache an auth token
    Login {
        /// Print the resolved token to stdout (token mode only)
        #[arg(long)]
        print_token: bool,
    },
    /// Start a local TCP forwarder to an allowed target
    Up {
        /// Target to connect to (ip:port)
        #[arg(long)]
        target: String,
        /// Local listen address (ip:port)
        #[arg(long)]
        listen: String,
        /// Exit after a single connection
        #[arg(long)]
        once: bool,
    },

    /// Start a local UDP proxy to an allowed target over CONNECT-UDP
    Udp {
        /// Target to connect to (ip:port)
        #[arg(long)]
        target: String,
        /// Local UDP listen address (ip:port)
        #[arg(long)]
        listen: String,
    },

    /// Audit log utilities
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Verify the local audit log hash chain
    Verify {
        /// Path to the audit JSONL file
        #[arg(long)]
        path: Option<String>,
        /// Signing key for verifying signed entries
        #[arg(long)]
        signing_key: Option<String>,
    },
}

fn audit_log_path_from_env_or_config() -> Option<std::path::PathBuf> {
    if let Ok(value) = std::env::var("TOPPY_AUDIT_LOG") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed.into());
        }
    }
    if let Ok((cfg, _)) = toppy_core::config::load_config() {
        if let Some(p) = cfg.audit_log_path {
            let trimmed = p.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed.into());
            }
        }
    }
    None
}

fn audit_signing_key_from_env_or_config() -> Option<Vec<u8>> {
    if let Ok(value) = std::env::var("TOPPY_AUDIT_SIGNING_KEY") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed.into_bytes());
        }
    }
    if let Ok((cfg, _)) = toppy_core::config::load_config() {
        if let Some(value) = cfg.audit_signing_key {
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed.into_bytes());
            }
        }
    }
    None
}

fn audit_ship_config_from_env_or_config() -> Option<AuditShipConfig> {
    let env_url = std::env::var("TOPPY_AUDIT_SHIP_URL").ok();
    let env_token = std::env::var("TOPPY_AUDIT_SHIP_TOKEN").ok();
    let env_timeout = std::env::var("TOPPY_AUDIT_SHIP_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok());

    let mut url = env_url.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let mut token = env_token.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let mut timeout_secs = env_timeout;

    if let Ok((cfg, _)) = toppy_core::config::load_config() {
        if url.is_none() {
            url = cfg.audit_ship_url.and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            });
        }
        if token.is_none() {
            token = cfg.audit_ship_token.and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            });
        }
        if timeout_secs.is_none() {
            timeout_secs = cfg.audit_ship_timeout_secs;
        }
    }

    let url = url?;
    Some(AuditShipConfig {
        url,
        token,
        timeout_secs: timeout_secs.unwrap_or(3),
    })
}

fn current_actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn try_audit_event(action: &str, target: &str, allowed: bool, reason: Option<String>) {
    try_audit_event_with_subject(action, target, allowed, reason, None);
}

fn try_audit_event_with_subject(
    action: &str,
    target: &str,
    allowed: bool,
    reason: Option<String>,
    auth_subject: Option<String>,
) {
    let path = audit_log_path_from_env_or_config().unwrap_or_else(default_audit_log_path);
    let event = AuditEvent {
        actor: current_actor(),
        action: action.to_string(),
        target: target.to_string(),
        allowed,
        auth_subject,
        reason,
    };
    let signing_key = audit_signing_key_from_env_or_config();
    match append_event_signed(path, now_unix_ms(), event, signing_key.as_deref()) {
        Ok(entry) => {
            if let Some(cfg) = audit_ship_config_from_env_or_config() {
                if let Err(err) = ship_entry(&entry, &cfg) {
                    eprintln!("audit ship failed: {}", err);
                }
            }
        }
        Err(err) => eprintln!("audit log write failed: {}", err),
    }
}

#[derive(Debug)]
struct UdpPeerState {
    stream_id: StreamId,
    last_active: Instant,
    ingress_limiter: Option<TokenBucket>,
    egress_limiter: Option<TokenBucket>,
    ingress_rate_drops: u64,
    egress_rate_drops: u64,
}

#[derive(Debug, Default)]
struct UdpProxyMetrics {
    peers_created: u64,
    ingress_datagrams: u64,
    egress_datagrams: u64,
    ingress_rate_drops: u64,
    egress_rate_drops: u64,
    idle_evictions: u64,
    cap_drops: u64,
}

fn auth_identity_from_token(token: Option<&str>) -> AuthIdentity {
    token
        .and_then(|value| extract_jwt_identity(value).ok())
        .unwrap_or_default()
}

fn best_effort_auth_identity(cfg: &toppy_core::config::Config) -> AuthIdentity {
    match cfg.resolve_auth_token() {
        Ok(Some(token)) => auth_identity_from_token(Some(&token)),
        _ => AuthIdentity::default(),
    }
}

fn udp_idle_timeout() -> Duration {
    std::env::var("TOPPY_UDP_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60))
}

fn udp_max_peers() -> usize {
    std::env::var("TOPPY_UDP_MAX_PEERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(128)
}

fn udp_limiter(limit: SessionRateLimit) -> Option<TokenBucket> {
    if limit.is_enabled() {
        Some(TokenBucket::new(limit.burst_bytes, limit.bytes_per_sec))
    } else {
        None
    }
}

fn udp_datagram_allowed(bucket: &mut Option<TokenBucket>, bytes: usize, started_at: Instant) -> bool {
    match bucket.as_mut() {
        Some(bucket) => bucket.try_take(bytes as u64, started_at.elapsed()),
        None => true,
    }
}

fn log_udp_metrics(metrics: &UdpProxyMetrics, active_peers: usize) {
    eprintln!(
        "udp metrics: active_peers={} peers_created={} ingress_datagrams={} egress_datagrams={} ingress_rate_drops={} egress_rate_drops={} idle_evictions={} cap_drops={}",
        active_peers,
        metrics.peers_created,
        metrics.ingress_datagrams,
        metrics.egress_datagrams,
        metrics.ingress_rate_drops,
        metrics.egress_rate_drops,
        metrics.idle_evictions,
        metrics.cap_drops,
    );
}

fn parse_socket_addr(label: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid {} {}: {}", label, value, e))
}

fn wait_for_auth_code(redirect_uri: &str, expected_state: &str) -> Result<String, String> {
    let url = Url::parse(redirect_uri)
        .map_err(|e| format!("invalid redirect_uri {}: {}", redirect_uri, e))?;
    let host = url
        .host_str()
        .ok_or_else(|| "redirect_uri must include host".to_string())?;
    let port = url.port().unwrap_or(80);
    let path = url.path().to_string();
    let listen = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&listen)
        .map_err(|e| format!("failed to bind redirect listener {}: {}", listen, e))?;

    for stream in listener.incoming() {
        let mut stream = stream.map_err(|e| format!("redirect accept failed: {}", e))?;
        let mut buffer = Vec::new();
        let mut temp = [0u8; 1024];
        loop {
            let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..n]);
            if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buffer.len() > 8192 {
                break;
            }
        }

        let request = String::from_utf8_lossy(&buffer);
        let mut lines = request.lines();
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let _method = parts.next().unwrap_or("");
        let uri = parts.next().unwrap_or("");

        let full_url = format!("http://{}{}", listen, uri);
        let parsed =
            Url::parse(&full_url).map_err(|e| format!("invalid redirect request: {}", e))?;

        if parsed.path() != path {
            send_redirect_response(&mut stream, 404, "Not Found", "invalid path");
            continue;
        }

        let mut code = None;
        let mut state = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.to_string()),
                "state" => state = Some(value.to_string()),
                _ => {}
            }
        }

        if state.as_deref() != Some(expected_state) {
            send_redirect_response(&mut stream, 400, "Bad Request", "state mismatch");
            return Err("state mismatch in redirect".to_string());
        }

        let code = code.ok_or_else(|| "missing code in redirect".to_string())?;
        send_redirect_response(
            &mut stream,
            200,
            "OK",
            "login complete; you can close this tab",
        );
        return Ok(code);
    }

    Err("redirect listener closed without receiving code".to_string())
}

fn send_redirect_response(stream: &mut TcpStream, status: u16, status_text: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn load_ca_certs_pem(path: &std::path::Path) -> Result<RootCertStore, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("failed to read ca_cert_path {}: {}", path.display(), e))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse CA certs from {}: {}", path.display(), e))?;
    if certs.is_empty() {
        return Err(format!("no CA certificates found in {}", path.display()));
    }
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| format!("failed to add CA cert {}: {}", path.display(), e))?;
    }
    Ok(store)
}

fn proxy_connection(
    mut inbound: TcpStream,
    target: SocketAddr,
    limit: SessionRateLimit,
) -> io::Result<()> {
    let mut outbound = TcpStream::connect(target)?;
    let _ = inbound.set_nodelay(true);
    let _ = outbound.set_nodelay(true);

    let mut inbound_clone = inbound.try_clone()?;
    let mut outbound_clone = outbound.try_clone()?;

    let t1 = thread::spawn(move || {
        rate_copy::copy_rate_limited(&mut inbound_clone, &mut outbound, limit)
    });
    let t2 = thread::spawn(move || {
        rate_copy::copy_rate_limited(&mut outbound_clone, &mut inbound, limit)
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

fn proxy_once(inbound: TcpStream, target: SocketAddr, limit: SessionRateLimit) -> io::Result<()> {
    proxy_connection(inbound, target, limit)
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Doctor { json }) => {
            // Invoke the doctor checks from toppy_core and print JSON
            let report = toppy_core::doctor::doctor_check();
            let auth_subject = toppy_core::config::load_config()
                .ok()
                .map(|(cfg, _)| best_effort_auth_identity(&cfg))
                .and_then(|identity| identity.subject);
            // Best-effort audit log: record the overall outcome.
            try_audit_event_with_subject(
                "doctor",
                "doctor",
                report.overall != "fail",
                Some(format!("overall={}", report.overall)),
                auth_subject,
            );
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{}", json),
                    Err(e) => eprintln!("Failed to serialize doctor report: {}", e),
                }
            } else {
                println!("doctor: {}", report.overall);
                println!("version: {}", report.version);
                for check in report.checks {
                    println!("- [{}] {}: {}", check.status, check.id, check.summary);
                }
            }
        }
        Some(Commands::Login { print_token }) => {
            let audit_ok = |reason: String| {
                try_audit_event("login", "login", true, Some(reason));
            };
            let audit_fail = |reason: String| {
                try_audit_event("login", "login", false, Some(reason));
            };

            let (cfg, path) = match toppy_core::config::load_config() {
                Ok((cfg, path)) => (cfg, path),
                Err(err) => {
                    eprintln!("Failed to load config: {}", err);
                    audit_fail(format!("config load failed: {}", err));
                    std::process::exit(1);
                }
            };
            if let Err(err) = cfg.validate() {
                eprintln!("Config validation failed ({}): {}", path.display(), err);
                audit_fail(format!("config validation failed: {}", err));
                std::process::exit(1);
            }

            match cfg.auth.as_ref() {
                None | Some(ClientAuthConfig::Token { .. }) => {
                    let token = cfg
                        .resolve_auth_token()
                        .map_err(|e| format!("failed to resolve auth token: {}", e));
                    match token {
                        Ok(Some(token)) => {
                            if print_token {
                                println!("{}", token);
                                audit_ok("mode=token printed=true".to_string());
                            } else {
                                println!(
                                    "auth: token mode (configured). Use `toppy up` / `toppy doctor`."
                                );
                                audit_ok("mode=token printed=false".to_string());
                            }
                        }
                        Ok(None) => {
                            eprintln!(
                                "auth: token mode requires a token. Set `auth_token = \"...\"` or `[auth] mode = \"token\"` with `token = \"...\"`."
                            );
                            audit_fail("mode=token missing token".to_string());
                            std::process::exit(2);
                        }
                        Err(err) => {
                            eprintln!("auth: {}", err);
                            audit_fail(format!("mode=token resolve failed: {}", err));
                            std::process::exit(1);
                        }
                    }
                }
                Some(ClientAuthConfig::OidcDeviceCode { .. }) => {
                    let oidc_cfg = match cfg.oidc_device_code_config() {
                        Ok(Some(cfg)) => cfg,
                        Ok(None) => {
                            eprintln!("auth: OIDC config missing");
                            audit_fail("mode=oidc_device_code config missing".to_string());
                            std::process::exit(3);
                        }
                        Err(err) => {
                            eprintln!("auth: {}", err);
                            audit_fail(format!("mode=oidc_device_code config error: {}", err));
                            std::process::exit(3);
                        }
                    };

                    let provider = match oidc::discover_provider(&oidc_cfg.issuer) {
                        Ok(provider) => provider,
                        Err(err) => {
                            eprintln!("auth: oidc discovery failed: {}", err);
                            audit_fail(format!("mode=oidc_device_code discovery failed: {}", err));
                            std::process::exit(3);
                        }
                    };
                    let device = match oidc::request_device_code(&provider, &oidc_cfg) {
                        Ok(device) => device,
                        Err(err) => {
                            eprintln!("auth: device code request failed: {}", err);
                            audit_fail(format!(
                                "mode=oidc_device_code device_code failed: {}",
                                err
                            ));
                            std::process::exit(3);
                        }
                    };

                    println!("auth: complete login in your browser");
                    if let Some(url) = device.verification_uri_complete.as_deref() {
                        println!("auth: {}", url);
                    } else {
                        println!("auth: visit {}", device.verification_uri);
                        println!("auth: enter code {}", device.user_code);
                    }

                    let token = match oidc::poll_device_code(&provider, &oidc_cfg, &device) {
                        Ok(token) => token,
                        Err(err) => {
                            eprintln!("auth: device code login failed: {}", err);
                            audit_fail(format!("mode=oidc_device_code poll failed: {}", err));
                            std::process::exit(3);
                        }
                    };

                    let cache_path = match oidc::save_token_cache(&oidc_cfg, &token) {
                        Ok(path) => path,
                        Err(err) => {
                            eprintln!("auth: failed to write token cache: {}", err);
                            audit_fail(format!(
                                "mode=oidc_device_code cache write failed: {}",
                                err
                            ));
                            std::process::exit(3);
                        }
                    };

                    if print_token {
                        println!("{}", token.access_token);
                        audit_ok(format!(
                            "mode=oidc_device_code printed=true cache={}",
                            cache_path.display()
                        ));
                    } else {
                        println!("auth: token cached at {}", cache_path.display());
                        audit_ok(format!(
                            "mode=oidc_device_code printed=false cache={}",
                            cache_path.display()
                        ));
                    }
                }
                Some(ClientAuthConfig::OidcAuthCodePkce { .. }) => {
                    let oidc_cfg = match cfg.oidc_auth_code_config() {
                        Ok(Some(cfg)) => cfg,
                        Ok(None) => {
                            eprintln!("auth: OIDC auth-code config missing");
                            audit_fail("mode=oidc_auth_code_pkce config missing".to_string());
                            std::process::exit(3);
                        }
                        Err(err) => {
                            eprintln!("auth: {}", err);
                            audit_fail(format!("mode=oidc_auth_code_pkce config error: {}", err));
                            std::process::exit(3);
                        }
                    };

                    let provider = match oidc::discover_provider(&oidc_cfg.issuer) {
                        Ok(provider) => provider,
                        Err(err) => {
                            eprintln!("auth: oidc discovery failed: {}", err);
                            audit_fail(format!(
                                "mode=oidc_auth_code_pkce discovery failed: {}",
                                err
                            ));
                            std::process::exit(3);
                        }
                    };

                    let (verifier, challenge) = match oidc::generate_pkce_pair() {
                        Ok(pair) => pair,
                        Err(err) => {
                            eprintln!("auth: pkce generation failed: {}", err);
                            audit_fail(format!("mode=oidc_auth_code_pkce pkce failed: {}", err));
                            std::process::exit(3);
                        }
                    };
                    let state = match oidc::generate_state() {
                        Ok(state) => state,
                        Err(err) => {
                            eprintln!("auth: state generation failed: {}", err);
                            audit_fail(format!("mode=oidc_auth_code_pkce state failed: {}", err));
                            std::process::exit(3);
                        }
                    };
                    let auth_url =
                        match oidc::build_authorize_url(&provider, &oidc_cfg, &challenge, &state) {
                            Ok(url) => url,
                            Err(err) => {
                                eprintln!("auth: build authorize url failed: {}", err);
                                audit_fail(format!("mode=oidc_auth_code_pkce url failed: {}", err));
                                std::process::exit(3);
                            }
                        };

                    println!("auth: open this URL in a browser to continue login:");
                    println!("auth: {}", auth_url);

                    let code = match wait_for_auth_code(&oidc_cfg.redirect_uri, &state) {
                        Ok(code) => code,
                        Err(err) => {
                            eprintln!("auth: redirect handling failed: {}", err);
                            audit_fail(format!(
                                "mode=oidc_auth_code_pkce redirect failed: {}",
                                err
                            ));
                            std::process::exit(3);
                        }
                    };

                    let token =
                        match oidc::exchange_auth_code(&provider, &oidc_cfg, &code, &verifier) {
                            Ok(token) => token,
                            Err(err) => {
                                eprintln!("auth: auth code exchange failed: {}", err);
                                audit_fail(format!(
                                    "mode=oidc_auth_code_pkce exchange failed: {}",
                                    err
                                ));
                                std::process::exit(3);
                            }
                        };

                    let cache_path = match oidc::save_token_cache_auth_code(&oidc_cfg, &token) {
                        Ok(path) => path,
                        Err(err) => {
                            eprintln!("auth: failed to write token cache: {}", err);
                            audit_fail(format!(
                                "mode=oidc_auth_code_pkce cache write failed: {}",
                                err
                            ));
                            std::process::exit(3);
                        }
                    };

                    if print_token {
                        println!("{}", token.access_token);
                        audit_ok(format!(
                            "mode=oidc_auth_code_pkce printed=true cache={}",
                            cache_path.display()
                        ));
                    } else {
                        println!("auth: token cached at {}", cache_path.display());
                        audit_ok(format!(
                            "mode=oidc_auth_code_pkce printed=false cache={}",
                            cache_path.display()
                        ));
                    }
                }
                Some(ClientAuthConfig::Saml { .. }) => {
                    let oidc_cfg = match cfg.oidc_device_code_config() {
                        Ok(Some(cfg)) => cfg,
                        Ok(None) => {
                            eprintln!("auth: SAML broker config missing");
                            audit_fail("mode=saml config missing".to_string());
                            std::process::exit(3);
                        }
                        Err(err) => {
                            eprintln!("auth: {}", err);
                            audit_fail(format!("mode=saml config error: {}", err));
                            std::process::exit(3);
                        }
                    };

                    println!("auth: SAML login uses an OIDC broker device-code flow");

                    let provider = match oidc::discover_provider(&oidc_cfg.issuer) {
                        Ok(provider) => provider,
                        Err(err) => {
                            eprintln!("auth: oidc discovery failed: {}", err);
                            audit_fail(format!("mode=saml discovery failed: {}", err));
                            std::process::exit(3);
                        }
                    };
                    let device = match oidc::request_device_code(&provider, &oidc_cfg) {
                        Ok(device) => device,
                        Err(err) => {
                            eprintln!("auth: device code request failed: {}", err);
                            audit_fail(format!("mode=saml device_code failed: {}", err));
                            std::process::exit(3);
                        }
                    };

                    println!("auth: complete login in your browser");
                    if let Some(url) = device.verification_uri_complete.as_deref() {
                        println!("auth: {}", url);
                    } else {
                        println!("auth: visit {}", device.verification_uri);
                        println!("auth: enter code {}", device.user_code);
                    }

                    let token = match oidc::poll_device_code(&provider, &oidc_cfg, &device) {
                        Ok(token) => token,
                        Err(err) => {
                            eprintln!("auth: device code login failed: {}", err);
                            audit_fail(format!("mode=saml poll failed: {}", err));
                            std::process::exit(3);
                        }
                    };

                    let cache_path = match oidc::save_token_cache(&oidc_cfg, &token) {
                        Ok(path) => path,
                        Err(err) => {
                            eprintln!("auth: failed to write token cache: {}", err);
                            audit_fail(format!("mode=saml cache write failed: {}", err));
                            std::process::exit(3);
                        }
                    };

                    if print_token {
                        println!("{}", token.access_token);
                        audit_ok(format!(
                            "mode=saml printed=true cache={}",
                            cache_path.display()
                        ));
                    } else {
                        println!("auth: token cached at {}", cache_path.display());
                        audit_ok(format!(
                            "mode=saml printed=false cache={}",
                            cache_path.display()
                        ));
                    }
                }
            }
        }
        Some(Commands::Up {
            target,
            listen,
            once,
        }) => {
            let (cfg, path) = match toppy_core::config::load_config() {
                Ok((cfg, path)) => (cfg, path),
                Err(err) => {
                    eprintln!("Failed to load config: {}", err);
                    try_audit_event("up", &target, false, Some("config load failed".to_string()));
                    std::process::exit(1);
                }
            };
            if let Err(err) = cfg.validate() {
                eprintln!("Config validation failed ({}): {}", path.display(), err);
                try_audit_event(
                    "up",
                    &target,
                    false,
                    Some(format!("config validation failed: {}", err)),
                );
                std::process::exit(1);
            }

            let auth_identity = best_effort_auth_identity(&cfg);
            let auth_subject = auth_identity.subject.clone();

            let session_rate_limit = cfg.session_rate_limit();

            let target_addr = match parse_socket_addr("target", &target) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            let listen_addr = match parse_socket_addr("listen", &listen) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };

            let policy = match cfg.policy.as_ref() {
                Some(policy_cfg) => match Policy::from_config(policy_cfg) {
                    Ok(policy) => policy,
                    Err(err) => {
                        eprintln!("Policy config invalid: {}", err);
                        std::process::exit(1);
                    }
                },
                None => Policy { allow: Vec::new() },
            };
            let target_policy = Target {
                ip: target_addr.ip(),
                port: target_addr.port(),
                subject: auth_identity.subject.clone(),
                claims: auth_identity.claims.clone(),
            };
            match policy.evaluate(&target_policy) {
                Decision::Allow => {}
                Decision::Deny { reason } => {
                    eprintln!("Policy denied: {}", reason);
                    try_audit_event_with_subject(
                        "up",
                        &target,
                        false,
                        Some(reason),
                        auth_subject.clone(),
                    );
                    std::process::exit(2);
                }
            }

            let listener = match TcpListener::bind(listen_addr) {
                Ok(listener) => listener,
                Err(err) => {
                    eprintln!("Failed to bind {}: {}", listen_addr, err);
                    std::process::exit(1);
                }
            };
            let local_addr = match listener.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("Failed to read local addr: {}", err);
                    std::process::exit(1);
                }
            };
            println!("toppy up listening on {} -> {}", local_addr, target_addr);

            // Record that the forwarder was started. Subsequent connection failures are still
            // reported to stderr by the proxy threads.
            try_audit_event_with_subject(
                "up",
                &target,
                true,
                Some(format!("listening={}", local_addr)),
                auth_subject,
            );

            let mut once_failed = false;
            for stream in listener.incoming() {
                match stream {
                    Ok(inbound) => {
                        if once {
                            if let Err(err) = proxy_once(inbound, target_addr, session_rate_limit) {
                                eprintln!("proxy connection failed: {}", err);
                                once_failed = true;
                            }
                            break;
                        }
                        let target = target_addr;
                        let limit = session_rate_limit;
                        thread::spawn(move || {
                            if let Err(err) = proxy_connection(inbound, target, limit) {
                                eprintln!("proxy connection failed: {}", err);
                            }
                        });
                    }
                    Err(err) => {
                        eprintln!("accept failed: {}", err);
                        if once {
                            break;
                        }
                    }
                }
            }

            if once_failed {
                std::process::exit(1);
            }
        }
        Some(Commands::Udp { target, listen }) => {
            let target_for_audit = target.clone();
            let target_for_err = target.clone();
            let (cfg, path) = match toppy_core::config::load_config() {
                Ok((cfg, path)) => (cfg, path),
                Err(err) => {
                    eprintln!("Failed to load config: {}", err);
                    try_audit_event(
                        "udp",
                        &target,
                        false,
                        Some("config load failed".to_string()),
                    );
                    std::process::exit(1);
                }
            };
            if let Err(err) = cfg.validate() {
                eprintln!("Config validation failed ({}): {}", path.display(), err);
                try_audit_event(
                    "udp",
                    &target,
                    false,
                    Some(format!("config validation failed: {}", err)),
                );
                std::process::exit(1);
            }

            let session_rate_limit = cfg.session_rate_limit();

            let target_addr = match parse_socket_addr("target", &target) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            let listen_addr = match parse_socket_addr("listen", &listen) {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            let auth_token = match cfg.resolve_auth_token() {
                Ok(Some(t)) => t,
                Ok(None) => {
                    eprintln!("Missing auth token (auth_token/auth config)");
                    std::process::exit(1);
                }
                Err(err) => {
                    eprintln!("Failed to resolve auth token: {}", err);
                    std::process::exit(1);
                }
            };
            let auth_identity = auth_identity_from_token(Some(&auth_token));
            let auth_subject = auth_identity.subject.clone();

            let policy = match cfg.policy.as_ref() {
                Some(policy_cfg) => match Policy::from_config(policy_cfg) {
                    Ok(policy) => policy,
                    Err(err) => {
                        eprintln!("Policy config invalid: {}", err);
                        std::process::exit(1);
                    }
                },
                None => Policy { allow: Vec::new() },
            };
            let target_policy = Target {
                ip: target_addr.ip(),
                port: target_addr.port(),
                subject: auth_identity.subject.clone(),
                claims: auth_identity.claims.clone(),
            };
            match policy.evaluate(&target_policy) {
                Decision::Allow => {}
                Decision::Deny { reason } => {
                    eprintln!("Policy denied: {}", reason);
                    try_audit_event_with_subject(
                        "udp",
                        &target,
                        false,
                        Some(reason),
                        auth_subject.clone(),
                    );
                    std::process::exit(2);
                }
            }

            let host = cfg
                .gateway
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    eprintln!("Missing config: gateway");
                    std::process::exit(1);
                });
            let port = cfg.port.unwrap_or_else(|| {
                eprintln!("Missing config: port");
                std::process::exit(1);
            });
            let server_name = cfg
                .server_name
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    eprintln!("Missing config: server_name");
                    std::process::exit(1);
                });
            let ca_cert_path = cfg
                .ca_cert_path
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    eprintln!("Missing config: ca_cert_path");
                    std::process::exit(1);
                });
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("failed to start tokio runtime: {}", e);
                    std::process::exit(1);
                });
            let auth_subject_for_run = auth_subject.clone();

            let run = rt.block_on(async move {
                let addr = format!("{}:{}", host, port);
                let addr = addr
                    .to_socket_addrs()
                    .map_err(|e| format!("resolve {} failed: {}", addr, e))?
                    .next()
                    .ok_or_else(|| format!("resolve {} returned no addresses", addr))?;

                let ca_store = load_ca_certs_pem(std::path::Path::new(ca_cert_path))?;
                let mut crypto = rustls::ClientConfig::builder()
                    .with_root_certificates(ca_store)
                    .with_no_client_auth();
                crypto.alpn_protocols = vec![b"h3".to_vec()];
                let crypto = QuicClientConfig::try_from(crypto)
                    .map_err(|e| format!("quic client config failed: {}", e))?;

                let mut client_config = ClientConfig::new(std::sync::Arc::new(crypto));
                client_config
                    .transport_config(std::sync::Arc::new(quinn::TransportConfig::default()));

                let bind_addr = "0.0.0.0:0"
                    .parse::<SocketAddr>()
                    .map_err(|e| e.to_string())?;
                let mut endpoint = Endpoint::client(bind_addr)
                    .map_err(|e| format!("quic client setup failed: {}", e))?;
                endpoint.set_default_client_config(client_config);

                let connecting = endpoint
                    .connect(addr, server_name)
                    .map_err(|e| format!("quic connect setup failed: {}", e))?;
                let connection = tokio::time::timeout(Duration::from_millis(1500), connecting)
                    .await
                    .map_err(|_| "quic connect timed out".to_string())?
                    .map_err(|e| format!("quic connect failed: {}", e))?;

                let is_h3 = connection
                    .handshake_data()
                    .and_then(|any| any.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|hs| hs.protocol)
                    .as_deref()
                    == Some(b"h3");
                if !is_h3 {
                    connection.close(0u32.into(), b"no-h3");
                    endpoint.wait_idle().await;
                    return Err("gateway did not negotiate ALPN h3".to_string());
                }

                let quinn_conn = h3_quinn::Connection::new(connection);
                let (mut h3_conn, mut sender) = h3::client::builder()
                    .enable_extended_connect(true)
                    .enable_datagram(true)
                    .build::<_, _, Bytes>(quinn_conn)
                    .await
                    .map_err(|e| format!("h3 client init failed: {e:?}"))?;

                let udp = tokio::net::UdpSocket::bind(listen_addr)
                    .await
                    .map_err(|e| format!("udp bind {} failed: {}", listen_addr, e))?;
                let local_addr = udp
                    .local_addr()
                    .map_err(|e| format!("failed to read local addr: {}", e))?;
                let idle_timeout = udp_idle_timeout();
                let max_peers = udp_max_peers();
                let rate_limit_start = Instant::now();
                let mut cleanup = tokio::time::interval(Duration::from_secs(5));
                cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                println!("toppy udp listening on {} -> {}", local_addr, target_addr);
                eprintln!(
                    "udp session controls: idle_timeout={}s max_peers={} rate_limit={}",
                    idle_timeout.as_secs(),
                    max_peers,
                    if session_rate_limit.is_enabled() { "enabled" } else { "disabled" }
                );
                try_audit_event_with_subject(
                    "udp",
                    &target_for_audit,
                    true,
                    Some(format!("listening={}", local_addr)),
                    auth_subject_for_run.clone(),
                );

                let mut peer_state: HashMap<SocketAddr, UdpPeerState> = HashMap::new();
                let mut stream_to_peer: HashMap<StreamId, SocketAddr> = HashMap::new();
                let mut stream_keepalive: Vec<(StreamId, Box<dyn std::any::Any + Send>)> = Vec::new();
                let mut metrics = UdpProxyMetrics::default();

                let mut dg_reader = h3_conn.get_datagram_reader();
                let mut buf = vec![0u8; 2048];

                loop {
                    tokio::select! {
                        recv = udp.recv_from(&mut buf) => {
                            let (n, peer) = recv.map_err(|e| format!("udp recv failed: {}", e))?;
                            let stream_id = match peer_state.get(&peer).map(|state| state.stream_id) {
                                Some(id) => id,
                                None => {
                                    if peer_state.len() >= max_peers {
                                        metrics.cap_drops = metrics.cap_drops.saturating_add(1);
                                        eprintln!("udp peer cap reached: dropping datagram from {}", peer);
                                        continue;
                                    }

                                    let uri: http::Uri = format!(
                                        "https://{}/.well-known/masque/udp-forward/{}/{}/",
                                        host,
                                        target_addr.ip(),
                                        target_addr.port()
                                    )
                                    .parse()
                                    .map_err(|e| format!("invalid uri: {e}"))?;

                                    let mut req = http::Request::builder()
                                        .method(http::Method::CONNECT)
                                        .uri(uri)
                                        .header("authorization", format!("Bearer {}", auth_token))
                                        .body(())
                                        .map_err(|e| format!("request build failed: {e}"))?;
                                    req.extensions_mut().insert(Protocol::CONNECT_UDP);

                                    let mut stream = tokio::time::timeout(
                                        Duration::from_millis(1500),
                                        sender.send_request(req),
                                    )
                                    .await
                                    .map_err(|_| "h3 send_request timed out".to_string())?
                                    .map_err(|e| format!("h3 send_request failed: {e:?}"))?;

                                    let resp = tokio::time::timeout(
                                        Duration::from_millis(1500),
                                        stream.recv_response(),
                                    )
                                    .await
                                    .map_err(|_| "h3 recv_response timed out".to_string())?
                                    .map_err(|e| format!("h3 recv_response failed: {e:?}"))?;
                                    if resp.status() != http::StatusCode::OK {
                                        let _ = stream.finish().await;
                                        return Err(format!(
                                            "connect-udp unexpected status: {}",
                                            resp.status()
                                        ));
                                    }

                                    let stream_id: StreamId = stream.id();
                                    peer_state.insert(
                                        peer,
                                        UdpPeerState {
                                            stream_id,
                                            last_active: Instant::now(),
                                            ingress_limiter: udp_limiter(session_rate_limit),
                                            egress_limiter: udp_limiter(session_rate_limit),
                                            ingress_rate_drops: 0,
                                            egress_rate_drops: 0,
                                        },
                                    );
                                    stream_to_peer.insert(stream_id, peer);
                                    stream_keepalive.push((stream_id, Box::new(stream)));
                                    metrics.peers_created = metrics.peers_created.saturating_add(1);
                                    stream_id
                                }
                            };

                            let state = peer_state
                                .get_mut(&peer)
                                .ok_or_else(|| format!("missing udp peer state for {}", peer))?;
                            state.last_active = Instant::now();
                            metrics.ingress_datagrams = metrics.ingress_datagrams.saturating_add(1);
                            if !udp_datagram_allowed(&mut state.ingress_limiter, n, rate_limit_start) {
                                state.ingress_rate_drops = state.ingress_rate_drops.saturating_add(1);
                                metrics.ingress_rate_drops = metrics.ingress_rate_drops.saturating_add(1);
                                continue;
                            }

                            let dg = HttpDatagram::new(CONNECT_UDP_CONTEXT_ID, &buf[..n])
                                .encode()
                                .map_err(|_| "encode http datagram failed".to_string())?;
                            let mut dg_sender = h3_conn.get_datagram_sender(stream_id);
                            dg_sender
                                .send_datagram(Bytes::from(dg))
                                .map_err(|e| format!("h3 send datagram failed: {e}"))?;
                        }
                        dg = dg_reader.read_datagram() => {
                            let dg = dg.map_err(|e| format!("h3 recv datagram failed: {e:?}"))?;
                            let dg_stream_id: StreamId = dg.stream_id();
                            let payload = dg.into_payload();
                            let decoded = HttpDatagram::decode(payload.as_ref())
                                .map_err(|_| "invalid http datagram".to_string())?;
                            if decoded.context_id != CONNECT_UDP_CONTEXT_ID {
                                continue;
                            }
                            if let Some(peer) = stream_to_peer.get(&dg_stream_id).copied() {
                                if let Some(state) = peer_state.get_mut(&peer) {
                                    state.last_active = Instant::now();
                                    if !udp_datagram_allowed(&mut state.egress_limiter, decoded.payload.len(), rate_limit_start) {
                                        state.egress_rate_drops = state.egress_rate_drops.saturating_add(1);
                                        metrics.egress_rate_drops = metrics.egress_rate_drops.saturating_add(1);
                                        continue;
                                    }
                                }
                                let _ = udp.send_to(decoded.payload.as_slice(), peer).await;
                                metrics.egress_datagrams = metrics.egress_datagrams.saturating_add(1);
                            }
                        }
                        _ = cleanup.tick() => {
                            let now = Instant::now();
                            let mut expired = Vec::new();
                            for (peer, state) in &peer_state {
                                if now.duration_since(state.last_active) >= idle_timeout {
                                    expired.push((*peer, state.stream_id));
                                }
                            }

                            if !expired.is_empty() {
                                metrics.idle_evictions = metrics.idle_evictions.saturating_add(expired.len() as u64);
                                for (peer, stream_id) in expired {
                                    peer_state.remove(&peer);
                                    stream_to_peer.remove(&stream_id);
                                    stream_keepalive.retain(|(id, _)| *id != stream_id);
                                    eprintln!("udp peer idle cleanup: peer={} stream_id={:?}", peer, stream_id);
                                }
                                log_udp_metrics(&metrics, peer_state.len());
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            break;
                        }
                    }
                }
                log_udp_metrics(&metrics, peer_state.len());
                let _ = h3_conn.shutdown(0).await;
                let _ = h3_conn.wait_idle().await;
                endpoint.wait_idle().await;
                Ok::<(), String>(())
            });

            if let Err(err) = run {
                eprintln!("udp proxy failed: {}", err);
                try_audit_event_with_subject(
                    "udp",
                    &target_for_err,
                    false,
                    Some(err),
                    auth_subject,
                );
                std::process::exit(1);
            }
        }
        Some(Commands::Audit { command }) => match command {
            AuditCommands::Verify { path, signing_key } => {
                let path = path
                    .map(std::path::PathBuf::from)
                    .or_else(audit_log_path_from_env_or_config)
                    .unwrap_or_else(default_audit_log_path);
                let signing_key = signing_key
                    .map(|value| value.into_bytes())
                    .or_else(audit_signing_key_from_env_or_config);
                match verify_chain_with_signing_key(&path, signing_key.as_deref()) {
                    Ok(()) => {
                        println!("audit ok: {}", path.display());
                        try_audit_event(
                            "audit.verify",
                            &path.display().to_string(),
                            true,
                            Some("ok".to_string()),
                        );
                        std::process::exit(0);
                    }
                    Err(err) => {
                        eprintln!("audit invalid: {}: {}", path.display(), err);
                        try_audit_event(
                            "audit.verify",
                            &path.display().to_string(),
                            false,
                            Some(format!("invalid: {}", err)),
                        );
                        std::process::exit(1);
                    }
                }
            }
        },
        None => {
            println!("No subcommand provided. Try `toppy doctor`.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    #[test]
    fn proxy_once_relays_bidirectional_traffic() {
        let target_listener = TcpListener::bind("127.0.0.1:0").expect("bind target listener");
        let target_addr = target_listener.local_addr().expect("target addr");
        let target_thread = thread::spawn(move || {
            let (mut socket, _) = target_listener.accept().expect("accept target connection");
            let mut buf = [0u8; 64];
            let n = socket.read(&mut buf).expect("read relayed payload");
            socket
                .write_all(&buf[..n])
                .expect("write echoed payload");
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").expect("bind inbound listener");
        let inbound_addr = inbound_listener.local_addr().expect("inbound addr");
        let proxy_thread = thread::spawn(move || {
            let (inbound, _) = inbound_listener.accept().expect("accept inbound connection");
            proxy_once(inbound, target_addr, SessionRateLimit::disabled())
                .expect("proxy once should relay traffic");
        });

        let payload = b"hello over once";
        let mut client = TcpStream::connect(inbound_addr).expect("connect to proxy");
        client.write_all(payload).expect("write request");
        client.shutdown(Shutdown::Write).expect("shutdown client write");

        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).expect("read echoed reply");

        assert_eq!(echoed, payload);

        drop(client);

        proxy_thread.join().expect("proxy thread join");
        target_thread.join().expect("target thread join");
    }
}
