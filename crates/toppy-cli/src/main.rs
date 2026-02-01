use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;
use toppy_core::audit::{
    append_event, default_audit_log_path, now_unix_ms, verify_chain, AuditEvent,
};
use toppy_core::config::{ClientAuthConfig, SessionRateLimit};
use toppy_core::oidc;
use toppy_core::policy::{Decision, Policy, Target};

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

fn current_actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn try_audit_event(action: &str, target: &str, allowed: bool, reason: Option<String>) {
    let path = audit_log_path_from_env_or_config().unwrap_or_else(default_audit_log_path);
    let event = AuditEvent {
        actor: current_actor(),
        action: action.to_string(),
        target: target.to_string(),
        allowed,
        reason,
    };
    if let Err(err) = append_event(path, now_unix_ms(), event) {
        eprintln!("audit log write failed: {}", err);
    }
}

fn parse_socket_addr(label: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid {} {}: {}", label, value, e))
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

fn proxy_once(inbound: TcpStream, target: SocketAddr) -> io::Result<()> {
    let _ = inbound.set_nodelay(true);
    let outbound = TcpStream::connect(target)?;
    let _ = outbound.set_nodelay(true);
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Doctor { json }) => {
            // Invoke the doctor checks from toppy_core and print JSON
            let report = toppy_core::doctor::doctor_check();
            // Best-effort audit log: record the overall outcome.
            try_audit_event(
                "doctor",
                "doctor",
                report.overall != "fail",
                Some(format!("overall={}", report.overall)),
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
            };
            match policy.evaluate(&target_policy) {
                Decision::Allow => {}
                Decision::Deny { reason } => {
                    eprintln!("Policy denied: {}", reason);
                    try_audit_event("up", &target, false, Some(reason));
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
            try_audit_event(
                "up",
                &target,
                true,
                Some(format!("listening={}", local_addr)),
            );

            for stream in listener.incoming() {
                match stream {
                    Ok(inbound) => {
                        if once {
                            if let Err(err) = proxy_once(inbound, target_addr) {
                                eprintln!("proxy connection failed: {}", err);
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
            };
            match policy.evaluate(&target_policy) {
                Decision::Allow => {}
                Decision::Deny { reason } => {
                    eprintln!("Policy denied: {}", reason);
                    try_audit_event("udp", &target, false, Some(reason));
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

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("failed to start tokio runtime: {}", e);
                    std::process::exit(1);
                });

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
                println!("toppy udp listening on {} -> {}", local_addr, target_addr);
                try_audit_event(
                    "udp",
                    &target_for_audit,
                    true,
                    Some(format!("listening={}", local_addr)),
                );

                // Multi-client mapping: we keep one CONNECT-UDP request stream per local UDP peer.
                // This allows correct reply routing without relying on a single "last sender".
                let mut peer_to_stream: HashMap<SocketAddr, StreamId> = HashMap::new();
                let mut stream_to_peer: HashMap<StreamId, SocketAddr> = HashMap::new();
                let mut stream_keepalive: Vec<Box<dyn std::any::Any + Send>> = Vec::new();

                let mut dg_reader = h3_conn.get_datagram_reader();
                let mut buf = vec![0u8; 2048];

                loop {
                    tokio::select! {
                        recv = udp.recv_from(&mut buf) => {
                            let (n, peer) = recv.map_err(|e| format!("udp recv failed: {}", e))?;
                            let stream_id = match peer_to_stream.get(&peer).copied() {
                                Some(id) => id,
                                None => {
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
                                    peer_to_stream.insert(peer, stream_id);
                                    stream_to_peer.insert(stream_id, peer);
                                    stream_keepalive.push(Box::new(stream));
                                    stream_id
                                }
                            };
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
                                let _ = udp.send_to(decoded.payload.as_slice(), peer).await;
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            break;
                        }
                    }
                }
                let _ = h3_conn.shutdown(0).await;
                let _ = h3_conn.wait_idle().await;
                endpoint.wait_idle().await;
                Ok::<(), String>(())
            });

            if let Err(err) = run {
                eprintln!("udp proxy failed: {}", err);
                try_audit_event("udp", &target_for_err, false, Some(err));
                std::process::exit(1);
            }
        }
        Some(Commands::Audit { command }) => match command {
            AuditCommands::Verify { path } => {
                let path = path
                    .map(std::path::PathBuf::from)
                    .or_else(audit_log_path_from_env_or_config)
                    .unwrap_or_else(default_audit_log_path);
                match verify_chain(&path) {
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
