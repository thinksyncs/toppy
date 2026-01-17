//! Implementation of the `doctor` diagnostics used by the CLI.
//!
//! The doctor checks are designed to provide a high-level status report on
//! the environment and configuration. Each check has an identifier, a
//! status (e.g. "pass", "warn", "fail"), and a summary explaining
//! the result. The overall status is aggregated across all checks.

use crate::config;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use std::env;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub version: String,
    pub overall: String,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub id: String,
    pub status: String,
    pub summary: String,
}

fn mk(id: &str, status: &str, summary: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        id: id.to_string(),
        status: status.to_string(),
        summary: summary.into(),
    }
}

fn aggregate_overall(checks: &[DoctorCheck]) -> String {
    // fail > warn > pass
    if checks.iter().any(|c| c.status == "fail") {
        "fail".to_string()
    } else if checks.iter().any(|c| c.status == "warn") {
        "warn".to_string()
    } else {
        "pass".to_string()
    }
}

fn dns_check(host: &str, port: u16) -> Result<usize, String> {
    let addr = format!("{}:{}", host, port);
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| format!("dns resolution failed for {}: {}", addr, e))?
        .collect();
    if addrs.is_empty() {
        Err(format!("dns resolution returned no addresses for {}", addr))
    } else {
        Ok(addrs.len())
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn quic_ping_check(host: &str, port: u16) -> Result<(), String> {
    let addr = format!("{}:{}", host, port);
    let addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {} failed: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("resolve {} returned no addresses", addr))?;

    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| format!("quic client config failed: {}", e))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio init failed: {}", e))?;

    let connect_timeout = Duration::from_millis(800);
    let stream_timeout = Duration::from_millis(800);

    rt.block_on(async move {
        let mut client_config = ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

        let bind_addr = "0.0.0.0:0"
            .parse::<std::net::SocketAddr>()
            .map_err(|e| e.to_string())?;
        let mut endpoint =
            Endpoint::client(bind_addr).map_err(|e| format!("quic client setup failed: {}", e))?;
        endpoint.set_default_client_config(client_config);

        let connecting = endpoint
            .connect(addr, host)
            .map_err(|e| format!("quic connect setup failed: {}", e))?;
        let connection = tokio::time::timeout(connect_timeout, connecting)
            .await
            .map_err(|_| "quic connect timed out".to_string())?
            .map_err(|e| format!("quic connect failed: {}", e))?;

        let (mut send, mut recv) = tokio::time::timeout(stream_timeout, connection.open_bi())
            .await
            .map_err(|_| "quic open stream timed out".to_string())?
            .map_err(|e| format!("quic open stream failed: {}", e))?;

        send.write_all(b"ping")
            .await
            .map_err(|e| format!("quic send failed: {}", e))?;
        send.finish()
            .map_err(|e| format!("quic finish failed: {}", e))?;

        let data = tokio::time::timeout(stream_timeout, recv.read_to_end(16))
            .await
            .map_err(|_| "quic read timed out".to_string())?
            .map_err(|e| format!("quic read failed: {}", e))?;

        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;

        if data == b"pong" {
            Ok(())
        } else {
            Err(format!("unexpected response: {:?}", data))
        }
    })
}

/// Runs a set of diagnostics and returns a report.
///
/// Dynamic implementation:
/// - Loads config from `TOPPY_CONFIG` or `~/.config/toppy/config.toml`
/// - Checks DNS resolution and minimal QUIC ping for `gateway:port`
pub fn doctor_check() -> DoctorReport {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // 1) config load check
    let cfg_res = config::load_config().and_then(|(cfg, path)| {
        cfg.validate()
            .map_err(|e| format!("config validation failed: {}", e))?;
        Ok((cfg, path))
    });
    match &cfg_res {
        Ok((_cfg, path)) => {
            checks.push(mk(
                "cfg.load",
                "pass",
                format!("loaded config: {}", path.display()),
            ));
        }
        Err(err) => {
            checks.push(mk("cfg.load", "fail", err));
        }
    }

    // 2) network reachability (basic)
    match cfg_res {
        Ok((cfg, _path)) => {
            let host = cfg.gateway.unwrap_or_else(|| "127.0.0.1".to_string());
            let port = cfg.port.unwrap_or(4433);
            let dns_ok = match dns_check(&host, port) {
                Ok(count) => {
                    checks.push(mk(
                        "net.dns",
                        "pass",
                        format!("resolved {}:{} to {} addr(s)", host, port, count),
                    ));
                    true
                }
                Err(e) => {
                    checks.push(mk("net.dns", "fail", e));
                    false
                }
            };

            match env::var("TOPPY_DOCTOR_NET").as_deref() {
                Ok("pass") => {
                    checks.push(mk("h3.connect", "pass", "forced pass via TOPPY_DOCTOR_NET"))
                }
                Ok("fail") => {
                    checks.push(mk("h3.connect", "fail", "forced fail via TOPPY_DOCTOR_NET"))
                }
                Ok("skip") => checks.push(mk("h3.connect", "warn", "skipped via TOPPY_DOCTOR_NET")),
                _ if !dns_ok => {
                    checks.push(mk("h3.connect", "warn", "skipped because net.dns failed"))
                }
                _ => match quic_ping_check(&host, port) {
                    Ok(()) => checks.push(mk(
                        "h3.connect",
                        "pass",
                        format!("quic ping ok {}:{}", host, port),
                    )),
                    Err(e) => checks.push(mk("h3.connect", "fail", e)),
                },
            }
        }
        Err(_) => {
            // config が無いならネットチェックは “warn (skip)” にする
            checks.push(mk(
                "net.dns",
                "warn",
                "skipped because config load failed (set TOPPY_CONFIG or create ~/.config/toppy/config.toml)",
            ));
            checks.push(mk(
                "h3.connect",
                "warn",
                "skipped because config load failed (set TOPPY_CONFIG or create ~/.config/toppy/config.toml)",
            ));
        }
    }

    let overall = aggregate_overall(&checks);
    DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        overall,
        checks,
    }
}
