//! Implementation of the `doctor` diagnostics used by the CLI.
//!
//! The doctor checks are designed to provide a high-level status report on
//! the environment and configuration. Each check has an identifier, a
//! status (e.g. "pass", "warn", "fail"), and a summary explaining
//! the result. The overall status is aggregated across all checks.

use crate::config;
use crate::policy::{Decision, Policy, Target};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde::Serialize;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::Path;
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

fn tun_perm_check() -> DoctorCheck {
    #[cfg(target_os = "linux")]
    {
        let path = "/dev/net/tun";
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(_) => mk("tun.perm", "pass", format!("opened {}", path)),
            Err(e) => mk("tun.perm", "fail", format!("cannot open {}: {}", path, e)),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match macos_utun_check() {
            Ok(()) => mk("tun.perm", "pass", "utun device opened"),
            Err(e) => mk("tun.perm", "fail", e),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        mk(
            "tun.perm",
            "warn",
            "tun permission check not supported on this OS",
        )
    }
}

#[cfg(target_os = "macos")]
fn macos_utun_check() -> Result<(), String> {
    use std::io;
    use std::mem;

    unsafe {
        let fd = libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(format!(
                "utun socket failed: {}",
                io::Error::last_os_error()
            ));
        }

        let mut info: libc::ctl_info = mem::zeroed();
        let name = b"com.apple.net.utun_control\0";
        for (dst, src) in info.ctl_name.iter_mut().zip(name.iter()) {
            *dst = *src as libc::c_char;
        }
        if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("utun ioctl CTLIOCGINFO failed: {}", err));
        }

        let mut addr: libc::sockaddr_ctl = mem::zeroed();
        addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0;

        if libc::connect(
            fd,
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ctl>() as u32,
        ) < 0
        {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("utun connect failed: {}", err));
        }

        libc::close(fd);
        Ok(())
    }
}

fn mtu_sanity_check(mtu: Option<u16>) -> DoctorCheck {
    let recommended = 1350u16;
    let min_reasonable = 1200u16;
    let max_reasonable = 9000u16;
    match mtu {
        Some(value) if value < min_reasonable => mk(
            "mtu.sanity",
            "warn",
            format!(
                "mtu {} is small; recommended >= {} (target {})",
                value, min_reasonable, recommended
            ),
        ),
        Some(value) if value > max_reasonable => mk(
            "mtu.sanity",
            "warn",
            format!(
                "mtu {} is large; recommended <= {} (target {})",
                value, max_reasonable, recommended
            ),
        ),
        Some(value) => mk(
            "mtu.sanity",
            "pass",
            format!("mtu {} within range (target {})", value, recommended),
        ),
        None => mk(
            "mtu.sanity",
            "warn",
            format!("mtu not set; recommended {}", recommended),
        ),
    }
}

fn parse_policy_target(value: &str) -> Result<Target, String> {
    let addr: SocketAddr = value
        .parse()
        .map_err(|e| format!("invalid target {}: {}", value, e))?;
    Ok(Target {
        ip: addr.ip(),
        port: addr.port(),
    })
}

fn load_ca_certs(path: &Path) -> Result<RootCertStore, String> {
    let data = fs::read(path)
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

fn quic_ping_check(
    host: &str,
    port: u16,
    server_name: &str,
    ca_cert_path: Option<&str>,
    auth_token: Option<&str>,
) -> Result<(), String> {
    let addr = format!("{}:{}", host, port);
    let addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {} failed: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("resolve {} returned no addresses", addr))?;

    let ca_cert_path =
        ca_cert_path.ok_or_else(|| "missing ca_cert_path for TLS verification".to_string())?;
    let auth_token =
        auth_token.ok_or_else(|| "missing auth_token for token verification".to_string())?;
    let ca_store = load_ca_certs(Path::new(ca_cert_path))?;
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(ca_store)
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
            .connect(addr, server_name)
            .map_err(|e| format!("quic connect setup failed: {}", e))?;
        let connection = tokio::time::timeout(connect_timeout, connecting)
            .await
            .map_err(|_| "quic connect timed out".to_string())?
            .map_err(|e| format!("quic connect failed: {}", e))?;

        let (mut send, mut recv) = tokio::time::timeout(stream_timeout, connection.open_bi())
            .await
            .map_err(|_| "quic open stream timed out".to_string())?
            .map_err(|e| format!("quic open stream failed: {}", e))?;

        let payload = format!("ping {}", auth_token);
        send.write_all(payload.as_bytes())
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
        } else if data == b"unauthorized" {
            Err("token rejected by gateway".to_string())
        } else {
            Err(format!("unexpected response: {:?}", data))
        }
    })
}

/// Runs a set of diagnostics and returns a report.
///
/// Dynamic implementation:
/// - Loads config from `TOPPY_CONFIG` or `~/.config/toppy/config.toml`
/// - Checks DNS resolution and minimal QUIC ping for `gateway:port` with TLS and token validation
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

    let mtu_value = cfg_res.as_ref().ok().and_then(|(cfg, _)| cfg.mtu);

    // 2) network reachability (basic)
    match cfg_res.as_ref() {
        Ok((cfg, _path)) => {
            let host = cfg
                .gateway
                .clone()
                .unwrap_or_else(|| "127.0.0.1".to_string());
            let port = cfg.port.unwrap_or(4433);
            let server_name = cfg.server_name.clone().unwrap_or_else(|| host.clone());
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
                _ => match quic_ping_check(
                    &host,
                    port,
                    &server_name,
                    cfg.ca_cert_path.as_deref(),
                    cfg.auth_token.as_deref(),
                ) {
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

    match env::var("TOPPY_DOCTOR_TUN").as_deref() {
        Ok("pass") => checks.push(mk("tun.perm", "pass", "forced pass via TOPPY_DOCTOR_TUN")),
        Ok("fail") => checks.push(mk("tun.perm", "fail", "forced fail via TOPPY_DOCTOR_TUN")),
        Ok("skip") => checks.push(mk("tun.perm", "warn", "skipped via TOPPY_DOCTOR_TUN")),
        _ => checks.push(tun_perm_check()),
    }
    checks.push(mtu_sanity_check(mtu_value));

    if let Ok(target_spec) = env::var("TOPPY_DOCTOR_TARGET") {
        match &cfg_res {
            Ok((cfg, _)) => match parse_policy_target(&target_spec) {
                Ok(target) => match cfg.policy.as_ref() {
                    Some(policy_cfg) => match Policy::from_config(policy_cfg) {
                        Ok(policy) => match policy.evaluate(&target) {
                            Decision::Allow => checks.push(mk(
                                "policy.denied",
                                "pass",
                                format!("target {}:{} allowed", target.ip, target.port),
                            )),
                            Decision::Deny { reason } => {
                                checks.push(mk("policy.denied", "fail", reason))
                            }
                        },
                        Err(err) => checks.push(mk("policy.denied", "fail", err)),
                    },
                    None => checks.push(mk("policy.denied", "warn", "policy not configured")),
                },
                Err(err) => {
                    checks.push(mk("policy.denied", "fail", err));
                }
            },
            Err(_) => checks.push(mk(
                "policy.denied",
                "warn",
                "skipped because config load failed",
            )),
        }
    }

    let overall = aggregate_overall(&checks);
    DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        overall,
        checks,
    }
}
