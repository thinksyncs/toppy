//! Implementation of the `doctor` diagnostics used by the CLI.
//!
//! The doctor checks are designed to provide a high-level status report on
//! the environment and configuration. Each check has an identifier, a
//! status (e.g. "pass", "warn", "fail"), and a summary explaining
//! the result. The overall status is aggregated across all checks.

use crate::config;
use serde::Serialize;
use std::env;
use std::net::{TcpStream, ToSocketAddrs};
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

fn tcp_connect_check(host: &str, port: u16) -> Result<(), String> {
    let addr = format!("{}:{}", host, port);
    TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("invalid address {}: {}", addr, e))?,
        Duration::from_millis(800),
    )
    .map(|_| ())
    .map_err(|e| format!("connect to {} failed: {}", addr, e))
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

/// Runs a set of diagnostics and returns a report.
///
/// Dynamic implementation:
/// - Loads config from `TOPPY_CONFIG` or `~/.config/toppy/config.toml`
/// - Checks basic reachability to configured `gateway:port` by TCP connect
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
                _ => match tcp_connect_check(&host, port) {
                    Ok(()) => checks.push(mk(
                        "h3.connect",
                        "pass",
                        format!("reachable (tcp preflight) {}:{}", host, port),
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
