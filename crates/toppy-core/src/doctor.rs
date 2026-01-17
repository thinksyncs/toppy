//! Implementation of the `doctor` diagnostics used by the CLI.
//!
//! The doctor checks are designed to provide a high-level status report on
//! the environment and configuration. Each check has an identifier, a
//! status (e.g. "pass", "warn", "fail"), and a summary explaining
//! the result. The overall status is aggregated across all checks.

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;
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

/// Configuration structure loaded from TOML.
///
/// Example:
/// ```toml
/// gateway = "127.0.0.1"
/// port = 4433
/// ```
#[derive(Deserialize, Debug)]
struct Config {
    gateway: Option<String>,
    port: Option<u16>,
}

fn default_config_path() -> PathBuf {
    // Minimal: ~/.config/toppy/config.toml
    // (XDG support can be added later)
    if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("toppy")
            .join("config.toml")
    } else {
        PathBuf::from(".config/toppy/config.toml")
    }
}

fn load_config() -> Result<(Config, PathBuf), String> {
    let path = env::var("TOPPY_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_config_path());

    let data = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config {}: {}", path.display(), e))?;
    let cfg: Config = toml::from_str(&data).map_err(|e| format!("failed to parse TOML: {}", e))?;
    Ok((cfg, path))
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

/// Runs a set of diagnostics and returns a report.
///
/// Dynamic implementation:
/// - Loads config from `TOPPY_CONFIG` or `~/.config/toppy/config.toml`
/// - Checks basic reachability to configured `gateway:port` by TCP connect
pub fn doctor_check() -> DoctorReport {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // 1) config load check
    let cfg_res = load_config();
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
            match env::var("TOPPY_DOCTOR_NET").as_deref() {
                Ok("pass") => checks.push(mk("net.h3", "pass", "forced pass via TOPPY_DOCTOR_NET")),
                Ok("fail") => checks.push(mk("net.h3", "fail", "forced fail via TOPPY_DOCTOR_NET")),
                Ok("skip") => checks.push(mk("net.h3", "warn", "skipped via TOPPY_DOCTOR_NET")),
                _ => match tcp_connect_check(&host, port) {
                    Ok(()) => checks.push(mk(
                        "net.h3",
                        "pass",
                        format!("reachable (tcp) {}:{}", host, port),
                    )),
                    Err(e) => checks.push(mk("net.h3", "fail", e)),
                },
            }
        }
        Err(_) => {
            // config が無いならネットチェックは “warn (skip)” にする
            checks.push(mk(
                "net.h3",
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
