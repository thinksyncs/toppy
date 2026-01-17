//! Implementation of the `doctor` diagnostics used by the CLI.
//!
//! The doctor checks are designed to provide a high-level status report on
//! the environment and configuration. Each check has an identifier, a
//! status (e.g. "pass", "warn", "fail"), and a summary explaining
//! the result. The overall status is aggregated across all checks.

use serde::{Deserialize, Serialize};

/// Top-level structure for a doctor report.
#[derive(Serialize)]
pub struct DoctorReport {
    pub overall: String,
    pub checks: Vec<DoctorCheck>,
}

/// Represents an individual check in the doctor report.
#[derive(Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: String,
    pub summary: String,
}

/// Configuration structure loaded from a TOML file.
#[derive(Deserialize, Debug)]
struct Config {
    /// MASQUE gateway host to check connectivity against.
    gateway: Option<String>,
    /// Port for the MASQUE gateway (defaults to 4433 if unspecified).
    port: Option<u16>,
}

/// Attempt to load the configuration from a file. The path is determined by the
/// `TOPPY_CONFIG` environment variable, or `~/.config/toppy/config.toml` if not set.
fn load_config() -> Option<Config> {
    use std::fs;
    use std::io::Read;

    // Determine the config file path.
    let path = std::env::var("TOPPY_CONFIG").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{}/.config/toppy/config.toml", home)
    });

    let mut contents = String::new();
    match fs::File::open(&path) {
        Ok(mut file) => {
            if file.read_to_string(&mut contents).is_ok() {
                // Attempt to parse the TOML.
                match toml::from_str::<Config>(&contents) {
                    Ok(cfg) => Some(cfg),
                    Err(_) => None,
                }
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Run a series of diagnostic checks and return a report.
pub fn doctor_check() -> DoctorReport {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // Load configuration from file.
    if let Some(cfg) = load_config() {
        checks.push(DoctorCheck {
            id: "cfg.load".to_string(),
            status: "pass".to_string(),
            summary: "Configuration loaded successfully.".to_string(),
        });

        // Determine the gateway host and port from the configuration.
        let host = cfg.gateway.unwrap_or_else(|| "127.0.0.1".to_string());
        let port = cfg.port.unwrap_or(4433);

        // Attempt to open a TCP connection to the gateway. If this fails,
        // record the failure in the report. Note: this is a synchronous
        // operation and may block briefly.
        match std::net::TcpStream::connect((host.as_str(), port)) {
            Ok(_) => {
                checks.push(DoctorCheck {
                    id: "net.h3".to_string(),
                    status: "pass".to_string(),
                    summary: format!("Successfully connected to {}:{}", host, port),
                });
            }
            Err(err) => {
                checks.push(DoctorCheck {
                    id: "net.h3".to_string(),
                    status: "fail".to_string(),
                    summary: format!("Failed to connect to {}:{} ({})", host, port, err),
                });
            }
        }
    } else {
        // Config file missing or unreadable.
        checks.push(DoctorCheck {
            id: "cfg.load".to_string(),
            status: "fail".to_string(),
            summary: "Configuration file missing or unreadable.".to_string(),
        });
        // Without config, we cannot determine the gateway address.
        checks.push(DoctorCheck {
            id: "net.h3".to_string(),
            status: "warn".to_string(),
            summary: "Gateway connectivity not tested due to missing config.".to_string(),
        });
    }

    // Determine overall status.
    let overall = if checks.iter().any(|c| c.status == "fail") {
        "fail"
    } else if checks.iter().any(|c| c.status == "warn") {
        "warn"
    } else {
        "pass"
    };

    DoctorReport {
        overall: overall.to_string(),
        checks,
    }
}