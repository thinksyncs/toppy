use crate::policy::{Policy, PolicyConfig};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub bytes_per_sec: Option<u64>,
    pub burst_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRateLimit {
    pub bytes_per_sec: u64,
    pub burst_bytes: u64,
}

impl SessionRateLimit {
    pub fn disabled() -> Self {
        Self {
            bytes_per_sec: 0,
            burst_bytes: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.bytes_per_sec > 0 && self.burst_bytes > 0
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub gateway: Option<String>,
    pub port: Option<u16>,
    pub ca_cert_path: Option<String>,
    pub server_name: Option<String>,
    pub auth_token: Option<String>,
    pub mtu: Option<u16>,
    pub audit_log_path: Option<String>,
    pub policy: Option<PolicyConfig>,
    pub rate: Option<RateLimitConfig>,
}

impl Config {
    const DEFAULT_SESSION_RATE_BYTES_PER_SEC: u64 = 10 * 1024 * 1024;

    pub fn session_rate_limit(&self) -> SessionRateLimit {
        if let Some(rate) = &self.rate {
            if rate.bytes_per_sec == Some(0) && rate.burst_bytes == Some(0) {
                return SessionRateLimit::disabled();
            }
        }

        let bytes_per_sec = self
            .rate
            .as_ref()
            .and_then(|r| r.bytes_per_sec)
            .unwrap_or(Self::DEFAULT_SESSION_RATE_BYTES_PER_SEC);
        let burst_bytes = self
            .rate
            .as_ref()
            .and_then(|r| r.burst_bytes)
            .unwrap_or(bytes_per_sec);

        SessionRateLimit {
            bytes_per_sec,
            burst_bytes,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(gateway) = &self.gateway {
            if gateway.trim().is_empty() {
                return Err("gateway must not be empty".to_string());
            }
        }
        if let Some(port) = self.port {
            if port == 0 {
                return Err("port must be non-zero".to_string());
            }
        }
        if let Some(ca_cert_path) = &self.ca_cert_path {
            if ca_cert_path.trim().is_empty() {
                return Err("ca_cert_path must not be empty".to_string());
            }
        }
        if let Some(server_name) = &self.server_name {
            if server_name.trim().is_empty() {
                return Err("server_name must not be empty".to_string());
            }
        }
        if let Some(auth_token) = &self.auth_token {
            if auth_token.trim().is_empty() {
                return Err("auth_token must not be empty".to_string());
            }
        }
        if let Some(mtu) = self.mtu {
            if mtu == 0 {
                return Err("mtu must be non-zero".to_string());
            }
        }
        if let Some(path) = &self.audit_log_path {
            if path.trim().is_empty() {
                return Err("audit_log_path must not be empty".to_string());
            }
        }
        if let Some(policy) = &self.policy {
            Policy::from_config(policy)?;
        }
        if let Some(rate) = &self.rate {
            let explicit_rate_zero = rate.bytes_per_sec == Some(0);
            let explicit_burst_zero = rate.burst_bytes == Some(0);
            if explicit_rate_zero ^ explicit_burst_zero {
                return Err(
                    "rate limiter disable requires both rate.bytes_per_sec=0 and rate.burst_bytes=0"
                        .to_string(),
                );
            }

            if explicit_rate_zero && explicit_burst_zero {
                return Ok(());
            }

            let bytes_per_sec = rate
                .bytes_per_sec
                .unwrap_or(Self::DEFAULT_SESSION_RATE_BYTES_PER_SEC);
            if bytes_per_sec == 0 {
                return Err("rate.bytes_per_sec must be non-zero".to_string());
            }

            let burst_bytes = rate.burst_bytes.unwrap_or(bytes_per_sec);
            if burst_bytes == 0 {
                return Err("rate.burst_bytes must be non-zero".to_string());
            }
        }
        Ok(())
    }
}

pub fn default_config_path() -> PathBuf {
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

pub fn load_config() -> Result<(Config, PathBuf), String> {
    let path = env::var("TOPPY_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_config_path());

    let data = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config {}: {}", path.display(), e))?;
    let cfg: Config = toml::from_str(&data).map_err(|e| format!("failed to parse TOML: {}", e))?;
    Ok((cfg, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        env::temp_dir().join(format!("toppy-{prefix}-{nanos}.toml"))
    }

    #[test]
    fn validate_rejects_empty_gateway() {
        let cfg = Config {
            gateway: Some("".to_string()),
            port: Some(4433),
            ca_cert_path: None,
            server_name: None,
            auth_token: None,
            mtu: None,
            audit_log_path: None,
            policy: None,
            rate: None,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_port() {
        let cfg = Config {
            gateway: Some("127.0.0.1".to_string()),
            port: Some(0),
            ca_cert_path: None,
            server_name: None,
            auth_token: None,
            mtu: None,
            audit_log_path: None,
            policy: None,
            rate: None,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_config_reads_toml() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = unique_temp_path("config-load");
        let data = "gateway = \"127.0.0.1\"\nport = 4433\n";
        fs::write(&path, data).expect("write config");

        let prev = env::var("TOPPY_CONFIG").ok();
        env::set_var("TOPPY_CONFIG", &path);

        let (cfg, loaded_path) = load_config().expect("load config");
        assert_eq!(loaded_path, path);
        assert_eq!(cfg.gateway.as_deref(), Some("127.0.0.1"));
        assert_eq!(cfg.port, Some(4433));

        if let Some(value) = prev {
            env::set_var("TOPPY_CONFIG", value);
        } else {
            env::remove_var("TOPPY_CONFIG");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn validate_rejects_empty_audit_log_path() {
        let cfg = Config {
            gateway: Some("127.0.0.1".to_string()),
            port: Some(4433),
            ca_cert_path: None,
            server_name: None,
            auth_token: None,
            mtu: None,
            audit_log_path: Some(" ".to_string()),
            policy: None,
            rate: None,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_config_reads_rate_limit() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = unique_temp_path("config-rate");
        let data = r#"
gateway = "127.0.0.1"
port = 4433

[rate]
bytes_per_sec = 1234
burst_bytes = 5678
"#;
        fs::write(&path, data).expect("write config");

        let prev = env::var("TOPPY_CONFIG").ok();
        env::set_var("TOPPY_CONFIG", &path);

        let (cfg, _) = load_config().expect("load config");
        assert_eq!(cfg.rate.as_ref().and_then(|r| r.bytes_per_sec), Some(1234));
        assert_eq!(cfg.rate.as_ref().and_then(|r| r.burst_bytes), Some(5678));
        assert_eq!(
            cfg.session_rate_limit(),
            SessionRateLimit {
                bytes_per_sec: 1234,
                burst_bytes: 5678
            }
        );

        if let Some(value) = prev {
            env::set_var("TOPPY_CONFIG", value);
        } else {
            env::remove_var("TOPPY_CONFIG");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn validate_rejects_partial_disable_rate_limit() {
        let cfg = Config {
            gateway: Some("127.0.0.1".to_string()),
            port: Some(4433),
            ca_cert_path: None,
            server_name: None,
            auth_token: None,
            mtu: None,
            audit_log_path: None,
            policy: None,
            rate: Some(RateLimitConfig {
                bytes_per_sec: Some(0),
                burst_bytes: Some(1),
            }),
        };
        assert!(cfg.validate().is_err());
    }
}
