use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub gateway: Option<String>,
    pub port: Option<u16>,
}

impl Config {
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
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_port() {
        let cfg = Config {
            gateway: Some("127.0.0.1".to_string()),
            port: Some(0),
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
}
