use crate::oidc::{self, OidcDeviceCodeConfig};
use crate::policy::{Policy, PolicyConfig};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ClientAuthConfig {
    /// Use a static token/JWT configured locally.
    ///
    /// If `token` is omitted, falls back to the legacy top-level `auth_token`.
    Token { token: Option<String> },

    /// OIDC device-code flow (supports MFA/FIDO2 at the IdP).
    OidcDeviceCode {
        issuer: String,
        client_id: String,
        audience: Option<String>,
        scope: Option<String>,
        token_cache_path: Option<String>,
    },

    /// OIDC authorization-code flow with PKCE (browser-based).
    OidcAuthCodePkce {
        issuer: String,
        client_id: String,
        audience: Option<String>,
        scope: Option<String>,
        redirect_uri: String,
        token_cache_path: Option<String>,
    },

    /// SAML login flow via broker/federation.
    Saml {
        idp_entity_id: String,
        sp_entity_id: Option<String>,
        broker_issuer: String,
        broker_client_id: String,
        broker_audience: Option<String>,
        broker_scope: Option<String>,
        token_cache_path: Option<String>,
    },
}

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
    pub auth: Option<ClientAuthConfig>,
    pub mtu: Option<u16>,
    pub audit_log_path: Option<String>,
    pub audit_signing_key: Option<String>,
    pub audit_ship_url: Option<String>,
    pub audit_ship_token: Option<String>,
    pub audit_ship_timeout_secs: Option<u64>,
    pub policy: Option<PolicyConfig>,
    pub rate: Option<RateLimitConfig>,
}

impl Config {
    const DEFAULT_SESSION_RATE_BYTES_PER_SEC: u64 = 10 * 1024 * 1024;

    pub fn resolve_auth_token(&self) -> Result<Option<String>, String> {
        match &self.auth {
            None => Ok(self.auth_token.clone()),
            Some(ClientAuthConfig::Token { token }) => {
                if let Some(value) = token {
                    return Ok(Some(value.clone()));
                }
                Ok(self.auth_token.clone())
            }
            Some(ClientAuthConfig::OidcDeviceCode { .. }) => {
                let cfg = self
                    .oidc_device_code_config()?
                    .ok_or_else(|| "missing oidc config".to_string())?;
                let token = oidc::resolve_cached_access_token(&cfg)?;
                Ok(Some(token))
            }
            Some(ClientAuthConfig::OidcAuthCodePkce { .. }) => {
                let cfg = self
                    .oidc_auth_code_config()?
                    .ok_or_else(|| "missing oidc auth-code config".to_string())?;
                let token = oidc::resolve_cached_access_token_auth_code(&cfg)?;
                Ok(Some(token))
            }
            Some(ClientAuthConfig::Saml { .. }) => {
                let cfg = self
                    .oidc_device_code_config()?
                    .ok_or_else(|| "missing saml broker config".to_string())?;
                let token = oidc::resolve_cached_access_token(&cfg)?;
                Ok(Some(token))
            }
        }
    }

    pub fn oidc_device_code_config(&self) -> Result<Option<OidcDeviceCodeConfig>, String> {
        match &self.auth {
            Some(ClientAuthConfig::OidcDeviceCode {
                issuer,
                client_id,
                audience,
                scope,
                token_cache_path,
            }) => Ok(Some(OidcDeviceCodeConfig {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
                audience: audience.clone(),
                scope: scope.clone(),
                token_cache_path: token_cache_path.clone(),
            })),
            Some(ClientAuthConfig::Saml {
                broker_issuer,
                broker_client_id,
                broker_audience,
                broker_scope,
                token_cache_path,
                ..
            }) => Ok(Some(OidcDeviceCodeConfig {
                issuer: broker_issuer.clone(),
                client_id: broker_client_id.clone(),
                audience: broker_audience.clone(),
                scope: broker_scope.clone(),
                token_cache_path: token_cache_path.clone(),
            })),
            _ => Ok(None),
        }
    }

    pub fn oidc_auth_code_config(&self) -> Result<Option<oidc::OidcAuthCodeConfig>, String> {
        match &self.auth {
            Some(ClientAuthConfig::OidcAuthCodePkce {
                issuer,
                client_id,
                audience,
                scope,
                redirect_uri,
                token_cache_path,
            }) => Ok(Some(oidc::OidcAuthCodeConfig {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
                audience: audience.clone(),
                scope: scope.clone(),
                redirect_uri: redirect_uri.clone(),
                token_cache_path: token_cache_path.clone(),
            })),
            _ => Ok(None),
        }
    }

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
        if let Some(auth) = &self.auth {
            match auth {
                ClientAuthConfig::Token { token } => {
                    if let Some(value) = token {
                        if value.trim().is_empty() {
                            return Err("auth.token must not be empty".to_string());
                        }
                    }
                }
                ClientAuthConfig::OidcDeviceCode {
                    issuer,
                    client_id,
                    token_cache_path,
                    ..
                } => {
                    if issuer.trim().is_empty() {
                        return Err("auth.issuer must not be empty".to_string());
                    }
                    if client_id.trim().is_empty() {
                        return Err("auth.client_id must not be empty".to_string());
                    }
                    if let Some(path) = token_cache_path {
                        if path.trim().is_empty() {
                            return Err("auth.token_cache_path must not be empty".to_string());
                        }
                    }
                }
                ClientAuthConfig::OidcAuthCodePkce {
                    issuer,
                    client_id,
                    redirect_uri,
                    token_cache_path,
                    ..
                } => {
                    if issuer.trim().is_empty() {
                        return Err("auth.issuer must not be empty".to_string());
                    }
                    if client_id.trim().is_empty() {
                        return Err("auth.client_id must not be empty".to_string());
                    }
                    if redirect_uri.trim().is_empty() {
                        return Err("auth.redirect_uri must not be empty".to_string());
                    }
                    if let Some(path) = token_cache_path {
                        if path.trim().is_empty() {
                            return Err("auth.token_cache_path must not be empty".to_string());
                        }
                    }
                }
                ClientAuthConfig::Saml {
                    idp_entity_id,
                    broker_issuer,
                    broker_client_id,
                    token_cache_path,
                    ..
                } => {
                    if idp_entity_id.trim().is_empty() {
                        return Err("auth.idp_entity_id must not be empty".to_string());
                    }
                    if broker_issuer.trim().is_empty() {
                        return Err("auth.broker_issuer must not be empty".to_string());
                    }
                    if broker_client_id.trim().is_empty() {
                        return Err("auth.broker_client_id must not be empty".to_string());
                    }
                    if let Some(path) = token_cache_path {
                        if path.trim().is_empty() {
                            return Err("auth.token_cache_path must not be empty".to_string());
                        }
                    }
                }
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
        if let Some(key) = &self.audit_signing_key {
            if key.trim().is_empty() {
                return Err("audit_signing_key must not be empty".to_string());
            }
        }
        if let Some(url) = &self.audit_ship_url {
            if url.trim().is_empty() {
                return Err("audit_ship_url must not be empty".to_string());
            }
        }
        if let Some(token) = &self.audit_ship_token {
            if token.trim().is_empty() {
                return Err("audit_ship_token must not be empty".to_string());
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
            auth: None,
            mtu: None,
            audit_log_path: None,
            audit_signing_key: None,
            audit_ship_url: None,
            audit_ship_token: None,
            audit_ship_timeout_secs: None,
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
            auth: None,
            mtu: None,
            audit_log_path: None,
            audit_signing_key: None,
            audit_ship_url: None,
            audit_ship_token: None,
            audit_ship_timeout_secs: None,
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
            auth: None,
            mtu: None,
            audit_log_path: Some(" ".to_string()),
            audit_signing_key: None,
            audit_ship_url: None,
            audit_ship_token: None,
            audit_ship_timeout_secs: None,
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
            auth: None,
            mtu: None,
            audit_log_path: None,
            audit_signing_key: None,
            audit_ship_url: None,
            audit_ship_token: None,
            audit_ship_timeout_secs: None,
            policy: None,
            rate: Some(RateLimitConfig {
                bytes_per_sec: Some(0),
                burst_bytes: Some(1),
            }),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn load_config_reads_auth_token_mode() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = unique_temp_path("config-auth-token");
        let data = r#"
gateway = "127.0.0.1"
port = 4433

[auth]
mode = "token"
token = "abc"
"#;
        fs::write(&path, data).expect("write config");

        let prev = env::var("TOPPY_CONFIG").ok();
        env::set_var("TOPPY_CONFIG", &path);

        let (cfg, _) = load_config().expect("load config");
        assert_eq!(
            cfg.auth,
            Some(ClientAuthConfig::Token {
                token: Some("abc".to_string())
            })
        );
        assert_eq!(
            cfg.resolve_auth_token().expect("resolve"),
            Some("abc".to_string())
        );

        if let Some(value) = prev {
            env::set_var("TOPPY_CONFIG", value);
        } else {
            env::remove_var("TOPPY_CONFIG");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_config_reads_oidc_device_code_mode() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = unique_temp_path("config-auth-oidc");
        let data = r#"
gateway = "127.0.0.1"
port = 4433

[auth]
mode = "oidc_device_code"
issuer = "https://issuer.example"
client_id = "client-123"
audience = "toppy"
scope = "openid"
token_cache_path = "/tmp/toppy-oidc-cache.json"
"#;
        fs::write(&path, data).expect("write config");

        let prev = env::var("TOPPY_CONFIG").ok();
        env::set_var("TOPPY_CONFIG", &path);

        let (cfg, _) = load_config().expect("load config");
        assert_eq!(
            cfg.auth,
            Some(ClientAuthConfig::OidcDeviceCode {
                issuer: "https://issuer.example".to_string(),
                client_id: "client-123".to_string(),
                audience: Some("toppy".to_string()),
                scope: Some("openid".to_string()),
                token_cache_path: Some("/tmp/toppy-oidc-cache.json".to_string()),
            })
        );

        if let Some(value) = prev {
            env::set_var("TOPPY_CONFIG", value);
        } else {
            env::remove_var("TOPPY_CONFIG");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_config_reads_oidc_auth_code_mode() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = unique_temp_path("config-auth-oidc-auth-code");
        let data = r#"
gateway = "127.0.0.1"
port = 4433

[auth]
mode = "oidc_auth_code_pkce"
issuer = "https://issuer.example"
client_id = "client-123"
audience = "toppy"
scope = "openid"
redirect_uri = "http://127.0.0.1:8080/callback"
token_cache_path = "/tmp/toppy-oidc-auth-code-cache.json"
"#;
        fs::write(&path, data).expect("write config");

        let prev = env::var("TOPPY_CONFIG").ok();
        env::set_var("TOPPY_CONFIG", &path);

        let (cfg, _) = load_config().expect("load config");
        assert_eq!(
            cfg.auth,
            Some(ClientAuthConfig::OidcAuthCodePkce {
                issuer: "https://issuer.example".to_string(),
                client_id: "client-123".to_string(),
                audience: Some("toppy".to_string()),
                scope: Some("openid".to_string()),
                redirect_uri: "http://127.0.0.1:8080/callback".to_string(),
                token_cache_path: Some("/tmp/toppy-oidc-auth-code-cache.json".to_string()),
            })
        );

        if let Some(value) = prev {
            env::set_var("TOPPY_CONFIG", value);
        } else {
            env::remove_var("TOPPY_CONFIG");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_config_reads_saml_broker_mode() {
        let _guard = crate::test_support::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = unique_temp_path("config-auth-saml");
        let data = r#"
gateway = "127.0.0.1"
port = 4433

[auth]
mode = "saml"
idp_entity_id = "https://idp.example/saml"
sp_entity_id = "toppy-sp"
broker_issuer = "https://broker.example"
broker_client_id = "broker-client"
broker_audience = "toppy"
broker_scope = "openid"
token_cache_path = "/tmp/toppy-saml-cache.json"
"#;
        fs::write(&path, data).expect("write config");

        let prev = env::var("TOPPY_CONFIG").ok();
        env::set_var("TOPPY_CONFIG", &path);

        let (cfg, _) = load_config().expect("load config");
        assert_eq!(
            cfg.auth,
            Some(ClientAuthConfig::Saml {
                idp_entity_id: "https://idp.example/saml".to_string(),
                sp_entity_id: Some("toppy-sp".to_string()),
                broker_issuer: "https://broker.example".to_string(),
                broker_client_id: "broker-client".to_string(),
                broker_audience: Some("toppy".to_string()),
                broker_scope: Some("openid".to_string()),
                token_cache_path: Some("/tmp/toppy-saml-cache.json".to_string()),
            })
        );

        if let Some(value) = prev {
            env::set_var("TOPPY_CONFIG", value);
        } else {
            env::remove_var("TOPPY_CONFIG");
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn resolve_auth_token_falls_back_to_legacy_field() {
        let cfg = Config {
            gateway: Some("127.0.0.1".to_string()),
            port: Some(4433),
            ca_cert_path: None,
            server_name: None,
            auth_token: Some("legacy".to_string()),
            auth: Some(ClientAuthConfig::Token { token: None }),
            mtu: None,
            audit_log_path: None,
            audit_signing_key: None,
            audit_ship_url: None,
            audit_ship_token: None,
            audit_ship_timeout_secs: None,
            policy: None,
            rate: None,
        };
        assert_eq!(
            cfg.resolve_auth_token().expect("resolve"),
            Some("legacy".to_string())
        );
    }

    #[test]
    fn resolve_auth_token_errors_for_unimplemented_modes() {
        let cfg = Config {
            gateway: Some("127.0.0.1".to_string()),
            port: Some(4433),
            ca_cert_path: None,
            server_name: None,
            auth_token: None,
            auth: Some(ClientAuthConfig::OidcDeviceCode {
                issuer: "https://issuer.example".to_string(),
                client_id: "client".to_string(),
                audience: None,
                scope: None,
                token_cache_path: Some(
                    env::temp_dir()
                        .join("toppy-oidc-missing.json")
                        .to_string_lossy()
                        .to_string(),
                ),
            }),
            mtu: None,
            audit_log_path: None,
            audit_signing_key: None,
            audit_ship_url: None,
            audit_ship_token: None,
            audit_ship_timeout_secs: None,
            policy: None,
            rate: None,
        };
        let err = cfg.resolve_auth_token().unwrap_err();
        assert!(err.contains("no cached token"));
    }
}
