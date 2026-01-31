use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_VERSION: u8 = 1;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const EXPIRY_SKEW_SECS: u64 = 60;
const DEFAULT_SCOPE: &str = "openid offline_access";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcDeviceCodeConfig {
    pub issuer: String,
    pub client_id: String,
    pub audience: Option<String>,
    pub scope: Option<String>,
    pub token_cache_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcProvider {
    pub issuer: String,
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcToken {
    pub cache_version: u8,
    pub issuer: String,
    pub client_id: String,
    pub audience: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct OidcDiscovery {
    device_authorization_endpoint: Option<String>,
    token_endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OidcErrorResponse {
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

#[derive(Debug)]
enum TokenPollError {
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    Other(String),
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl OidcToken {
    fn from_response(cfg: &OidcDeviceCodeConfig, resp: TokenResponse, issued_at: u64) -> Self {
        let expires_at = resp.expires_in.map(|ttl| issued_at.saturating_add(ttl));
        OidcToken {
            cache_version: CACHE_VERSION,
            issuer: cfg.issuer.clone(),
            client_id: cfg.client_id.clone(),
            audience: cfg.audience.clone(),
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            token_type: resp.token_type,
            scope: resp.scope,
            issued_at,
            expires_at,
        }
    }

    fn is_expired(&self, now: u64) -> bool {
        match self.expires_at {
            Some(exp) => exp <= now.saturating_add(EXPIRY_SKEW_SECS),
            None => false,
        }
    }
}

pub fn default_token_cache_path() -> PathBuf {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    PathBuf::from(home)
        .join(".config")
        .join("toppy")
        .join("oidc-token.json")
}

pub fn token_cache_path(cfg: &OidcDeviceCodeConfig) -> PathBuf {
    cfg.token_cache_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(default_token_cache_path)
}

pub fn discover_provider(issuer: &str) -> Result<OidcProvider, String> {
    let normalized = issuer.trim_end_matches('/');
    let url = format!("{}/.well-known/openid-configuration", normalized);
    let discovery: OidcDiscovery = http_get_json(&url)?;
    let device_endpoint = discovery
        .device_authorization_endpoint
        .ok_or_else(|| "missing device_authorization_endpoint in discovery document".to_string())?;
    Ok(OidcProvider {
        issuer: normalized.to_string(),
        device_authorization_endpoint: device_endpoint,
        token_endpoint: discovery.token_endpoint,
    })
}

pub fn request_device_code(
    provider: &OidcProvider,
    cfg: &OidcDeviceCodeConfig,
) -> Result<DeviceCodeResponse, String> {
    let scope = cfg
        .scope
        .clone()
        .unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    let mut params = vec![
        ("client_id".to_string(), cfg.client_id.clone()),
        ("scope".to_string(), scope),
    ];
    if let Some(audience) = cfg.audience.as_ref() {
        params.push(("audience".to_string(), audience.clone()));
    }

    let body = http_post_form(&provider.device_authorization_endpoint, &params)?;
    serde_json::from_str(&body).map_err(|e| format!("failed to parse device code response: {}", e))
}

pub fn poll_device_code(
    provider: &OidcProvider,
    cfg: &OidcDeviceCodeConfig,
    device: &DeviceCodeResponse,
) -> Result<OidcToken, String> {
    let mut interval = device.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS).max(1);
    let deadline = now_unix_secs().saturating_add(device.expires_in);

    loop {
        if now_unix_secs() >= deadline {
            return Err("device code expired before authorization completed".to_string());
        }

        match request_device_token(provider, cfg, &device.device_code) {
            Ok(token) => return Ok(token),
            Err(TokenPollError::AuthorizationPending) => {
                std::thread::sleep(Duration::from_secs(interval));
            }
            Err(TokenPollError::SlowDown) => {
                interval = interval.saturating_add(5);
                std::thread::sleep(Duration::from_secs(interval));
            }
            Err(TokenPollError::AccessDenied) => {
                return Err("device code authorization denied".to_string());
            }
            Err(TokenPollError::ExpiredToken) => {
                return Err("device code expired".to_string());
            }
            Err(TokenPollError::Other(err)) => return Err(err),
        }
    }
}

pub fn load_token_cache(cfg: &OidcDeviceCodeConfig) -> Result<Option<OidcToken>, String> {
    let path = token_cache_path(cfg);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read token cache {}: {}", path.display(), e))?;
    let token: OidcToken =
        serde_json::from_str(&data).map_err(|e| format!("invalid token cache: {}", e))?;
    if token.cache_version != CACHE_VERSION {
        return Err("unsupported token cache version".to_string());
    }
    Ok(Some(token))
}

pub fn save_token_cache(cfg: &OidcDeviceCodeConfig, token: &OidcToken) -> Result<PathBuf, String> {
    let path = token_cache_path(cfg);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create cache dir {}: {}", parent.display(), e))?;
    }
    let data = serde_json::to_vec_pretty(token)
        .map_err(|e| format!("failed to serialize token cache: {}", e))?;
    fs::write(&path, data)
        .map_err(|e| format!("failed to write token cache {}: {}", path.display(), e))?;
    Ok(path)
}

pub fn resolve_cached_access_token(cfg: &OidcDeviceCodeConfig) -> Result<String, String> {
    let cached = load_token_cache(cfg)?;
    let token = cached.ok_or_else(|| {
        "no cached token found for oidc_device_code; run `toppy login`".to_string()
    })?;

    if token.issuer != cfg.issuer
        || token.client_id != cfg.client_id
        || token.audience != cfg.audience
    {
        return Err("cached token does not match current OIDC configuration".to_string());
    }

    let now = now_unix_secs();
    if !token.is_expired(now) {
        return Ok(token.access_token);
    }

    let refresh = token
        .refresh_token
        .ok_or_else(|| "cached token expired and has no refresh token".to_string())?;
    let provider = discover_provider(&cfg.issuer)?;
    let refreshed = refresh_access_token(&provider, cfg, &refresh)?;
    save_token_cache(cfg, &refreshed)?;
    Ok(refreshed.access_token)
}

fn refresh_access_token(
    provider: &OidcProvider,
    cfg: &OidcDeviceCodeConfig,
    refresh_token: &str,
) -> Result<OidcToken, String> {
    let mut params = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("refresh_token".to_string(), refresh_token.to_string()),
        ("client_id".to_string(), cfg.client_id.clone()),
    ];
    if let Some(scope) = cfg.scope.as_ref() {
        params.push(("scope".to_string(), scope.clone()));
    }
    if let Some(audience) = cfg.audience.as_ref() {
        params.push(("audience".to_string(), audience.clone()));
    }

    let body = http_post_form(&provider.token_endpoint, &params)?;
    let resp: TokenResponse =
        serde_json::from_str(&body).map_err(|e| format!("invalid token response: {}", e))?;
    Ok(OidcToken::from_response(cfg, resp, now_unix_secs()))
}

fn request_device_token(
    provider: &OidcProvider,
    cfg: &OidcDeviceCodeConfig,
    device_code: &str,
) -> Result<OidcToken, TokenPollError> {
    let params = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        ("device_code".to_string(), device_code.to_string()),
        ("client_id".to_string(), cfg.client_id.clone()),
    ];

    let response =
        http_post_form_raw(&provider.token_endpoint, &params).map_err(TokenPollError::Other)?;
    if response.status.is_success() {
        let resp: TokenResponse = serde_json::from_str(&response.body)
            .map_err(|e| TokenPollError::Other(format!("invalid token response: {}", e)))?;
        Ok(OidcToken::from_response(cfg, resp, now_unix_secs()))
    } else if let Ok(err) = serde_json::from_str::<OidcErrorResponse>(&response.body) {
        match err.error.as_str() {
            "authorization_pending" => Err(TokenPollError::AuthorizationPending),
            "slow_down" => Err(TokenPollError::SlowDown),
            "access_denied" => Err(TokenPollError::AccessDenied),
            "expired_token" => Err(TokenPollError::ExpiredToken),
            _ => Err(TokenPollError::Other(format_oidc_error(err))),
        }
    } else {
        Err(TokenPollError::Other(format!(
            "token endpoint error: {}",
            response.body.trim()
        )))
    }
}

struct RawResponse {
    status: reqwest::StatusCode,
    body: String,
}

fn http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {}", e))
}

fn http_get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, String> {
    let client = http_client()?;
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("GET {} failed: {}", url, e))?;
    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("failed to read response from {}: {}", url, e))?;
    if !status.is_success() {
        return Err(format!("GET {} failed: {}", url, body.trim()));
    }
    serde_json::from_str(&body).map_err(|e| format!("invalid JSON from {}: {}", url, e))
}

fn http_post_form(url: &str, params: &[(String, String)]) -> Result<String, String> {
    let response = http_post_form_raw(url, params)?;
    if response.status.is_success() {
        Ok(response.body)
    } else if let Ok(err) = serde_json::from_str::<OidcErrorResponse>(&response.body) {
        Err(format_oidc_error(err))
    } else {
        Err(format!("POST {} failed: {}", url, response.body.trim()))
    }
}

fn http_post_form_raw(url: &str, params: &[(String, String)]) -> Result<RawResponse, String> {
    let client = http_client()?;
    let response = client
        .post(url)
        .form(&params)
        .send()
        .map_err(|e| format!("POST {} failed: {}", url, e))?;
    let status = response.status();
    let body = response
        .text()
        .map_err(|e| format!("failed to read response from {}: {}", url, e))?;
    Ok(RawResponse { status, body })
}

fn format_oidc_error(err: OidcErrorResponse) -> String {
    let mut message = format!("oidc error: {}", err.error);
    if let Some(desc) = err.error_description {
        message.push_str(&format!(" ({})", desc));
    }
    if let Some(uri) = err.error_uri {
        message.push_str(&format!(" [{}]", uri));
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockOidcServer {
        addr: String,
    }

    #[derive(Default)]
    struct MockState {
        token_calls: usize,
    }

    impl MockOidcServer {
        fn start() -> Option<Self> {
            let listener = match TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => listener,
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return None,
                Err(err) => panic!("bind: {}", err),
            };
            let addr = listener.local_addr().expect("addr");
            let state = Arc::new(Mutex::new(MockState::default()));
            let state_clone = Arc::clone(&state);

            thread::spawn(move || {
                for stream in listener.incoming() {
                    let mut stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let state = Arc::clone(&state_clone);
                    handle_mock_request(&mut stream, &state);
                }
            });

            Some(MockOidcServer {
                addr: format!("http://{}", addr),
            })
        }

        fn issuer(&self) -> String {
            self.addr.clone()
        }
    }

    fn read_request(stream: &mut TcpStream) -> (String, String, String) {
        let mut buffer = Vec::new();
        let mut temp = [0u8; 1024];
        loop {
            let n = stream.read(&mut temp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..n]);
            if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buffer).to_string();
        let mut headers_body = request.splitn(2, "\r\n\r\n");
        let headers = headers_body.next().unwrap_or("");
        let mut body = headers_body.next().unwrap_or("").to_string();

        let mut content_length = 0usize;
        for line in headers.lines() {
            if let Some(value) = line.strip_prefix("Content-Length:") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
        if body.len() < content_length {
            let mut remaining = vec![0u8; content_length - body.len()];
            let _ = stream.read_exact(&mut remaining);
            body.push_str(&String::from_utf8_lossy(&remaining));
        }

        let mut parts = headers.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        (method, path, body)
    }

    fn respond(stream: &mut TcpStream, status: &str, body: &str) {
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            status,
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    }

    fn handle_mock_request(stream: &mut TcpStream, state: &Arc<Mutex<MockState>>) {
        let (_method, path, _body) = read_request(stream);
        if path == "/.well-known/openid-configuration" {
            let addr = stream.local_addr().unwrap();
            let base = format!("http://{}", addr);
            let body = format!(
                "{{\"device_authorization_endpoint\":\"{}/device\",\"token_endpoint\":\"{}/token\"}}",
                base, base
            );
            respond(stream, "200 OK", &body);
            return;
        }
        if path == "/device" {
            let body = "{\"device_code\":\"device-123\",\"user_code\":\"CODE-456\",\"verification_uri\":\"https://verify.example\",\"verification_uri_complete\":\"https://verify.example/?user_code=CODE-456\",\"expires_in\":30,\"interval\":1}";
            respond(stream, "200 OK", body);
            return;
        }
        if path == "/token" {
            let mut guard = state.lock().unwrap();
            guard.token_calls += 1;
            if guard.token_calls == 1 {
                let body =
                    "{\"error\":\"authorization_pending\",\"error_description\":\"pending\"}";
                respond(stream, "400 Bad Request", body);
            } else {
                let body = "{\"access_token\":\"token-abc\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"refresh-xyz\"}";
                respond(stream, "200 OK", body);
            }
            return;
        }

        respond(stream, "404 Not Found", "{\"error\":\"not_found\"}");
    }

    #[test]
    fn device_code_flow_succeeds_against_mock() {
        let server = match MockOidcServer::start() {
            Some(server) => server,
            None => return,
        };
        let cfg = OidcDeviceCodeConfig {
            issuer: server.issuer(),
            client_id: "client-123".to_string(),
            audience: None,
            scope: Some("openid".to_string()),
            token_cache_path: None,
        };

        let provider = discover_provider(&cfg.issuer).expect("discover");
        let device = request_device_code(&provider, &cfg).expect("device code");
        assert_eq!(device.user_code, "CODE-456");

        let token = poll_device_code(&provider, &cfg, &device).expect("token");
        assert_eq!(token.access_token, "token-abc");
        assert_eq!(token.refresh_token.as_deref(), Some("refresh-xyz"));
    }

    #[test]
    fn token_cache_roundtrip() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let cache_path = env::temp_dir()
            .join(format!("toppy-oidc-cache-{}.json", nanos))
            .to_string_lossy()
            .to_string();
        let cfg = OidcDeviceCodeConfig {
            issuer: "https://issuer.example".to_string(),
            client_id: "client".to_string(),
            audience: Some("aud".to_string()),
            scope: None,
            token_cache_path: Some(cache_path),
        };
        let token = OidcToken {
            cache_version: CACHE_VERSION,
            issuer: cfg.issuer.clone(),
            client_id: cfg.client_id.clone(),
            audience: cfg.audience.clone(),
            access_token: "token".to_string(),
            refresh_token: Some("refresh".to_string()),
            token_type: Some("Bearer".to_string()),
            scope: Some("openid".to_string()),
            issued_at: now_unix_secs(),
            expires_at: Some(now_unix_secs() + 3600),
        };

        let path = save_token_cache(&cfg, &token).expect("save");
        let loaded = load_token_cache(&cfg).expect("load").expect("cached");
        assert_eq!(loaded, token);
        let _ = fs::remove_file(path);
    }
}
