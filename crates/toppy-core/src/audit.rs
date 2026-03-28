use ring::digest;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(String),
    Ship(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(e) => write!(f, "io error: {}", e),
            AuditError::Json(e) => write!(f, "json error: {}", e),
            AuditError::Invalid(msg) => write!(f, "invalid audit log: {}", msg),
            AuditError::Ship(msg) => write!(f, "audit ship error: {}", msg),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<io::Error> for AuditError {
    fn from(value: io::Error) -> Self {
        AuditError::Io(value)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(value: serde_json::Error) -> Self {
        AuditError::Json(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AuditEvent {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AuditEntry {
    pub version: u32,
    pub seq: u64,
    /// Unix timestamp in milliseconds.
    pub unix_ms: u64,
    pub event: AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct AuditEntryUnsigned<'a> {
    version: u32,
    seq: u64,
    unix_ms: u64,
    event: &'a AuditEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_hash: Option<&'a str>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, bytes);
    hex_encode(digest.as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_char((b >> 4) & 0x0f));
        out.push(hex_char(b & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '0',
    }
}

fn compute_hash(
    version: u32,
    seq: u64,
    unix_ms: u64,
    event: &AuditEvent,
    prev_hash: Option<&str>,
) -> Result<String, AuditError> {
    let unsigned = AuditEntryUnsigned {
        version,
        seq,
        unix_ms,
        event,
        prev_hash,
    };
    let bytes = serde_json::to_vec(&unsigned)?;
    Ok(sha256_hex(&bytes))
}

fn compute_signature(hash: &str, key: &[u8]) -> String {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let sig = hmac::sign(&signing_key, hash.as_bytes());
    hex_encode(sig.as_ref())
}

pub struct AuditChainWriter {
    path: PathBuf,
    writer: BufWriter<File>,
    next_seq: u64,
    prev_hash: Option<String>,
}

impl AuditChainWriter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();

        let mut next_seq = 1u64;
        let mut prev_hash: Option<String> = None;

        if path.exists() {
            if let Some(last) = read_last_entry(&path)? {
                // Basic sanity: verify the last entry hash is self-consistent.
                let expected = compute_hash(
                    last.version,
                    last.seq,
                    last.unix_ms,
                    &last.event,
                    last.prev_hash.as_deref(),
                )?;
                if expected != last.hash {
                    return Err(AuditError::Invalid("last entry hash mismatch".to_string()));
                }
                next_seq = last.seq.saturating_add(1);
                prev_hash = Some(last.hash);
            }
        }

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            path,
            writer: BufWriter::new(file),
            next_seq,
            prev_hash,
        })
    }

    pub fn append(&mut self, unix_ms: u64, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        self.append_with_signing_key(unix_ms, event, None)
    }

    pub fn append_with_signing_key(
        &mut self,
        unix_ms: u64,
        event: AuditEvent,
        signing_key: Option<&[u8]>,
    ) -> Result<AuditEntry, AuditError> {
        let version = 1u32;
        let seq = self.next_seq;
        let prev_hash = self.prev_hash.as_deref();
        let hash = compute_hash(version, seq, unix_ms, &event, prev_hash)?;
        let signature = signing_key.map(|key| compute_signature(&hash, key));

        let entry = AuditEntry {
            version,
            seq,
            unix_ms,
            event,
            prev_hash: self.prev_hash.clone(),
            hash: hash.clone(),
            signature,
        };

        serde_json::to_writer(&mut self.writer, &entry)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;

        self.next_seq = self.next_seq.saturating_add(1);
        self.prev_hash = Some(hash);
        Ok(entry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn default_audit_log_path() -> PathBuf {
    // ~/.local/share/toppy/audit.jsonl (Linux-ish); good enough for now.
    // macOS will also work with HOME, and users can override via config/env.
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("toppy")
            .join("audit.jsonl")
    } else {
        PathBuf::from("toppy-audit.jsonl")
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn append_event(
    path: impl AsRef<Path>,
    unix_ms: u64,
    event: AuditEvent,
) -> Result<AuditEntry, AuditError> {
    let mut w = AuditChainWriter::open(path)?;
    w.append(unix_ms, event)
}

pub fn append_event_signed(
    path: impl AsRef<Path>,
    unix_ms: u64,
    event: AuditEvent,
    signing_key: Option<&[u8]>,
) -> Result<AuditEntry, AuditError> {
    let mut w = AuditChainWriter::open(path)?;
    w.append_with_signing_key(unix_ms, event, signing_key)
}

pub fn verify_chain(path: impl AsRef<Path>) -> Result<(), AuditError> {
    verify_chain_with_signing_key(path, None)
}

pub fn verify_chain_with_signing_key(
    path: impl AsRef<Path>,
    signing_key: Option<&[u8]>,
) -> Result<(), AuditError> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_prev: Option<String> = None;
    let mut expected_seq: u64 = 1;

    for (idx, line_res) in reader.lines().enumerate() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)?;

        if entry.seq != expected_seq {
            return Err(AuditError::Invalid(format!(
                "seq mismatch at line {}: expected {}, got {}",
                idx + 1,
                expected_seq,
                entry.seq
            )));
        }

        if entry.prev_hash != expected_prev {
            return Err(AuditError::Invalid(format!(
                "prev_hash mismatch at line {}",
                idx + 1
            )));
        }

        let expected_hash = compute_hash(
            entry.version,
            entry.seq,
            entry.unix_ms,
            &entry.event,
            entry.prev_hash.as_deref(),
        )?;
        if expected_hash != entry.hash {
            return Err(AuditError::Invalid(format!(
                "hash mismatch at line {}",
                idx + 1
            )));
        }

        if let Some(sig) = entry.signature.as_deref() {
            let key = signing_key.ok_or_else(|| {
                AuditError::Invalid(format!(
                    "signature present but no signing key at line {}",
                    idx + 1
                ))
            })?;
            let expected_sig = compute_signature(&entry.hash, key);
            if expected_sig != sig {
                return Err(AuditError::Invalid(format!(
                    "signature mismatch at line {}",
                    idx + 1
                )));
            }
        }

        expected_prev = Some(entry.hash);
        expected_seq = expected_seq.saturating_add(1);
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct AuditShipConfig {
    pub url: String,
    pub token: Option<String>,
    pub timeout_secs: u64,
    pub retry_attempts: u32,
    pub retry_backoff_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AuditRemoteVerifyConfig {
    pub url: String,
    pub token: Option<String>,
    pub timeout_secs: u64,
    pub retry_attempts: u32,
    pub retry_backoff_ms: u64,
}

#[derive(Debug, Deserialize)]
struct AuditRemoteVerifyResponse {
    verified: Option<bool>,
    ok: Option<bool>,
    message: Option<String>,
}

pub fn load_entries(path: impl AsRef<Path>) -> Result<Vec<AuditEntry>, AuditError> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line_res in reader.lines() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        entries.push(serde_json::from_str(&line)?);
    }

    Ok(entries)
}

pub fn ship_entry(entry: &AuditEntry, cfg: &AuditShipConfig) -> Result<(), AuditError> {
    with_retry(cfg.retry_attempts, cfg.retry_backoff_ms, || {
        let client = audit_http_client(cfg.timeout_secs)?;
        let response = audit_post_json(&client, &cfg.url, cfg.token.as_deref(), entry)
            .map_err(|e| AuditError::Ship(format!("failed to ship audit entry: {}", e)))?;
        handle_audit_http_response("ship failed", response)
    })
}

pub fn ship_entries(entries: &[AuditEntry], cfg: &AuditShipConfig) -> Result<(), AuditError> {
    with_retry(cfg.retry_attempts, cfg.retry_backoff_ms, || {
        let client = audit_http_client(cfg.timeout_secs)?;
        let response = audit_post_json(&client, &cfg.url, cfg.token.as_deref(), entries)
            .map_err(|e| AuditError::Ship(format!("failed to ship audit batch: {}", e)))?;
        handle_audit_http_response("batch ship failed", response)
    })
}

pub fn verify_chain_remote(
    path: impl AsRef<Path>,
    cfg: &AuditRemoteVerifyConfig,
) -> Result<String, AuditError> {
    let entries = load_entries(path)?;
    with_retry(cfg.retry_attempts, cfg.retry_backoff_ms, || {
        let client = audit_http_client(cfg.timeout_secs)?;
        let response = audit_post_json(&client, &cfg.url, cfg.token.as_deref(), &entries)
            .map_err(|e| AuditError::Ship(format!("failed to request remote verify: {}", e)))?;
        let status = response.status();
        let body = response.text().map_err(|e| {
            AuditError::Ship(format!("failed to read remote verify response: {}", e))
        })?;
        if !status.is_success() {
            return Err(AuditError::Ship(format!(
                "remote verify failed: {} {}",
                status,
                body.trim()
            )));
        }
        if body.trim().is_empty() {
            return Ok("remote verify ok".to_string());
        }
        if let Ok(parsed) = serde_json::from_str::<AuditRemoteVerifyResponse>(&body) {
            if parsed.verified == Some(false) || parsed.ok == Some(false) {
                return Err(AuditError::Ship(parsed.message.unwrap_or_else(|| {
                    "remote verify rejected the audit chain".to_string()
                })));
            }
            return Ok(parsed
                .message
                .unwrap_or_else(|| "remote verify ok".to_string()));
        }
        Ok(body.trim().to_string())
    })
}

fn audit_http_client(timeout_secs: u64) -> Result<reqwest::blocking::Client, AuditError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| AuditError::Ship(format!("failed to build HTTP client: {}", e)))
}

fn audit_post_json<T: Serialize + ?Sized>(
    client: &reqwest::blocking::Client,
    url: &str,
    token: Option<&str>,
    payload: &T,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let mut request = client.post(url).json(payload);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send()
}

fn handle_audit_http_response(
    prefix: &str,
    response: reqwest::blocking::Response,
) -> Result<(), AuditError> {
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().unwrap_or_default();
    Err(AuditError::Ship(format!(
        "{}: {} {}",
        prefix,
        status,
        body.trim()
    )))
}

fn with_retry<T, F>(retry_attempts: u32, retry_backoff_ms: u64, mut f: F) -> Result<T, AuditError>
where
    F: FnMut() -> Result<T, AuditError>,
{
    let mut last_err = None;
    for attempt in 0..=retry_attempts {
        match f() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt == retry_attempts {
                    break;
                }
                let multiplier = 1u64 << attempt.min(10);
                let delay = retry_backoff_ms.saturating_mul(multiplier);
                if delay > 0 {
                    thread::sleep(Duration::from_millis(delay));
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| AuditError::Ship("retry exhausted".to_string())))
}

fn read_last_entry(path: &Path) -> Result<Option<AuditEntry>, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut last: Option<AuditEntry> = None;
    for line_res in reader.lines() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(serde_json::from_str(&line)?);
    }

    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::ErrorKind;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("toppy-audit-{}-{}", name, std::process::id()));
        p
    }

    #[derive(Default)]
    struct MockAuditServerState {
        responses: Vec<(u16, String)>,
        bodies: Vec<String>,
    }

    struct MockAuditServer {
        addr: String,
        state: Arc<Mutex<MockAuditServerState>>,
    }

    impl MockAuditServer {
        fn start(responses: Vec<(u16, String)>) -> Option<Self> {
            let listener = match TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => listener,
                Err(err) if err.kind() == ErrorKind::PermissionDenied => return None,
                Err(err) => panic!("bind mock audit server: {}", err),
            };
            let addr = listener.local_addr().expect("addr");
            let state = Arc::new(Mutex::new(MockAuditServerState {
                responses,
                bodies: Vec::new(),
            }));
            let state_clone = Arc::clone(&state);

            thread::spawn(move || {
                for stream in listener.incoming() {
                    let mut stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    handle_mock_audit_request(&mut stream, &state_clone);
                }
            });

            Some(Self {
                addr: format!("http://{}", addr),
                state,
            })
        }

        fn url(&self) -> &str {
            &self.addr
        }

        fn bodies(&self) -> Vec<String> {
            self.state.lock().expect("state").bodies.clone()
        }
    }

    fn handle_mock_audit_request(stream: &mut TcpStream, state: &Arc<Mutex<MockAuditServerState>>) {
        let mut buf = Vec::new();
        let mut temp = [0u8; 1024];
        let mut header_end = None;

        loop {
            let n = stream.read(&mut temp).expect("read request");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&temp[..n]);
            if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(idx + 4);
                break;
            }
        }

        let header_end = header_end.expect("header end");
        let headers = String::from_utf8_lossy(&buf[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = buf[header_end..].to_vec();
        while body.len() < content_length {
            let n = stream.read(&mut temp).expect("read body");
            if n == 0 {
                break;
            }
            body.extend_from_slice(&temp[..n]);
        }

        let body = String::from_utf8_lossy(&body[..content_length]).to_string();
        let (status, response_body) = {
            let mut guard = state.lock().expect("state");
            guard.bodies.push(body);
            if guard.responses.is_empty() {
                (200, "{\"ok\":true}".to_string())
            } else {
                guard.responses.remove(0)
            }
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            status,
            if status == 200 { "OK" } else { "ERR" },
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    }

    #[test]
    fn audit_chain_roundtrip_and_verify() {
        let path = temp_path("roundtrip.jsonl");
        let _ = fs::remove_file(&path);

        let mut w = AuditChainWriter::open(&path).unwrap();
        w.append(
            1,
            AuditEvent {
                actor: "alice".to_string(),
                action: "connect".to_string(),
                target: "127.0.0.1:22".to_string(),
                allowed: true,
                auth_subject: None,
                reason: None,
            },
        )
        .unwrap();
        w.append(
            2,
            AuditEvent {
                actor: "alice".to_string(),
                action: "connect".to_string(),
                target: "127.0.0.1:23".to_string(),
                allowed: false,
                auth_subject: None,
                reason: Some("not allowed".to_string()),
            },
        )
        .unwrap();

        verify_chain(&path).unwrap();

        // Re-open and append more.
        let mut w2 = AuditChainWriter::open(&path).unwrap();
        w2.append(
            3,
            AuditEvent {
                actor: "bob".to_string(),
                action: "doctor".to_string(),
                target: "cfg".to_string(),
                allowed: true,
                auth_subject: None,
                reason: None,
            },
        )
        .unwrap();

        verify_chain(&path).unwrap();

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn audit_chain_detects_tamper() {
        let path = temp_path("tamper.jsonl");
        let _ = fs::remove_file(&path);

        {
            let mut w = AuditChainWriter::open(&path).unwrap();
            w.append(
                1,
                AuditEvent {
                    actor: "alice".to_string(),
                    action: "connect".to_string(),
                    target: "127.0.0.1:22".to_string(),
                    allowed: true,
                    auth_subject: None,
                    reason: None,
                },
            )
            .unwrap();
        }

        // Tamper by rewriting the line.
        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        // Flip a field in JSON (best-effort). This should break hash verification.
        let tampered = lines[0].replace("\"allowed\":true", "\"allowed\":false");
        fs::write(&path, format!("{}\n", tampered)).unwrap();

        let err = verify_chain(&path).unwrap_err();
        match err {
            AuditError::Invalid(_) => {}
            other => panic!("expected invalid error, got: {:?}", other),
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_event_helper_integrates_with_verify() {
        let path = temp_path("append-helper.jsonl");
        let _ = fs::remove_file(&path);

        append_event(
            &path,
            10,
            AuditEvent {
                actor: "alice".to_string(),
                action: "doctor".to_string(),
                target: "cfg".to_string(),
                allowed: true,
                auth_subject: None,
                reason: None,
            },
        )
        .unwrap();

        verify_chain(&path).unwrap();

        // Tamper by changing a field.
        let contents = fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().unwrap();
        let tampered = line.replace("\"action\":\"doctor\"", "\"action\":\"up\"");
        fs::write(&path, format!("{}\n", tampered)).unwrap();

        assert!(verify_chain(&path).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn audit_chain_sign_and_verify() {
        let path = temp_path("signed.jsonl");
        let _ = fs::remove_file(&path);

        let mut w = AuditChainWriter::open(&path).unwrap();
        w.append_with_signing_key(
            1,
            AuditEvent {
                actor: "alice".to_string(),
                action: "login".to_string(),
                target: "cfg".to_string(),
                allowed: true,
                auth_subject: None,
                reason: None,
            },
            Some(b"signing-key"),
        )
        .unwrap();

        verify_chain_with_signing_key(&path, Some(b"signing-key")).unwrap();
        assert!(verify_chain_with_signing_key(&path, None).is_err());
        assert!(verify_chain_with_signing_key(&path, Some(b"wrong")).is_err());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ship_entry_retries_and_succeeds() {
        let Some(server) = MockAuditServer::start(vec![
            (500, "{\"ok\":false}".to_string()),
            (200, "{\"ok\":true}".to_string()),
        ]) else {
            return;
        };
        let entry = AuditEntry {
            version: 1,
            seq: 1,
            unix_ms: 1,
            event: AuditEvent {
                actor: "alice".to_string(),
                action: "doctor".to_string(),
                target: "cfg".to_string(),
                allowed: true,
                auth_subject: Some("user-123".to_string()),
                reason: None,
            },
            prev_hash: None,
            hash: "hash".to_string(),
            signature: None,
        };
        let cfg = AuditShipConfig {
            url: server.url().to_string(),
            token: None,
            timeout_secs: 2,
            retry_attempts: 1,
            retry_backoff_ms: 1,
        };

        ship_entry(&entry, &cfg).expect("ship entry");
        assert_eq!(server.bodies().len(), 2);
    }

    #[test]
    fn ship_entries_sends_json_array() {
        let Some(server) = MockAuditServer::start(vec![(200, "{\"ok\":true}".to_string())]) else {
            return;
        };
        let entries = vec![
            AuditEntry {
                version: 1,
                seq: 1,
                unix_ms: 1,
                event: AuditEvent {
                    actor: "alice".to_string(),
                    action: "doctor".to_string(),
                    target: "cfg".to_string(),
                    allowed: true,
                    auth_subject: None,
                    reason: None,
                },
                prev_hash: None,
                hash: "hash-1".to_string(),
                signature: None,
            },
            AuditEntry {
                version: 1,
                seq: 2,
                unix_ms: 2,
                event: AuditEvent {
                    actor: "alice".to_string(),
                    action: "up".to_string(),
                    target: "127.0.0.1:22".to_string(),
                    allowed: true,
                    auth_subject: None,
                    reason: None,
                },
                prev_hash: Some("hash-1".to_string()),
                hash: "hash-2".to_string(),
                signature: None,
            },
        ];
        let cfg = AuditShipConfig {
            url: server.url().to_string(),
            token: None,
            timeout_secs: 2,
            retry_attempts: 0,
            retry_backoff_ms: 0,
        };

        ship_entries(&entries, &cfg).expect("ship entries");
        let body = server.bodies().pop().expect("body");
        assert!(body.starts_with('['));
    }

    #[test]
    fn verify_chain_remote_accepts_verified_response() {
        let path = temp_path("remote-verify.jsonl");
        let _ = fs::remove_file(&path);
        append_event(
            &path,
            1,
            AuditEvent {
                actor: "alice".to_string(),
                action: "doctor".to_string(),
                target: "cfg".to_string(),
                allowed: true,
                auth_subject: Some("user-123".to_string()),
                reason: None,
            },
        )
        .unwrap();

        let Some(server) = MockAuditServer::start(vec![(
            200,
            "{\"verified\":true,\"message\":\"remote verified\"}".to_string(),
        )]) else {
            return;
        };
        let cfg = AuditRemoteVerifyConfig {
            url: server.url().to_string(),
            token: None,
            timeout_secs: 2,
            retry_attempts: 0,
            retry_backoff_ms: 0,
        };

        let message = verify_chain_remote(&path, &cfg).expect("remote verify");
        assert_eq!(message, "remote verified");
        let _ = fs::remove_file(&path);
    }
}
