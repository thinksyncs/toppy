use ring::digest;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
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
}

pub fn ship_entry(entry: &AuditEntry, cfg: &AuditShipConfig) -> Result<(), AuditError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .build()
        .map_err(|e| AuditError::Ship(format!("failed to build HTTP client: {}", e)))?;

    let mut request = client.post(&cfg.url).json(entry);
    if let Some(token) = cfg.token.as_ref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .map_err(|e| AuditError::Ship(format!("failed to ship audit entry: {}", e)))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(AuditError::Ship(format!(
            "ship failed: {} {}",
            status,
            body.trim()
        )));
    }
    Ok(())
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

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("toppy-audit-{}-{}", name, std::process::id()));
        p
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
}
