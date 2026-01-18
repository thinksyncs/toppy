use ring::digest;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(e) => write!(f, "io error: {}", e),
            AuditError::Json(e) => write!(f, "json error: {}", e),
            AuditError::Invalid(msg) => write!(f, "invalid audit log: {}", msg),
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
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for b in digest.as_ref() {
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

fn compute_hash(version: u32, seq: u64, unix_ms: u64, event: &AuditEvent, prev_hash: Option<&str>) -> Result<String, AuditError> {
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

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        Ok(Self {
            path,
            writer: BufWriter::new(file),
            next_seq,
            prev_hash,
        })
    }

    pub fn append(&mut self, unix_ms: u64, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        let version = 1u32;
        let seq = self.next_seq;
        let prev_hash = self.prev_hash.as_deref();
        let hash = compute_hash(version, seq, unix_ms, &event, prev_hash)?;

        let entry = AuditEntry {
            version,
            seq,
            unix_ms,
            event,
            prev_hash: self.prev_hash.clone(),
            hash: hash.clone(),
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

pub fn verify_chain(path: impl AsRef<Path>) -> Result<(), AuditError> {
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
            return Err(AuditError::Invalid(format!("hash mismatch at line {}", idx + 1)));
        }

        expected_prev = Some(entry.hash);
        expected_seq = expected_seq.saturating_add(1);
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
        p.push(format!(
            "toppy-audit-{}-{}",
            name,
            std::process::id()
        ));
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
}
