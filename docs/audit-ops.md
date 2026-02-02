# Audit logging: operations and threat model notes

This note covers how audit logs are written, verified, and optionally shipped.

## Local audit log

- Format: JSONL with a hash chain per entry.
- Location (default): `~/.local/share/toppy/audit.jsonl`.
- Override (highest priority):
  1. `TOPPY_AUDIT_LOG`
  2. `audit_log_path` in `config.toml`

## Optional HMAC signing

- Configure `TOPPY_AUDIT_SIGNING_KEY` or `audit_signing_key`.
- Each entry includes a signature over the entry hash (HMAC-SHA256).
- Verification requires the same key:
  - `toppy audit verify --signing-key <key>`

### Key management guidance

- Store the signing key in a secret manager or restricted env var.
- Rotate keys by switching to a new log file path.
- Keep keys out of shell history or shared config files.

## Optional remote shipping (best-effort)

- Configure `TOPPY_AUDIT_SHIP_URL` or `audit_ship_url`.
- Optional `TOPPY_AUDIT_SHIP_TOKEN` / `audit_ship_token` (Bearer).
- Optional `TOPPY_AUDIT_SHIP_TIMEOUT` / `audit_ship_timeout_secs` (seconds; default 3).

Behavior:
- Shipping happens per-entry, synchronously after append.
- Failures are logged to stderr; local append still succeeds.
- Use HTTPS endpoints and validate inbound auth at the receiver.

## Threat model notes

- Hash chains detect local tampering after the fact.
- HMAC signing helps detect tampering across shipping boundaries.
- A fully compromised client can still forge events; this is not a remote attestation system.
