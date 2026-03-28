# toppy

Toppy is a Rust workspace for experimenting with a MASQUE-oriented access gateway and a small client CLI.

Current scope:
- `toppy-gw`: QUIC ping plus HTTP/3 Extended CONNECT for CONNECT-UDP.
- `toppy-cli`: `doctor`, `login`, `up`, `udp`, `audit verify`, `audit ship`, and `audit remote-verify`.
- `toppy-core`: config, auth, policy, audit, doctor, and rate-limit primitives.
- `toppy-proto`: protocol helpers for CONNECT-UDP and HTTP Datagrams.

## Quickstart

1. Install Rust stable.
2. Build the workspace:

```bash
cargo build
```

3. Create `~/.config/toppy/config.toml`:

```toml
gateway = "127.0.0.1"
port = 4433
server_name = "localhost"
ca_cert_path = "crates/toppy-gw/testdata/localhost-cert.pem"
auth_token = "dev-token"
mtu = 1350

[policy]
  [[policy.allow]]
  cidr = "127.0.0.1/32"
  ports = [22, 443]
```

4. Run diagnostics:

```bash
cargo run -p toppy-cli -- doctor --json
```

## Commands

- `toppy doctor [--json]`: config and environment diagnostics.
- `toppy login [--print-token]`: token acquisition and cache management.
- `toppy up --target <ip:port> --listen <ip:port> [--once]`: local TCP forwarder.
- `toppy udp --target <ip:port> --listen <ip:port>`: local UDP proxy over CONNECT-UDP.
- `toppy audit verify [--path <file>]`: verify local tamper-evident audit logs.
- `toppy audit ship [--path <file>] [--batch-size <n>]`: replay local audit logs to the configured remote endpoint in batches.
- `toppy audit remote-verify --url <url> [--path <file>]`: submit the local audit chain to a remote verifier.

Additional behavior:

- `toppy udp` applies per-peer rate limits, idle cleanup, and peer caps. Use `TOPPY_UDP_IDLE_SECS` / `TOPPY_UDP_MAX_PEERS` to tune session controls.
- Policy rules can match `subjects` and selected scalar JWT `claims` in addition to CIDR and port rules.

## Docs

- Usage-oriented spec: [spec.md](spec.md)
- LaTeX manual source: [docs/manual.tex](docs/manual.tex)
- Audit operations note: [docs/audit-ops.md](docs/audit-ops.md)
- Backlog tracking: `bd list`, `bd show <id>`, `bd ready`

To build the manual locally:

```bash
cd docs
pdflatex manual.tex
```

## Development

- Local quality gates:

```bash
make fmt clippy test
```

- Integration / E2E:

```bash
./scripts/it-compose.sh
./scripts/e2e-tcp.sh
```

## Audit Shipping

- Per-entry shipping supports retries via `TOPPY_AUDIT_SHIP_RETRIES` and `TOPPY_AUDIT_SHIP_BACKOFF_MS`.
- Batch replay defaults to 100 entries per request and can be tuned with `TOPPY_AUDIT_SHIP_BATCH_SIZE`.
- Remote verification supports `TOPPY_AUDIT_VERIFY_URL`, `TOPPY_AUDIT_VERIFY_TOKEN`, `TOPPY_AUDIT_VERIFY_TIMEOUT`, `TOPPY_AUDIT_VERIFY_RETRIES`, and `TOPPY_AUDIT_VERIFY_BACKOFF_MS`.

## License

MIT
