# toppy

This repository contains the source code for **Toppy**, a Rust-based project implementing a MASQUE-compatible gateway and client toolkit.

## Project structure

The project is organized as a Cargo workspace with multiple crates:

- `toppy-cli`: Command-line interface for users to interact with the gateway and manage connections.
- `toppy-gw`: A lightweight MASQUE gateway implementation built on HTTP/3 for tunneling IP and UDP traffic.
- `toppy-core`: Shared functionality, including configuration management, policy enforcement, and logging.
- `toppy-proto`: Definitions of the custom capsule/command messages used between client and gateway.

This repository is currently a minimal skeleton to get started. Each crate includes a basic Rust program or library that will compile successfully. See `spec.md` for a high-level specification and TODO list.

## Quickstart (5 min)

1. Install Rust stable (rustup).
2. Build the workspace:
   - `cargo build`
3. Create a minimal config:
   - `~/.config/toppy/config.toml`
   - Example:
     ```toml
     gateway = "127.0.0.1"
     port = 4433
     server_name = "localhost"
     ca_cert_path = "crates/toppy-gw/testdata/localhost-cert.pem"
     auth_token = "dev-token"
     mtu = 1350
     ```

   - JWT auth (optional):
     - Set `TOPPY_GW_JWT_SECRET` (and optional `TOPPY_GW_JWT_ISS`, `TOPPY_GW_JWT_AUD`) in the gateway.
     - Set `auth_token` to a JWT signed with the shared secret.

   - Auth mode selection (skeleton; keeps CLI UX stable):
     - Default behavior stays the same: `auth_token` is used as-is.
     - You can also specify an explicit mode under `[auth]`:
       ```toml
       [auth]
       mode = "token"
       token = "dev-token"
       ```
     - OIDC device-code and direct SAML are intentionally only config stubs for now.
4. Run the doctor checks:
   - `cargo run -p toppy-cli -- doctor --json`
   - Or `make doctor`

## Dev setup

If you don't have Rust installed yet, run:

- `make bootstrap`

Manual install (recommended):

- macOS/Linux: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` then `source ~/.cargo/env`
- Windows: install from https://rustup.rs/

After that, local quality gates:

- `make fmt clippy test`

### CONNECT-UDP verification (doctor)

If the gateway is running and reachable, `toppy doctor` will also attempt a minimal
CONNECT-UDP validation using HTTP/3 Extended CONNECT + HTTP Datagrams.

- Start the gateway (one option):
   - `make compose-up`
- Run doctor:
   - `make doctor`

In the JSON output, verify these checks are `pass`:

- `masque.connect_udp` (Extended CONNECT handshake)
- `masque.connect_udp.datagram` (HTTP Datagram echo)

## Gateway healthcheck (docker compose)

- `make compose-up`
- Wait until `docker compose ps` shows `healthy` for `toppy-gw`.
- `curl -fsS http://localhost:8080/healthz`
- `make compose-down`

## Threat model (summary)

- Short-lived credentials and default-deny policies to limit blast radius.
- Audit logs for connection activity are recorded locally as tamper-evident JSONL.
- Out of scope for MVP: full L3 VPN, direct SAML integration, full CONNECT-UDP proxying to arbitrary UDP targets.

## Audit logs

Toppy can write a tamper-evident audit log (hash-chained JSONL) for actions like `doctor` and `up`.

Audit log path resolution (highest priority first):

1. `TOPPY_AUDIT_LOG` env var
2. `audit_log_path` in `config.toml`
3. Default: `~/.local/share/toppy/audit.jsonl`

Verify the log:

- `cargo run -p toppy-cli -- audit verify`
- Or: `TOPPY_AUDIT_LOG=/path/to/audit.jsonl cargo run -p toppy-cli -- audit verify`

## IdP expansion (Phase 3 decision)

For the next milestone, Toppy treats MFA and FIDO2 as **IdP concerns**, not separate client modes:

- Supported now: **static token/JWT** via `auth_token` (or `[auth] mode="token"`).
- Planned next: **OIDC device-code flow** (MFA/FIDO2 happen at the IdP during login).
- Not supported directly: **SAML** (recommended: SAML-to-OIDC broker / federation, or mint JWT out-of-band).

## Session rate limiting (`toppy up`)

The `toppy up` TCP forwarder applies a per-connection token-bucket rate limit to session traffic.

Defaults (when `[rate]` is omitted): **10 MiB/s** with a **10 MiB burst** (per direction).

Configure in `~/.config/toppy/config.toml`:

```toml
[rate]
bytes_per_sec = 10485760
burst_bytes = 10485760
```

Disable:

```toml
[rate]
bytes_per_sec = 0
burst_bytes = 0
```

## License

MIT
