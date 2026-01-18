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
4. Run the doctor checks:
   - `cargo run -p toppy-cli -- doctor --json`
   - Or `make doctor`

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
- Audit logs for connection activity (planned).
- Out of scope for MVP: full L3 VPN, non-OIDC IdPs, full CONNECT-UDP proxying to arbitrary UDP targets.

## License

MIT
