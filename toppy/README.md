# toppy

This repository contains the source code for **Toppy**, a Rust-based project implementing a MASQUE-compatible gateway and client toolkit.

## Project structure

The project is organized as a Cargo workspace with multiple crates:

- `toppy-cli`: Command‑line interface for users to interact with the gateway and manage connections.
- `toppy-gw`: A lightweight MASQUE gateway implementation built on HTTP/3 for tunnelling IP and UDP traffic.
- `toppy-core`: Shared functionality, including configuration management, policy enforcement, and logging.
- `toppy-proto`: Definitions of the custom capsule/command messages used between client and gateway.

This repository is currently a minimal skeleton to get started. Each crate includes a basic Rust program or library that will compile successfully. See `toppy_spec_and_todo.md` in the parent directory for a high‑level specification and TODO list.