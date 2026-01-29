SHELL := /bin/bash

CARGO ?= cargo
CLI_PKG ?= toppy-cli
DOCTOR_ARGS ?= --json
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml

.PHONY: bootstrap fmt clippy test dev doctor compose-up compose-down e2e

bootstrap:
	@if command -v $(CARGO) >/dev/null 2>&1; then \
		echo "OK: cargo found: $$($(CARGO) --version)"; \
		exit 0; \
	fi; \
	echo "ERROR: cargo not found."; \
	echo; \
	echo "Install Rust (stable) via rustup:"; \
	echo "  macOS/Linux:"; \
	echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
	echo "    source $$HOME/.cargo/env"; \
	echo "  Windows:"; \
	echo "    https://rustup.rs/ (download rustup-init.exe)"; \
	echo; \
	echo "Then re-run:"; \
	echo "  make fmt clippy test"; \
	exit 1

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

test:
	$(CARGO) test

dev:
	$(CARGO) run -p $(CLI_PKG)

doctor:
	$(CARGO) run -p $(CLI_PKG) -- doctor $(DOCTOR_ARGS)

compose-up:
	$(COMPOSE) -f $(COMPOSE_FILE) up -d

compose-down:
	$(COMPOSE) -f $(COMPOSE_FILE) down

e2e:
	./scripts/e2e-tcp.sh
