SHELL := /bin/bash

CARGO ?= cargo
CLI_PKG ?= toppy-cli
DOCTOR_ARGS ?= --json
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml

.PHONY: fmt clippy test dev doctor compose-up compose-down e2e

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
