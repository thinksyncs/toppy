#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  docker compose down -v
}

trap cleanup EXIT

docker compose up -d --build

ready=0
for _ in {1..30}; do
  if curl -fsS http://localhost:8080/healthz >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "healthz did not become healthy" >&2
  docker compose ps
  exit 1
fi

config_file="$(mktemp)"
cat >"$config_file" <<EOF
gateway = "127.0.0.1"
port = 4433
EOF

output="$(TOPPY_CONFIG="$config_file" cargo run -p toppy-cli -- doctor --json)"
rm -f "$config_file"

printf '%s' "$output" | python - <<'PY'
import json
import sys

data = json.load(sys.stdin)
if data.get("overall") != "pass":
    raise SystemExit(f"expected overall pass, got {data.get('overall')}")

checks = {c["id"]: c for c in data.get("checks", [])}
for required in ("cfg.load", "net.dns", "h3.connect"):
    if required not in checks:
        raise SystemExit(f"missing check: {required}")

if checks["net.dns"]["status"] != "pass":
    raise SystemExit(f"net.dns status: {checks['net.dns']['status']}")
if checks["h3.connect"]["status"] != "pass":
    raise SystemExit(f"h3.connect status: {checks['h3.connect']['status']}")
PY
