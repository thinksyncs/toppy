#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  docker compose down -v
}

trap cleanup EXIT

docker compose up -d --build

service="toppy-gw"
container_id="$(docker compose ps -q "$service")"
if [[ -z "$container_id" ]]; then
  echo "no container id for ${service}" >&2
  docker compose ps
  docker compose logs --no-color || true
  exit 1
fi

ready=0
for _ in {1..60}; do
  status="$(docker inspect -f '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
  if [[ "$status" == "exited" ]]; then
    echo "${service} exited before healthz became ready" >&2
    docker compose ps
    docker compose logs --no-color || true
    exit 1
  fi
  if curl -fsS http://127.0.0.1:8080/healthz >/dev/null; then
    ready=1
    break
  fi
  sleep 2
done

if [[ "$ready" -ne 1 ]]; then
  echo "healthz did not become healthy" >&2
  docker compose ps
  docker compose logs --no-color || true
  exit 1
fi

config_file="$(mktemp)"
cert_path="$(pwd)/crates/toppy-gw/testdata/localhost-cert.pem"
auth_token="dev-token"
cat >"$config_file" <<EOF
gateway = "127.0.0.1"
port = 4433
server_name = "localhost"
ca_cert_path = "${cert_path}"
auth_token = "${auth_token}"
mtu = 1350
EOF

output="$(TOPPY_CONFIG="$config_file" TOPPY_DOCTOR_TUN=pass cargo run -p toppy-cli -- doctor --json)"
rm -f "$config_file"

printf '%s' "$output" | python -c $'import json,sys\n\ndata = json.load(sys.stdin)\noverall = data.get(\"overall\")\nif overall != \"pass\":\n    raise SystemExit(f\"expected overall pass, got {overall}\")\n\nchecks = {c[\"id\"]: c for c in data.get(\"checks\", [])}\nfor required in (\"cfg.load\", \"net.dns\", \"h3.connect\", \"tun.perm\", \"mtu.sanity\"):\n    if required not in checks:\n        raise SystemExit(f\"missing check: {required}\")\n\ndns_status = checks[\"net.dns\"][\"status\"]\nif dns_status != \"pass\":\n    raise SystemExit(f\"net.dns status: {dns_status}\")\nh3_status = checks[\"h3.connect\"][\"status\"]\nif h3_status != \"pass\":\n    raise SystemExit(f\"h3.connect status: {h3_status}\")\ntun_status = checks[\"tun.perm\"][\"status\"]\nif tun_status not in (\"pass\", \"warn\"):\n    raise SystemExit(f\"tun.perm status: {tun_status}\")\nmtu_status = checks[\"mtu.sanity\"][\"status\"]\nif mtu_status != \"pass\":\n    raise SystemExit(f\"mtu.sanity status: {mtu_status}\")\n'
