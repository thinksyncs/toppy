#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [[ "${udp_pid:-}" != "" ]]; then
    kill "$udp_pid" 2>/dev/null || true
    wait "$udp_pid" 2>/dev/null || true
  fi
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

echo_service="udp-echo"
echo_container_id="$(docker compose ps -q "$echo_service")"
if [[ -z "$echo_container_id" ]]; then
  echo "no container id for ${echo_service}" >&2
  docker compose ps
  docker compose logs --no-color || true
  exit 1
fi

echo_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$echo_container_id" 2>/dev/null || true)"
if [[ -z "$echo_ip" ]]; then
  echo "failed to discover udp-echo container IP" >&2
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

[policy]
allow = [
  { cidr = "${echo_ip}/32", ports = [9999] },
]
EOF

output="$(TOPPY_CONFIG="$config_file" TOPPY_DOCTOR_TUN=pass TOPPY_DOCTOR_NET=pass cargo run -p toppy-cli -- doctor --json)"
TOPPY_CONFIG="$config_file" cargo run -p toppy-cli -- udp --listen 127.0.0.1:19000 --target "${echo_ip}:9999" >/tmp/toppy-udp-proxy.log 2>&1 &
udp_pid=$!

for _ in {1..40}; do
  if grep -q "toppy udp listening" /tmp/toppy-udp-proxy.log 2>/dev/null; then
    break
  fi
  sleep 0.25
done

python - <<'PY'
import socket

addr = ("127.0.0.1", 19000)
msg = b"toppy-udp-proxy-it"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(msg, addr)
data, _ = s.recvfrom(65535)
if data != msg:
    raise SystemExit(f"udp proxy mismatch: {data!r}")
print("udp proxy ok")
PY

kill "$udp_pid" 2>/dev/null || true
wait "$udp_pid" 2>/dev/null || true
rm -f "$config_file" /tmp/toppy-udp-proxy.log

printf '%s' "$output" | python -c $'import json,sys\n\ndata = json.load(sys.stdin)\noverall = data.get(\"overall\")\nif overall != \"pass\":\n    raise SystemExit(f\"expected overall pass, got {overall}\")\n\nchecks = {c[\"id\"]: c for c in data.get(\"checks\", [])}\nfor required in (\"cfg.load\", \"net.dns\", \"h3.connect\", \"tun.perm\", \"mtu.sanity\"):\n    if required not in checks:\n        raise SystemExit(f\"missing check: {required}\")\n\ndns_status = checks[\"net.dns\"][\"status\"]\nif dns_status != \"pass\":\n    raise SystemExit(f\"net.dns status: {dns_status}\")\nh3_status = checks[\"h3.connect\"][\"status\"]\nif h3_status != \"pass\":\n    raise SystemExit(f\"h3.connect status: {h3_status}\")\ntun_status = checks[\"tun.perm\"][\"status\"]\nif tun_status not in (\"pass\", \"warn\"):\n    raise SystemExit(f\"tun.perm status: {tun_status}\")\nmtu_status = checks[\"mtu.sanity\"][\"status\"]\nif mtu_status != \"pass\":\n    raise SystemExit(f\"mtu.sanity status: {mtu_status}\")\n'\
\
printf '%s' "$output" | python -c $'import json,sys\n\ndata = json.load(sys.stdin)\nchecks = {c[\"id\"]: c for c in data.get(\"checks\", [])}\nfor required in (\"masque.connect_udp\", \"masque.connect_udp.datagram\"):\n    if required not in checks:\n        raise SystemExit(f\"missing check: {required}\")\n\nhandshake = checks[\"masque.connect_udp\"][\"status\"]\nif handshake != \"pass\":\n    raise SystemExit(f\"masque.connect_udp status: {handshake}\")\necho = checks[\"masque.connect_udp.datagram\"][\"status\"]\nif echo != \"pass\":\n    raise SystemExit(f\"masque.connect_udp.datagram status: {echo}\")\n'
