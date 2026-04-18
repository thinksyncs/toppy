#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run scripts/it-compose.sh" >&2
  exit 127
fi

cleanup() {
  if [[ "${udp_pid:-}" != "" ]]; then
    kill "$udp_pid" 2>/dev/null || true
    wait "$udp_pid" 2>/dev/null || true
  fi
  if [[ "${audit_server_pid:-}" != "" ]]; then
    kill "$audit_server_pid" 2>/dev/null || true
    wait "$audit_server_pid" 2>/dev/null || true
  fi
  if [[ "${audit_tmp_dir:-}" != "" ]]; then
    rm -rf "$audit_tmp_dir"
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
audit_log="$(mktemp)"
audit_tmp_dir="$(mktemp -d)"
audit_requests="${audit_tmp_dir}/requests.jsonl"
audit_port_file="${audit_tmp_dir}/port"
python3 -u - "$audit_tmp_dir" <<'PY' >/tmp/toppy-audit-mock.log 2>&1 &
import http.server
import json
import pathlib
import socketserver
import sys

state_dir = pathlib.Path(sys.argv[1])
port_file = state_dir / "port"
requests_path = state_dir / "requests.jsonl"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        record = {
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": raw.decode("utf-8"),
        }
        with requests_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record))
            handle.write("\n")
        if self.path == "/verify":
            payload = {"verified": True, "message": "remote verified"}
        else:
            payload = {"ok": True}
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


with ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
    port_file.write_text(str(server.server_address[1]), encoding="utf-8")
    server.serve_forever()
PY
audit_server_pid=$!
for _ in {1..40}; do
  if [[ -s "$audit_port_file" ]]; then
    break
  fi
  sleep 0.25
done
if [[ ! -s "$audit_port_file" ]]; then
  echo "audit mock server did not start" >&2
  cat /tmp/toppy-audit-mock.log >&2 || true
  exit 1
fi
audit_port="$(cat "$audit_port_file")"
audit_ship_url="http://127.0.0.1:${audit_port}/ship"
audit_verify_url="http://127.0.0.1:${audit_port}/verify"
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

output="$(
  TOPPY_CONFIG="$config_file" \
  TOPPY_AUDIT_LOG_PATH="$audit_log" \
  TOPPY_DOCTOR_TUN=pass \
  TOPPY_DOCTOR_NET=pass \
  cargo run -p toppy-cli -- doctor --json
)"
TOPPY_CONFIG="$config_file" TOPPY_AUDIT_LOG_PATH="$audit_log" cargo run -p toppy-cli -- udp --listen 127.0.0.1:19000 --target "${echo_ip}:9999" >/tmp/toppy-udp-proxy.log 2>&1 &
udp_pid=$!

for _ in {1..40}; do
  if grep -q "toppy udp listening" /tmp/toppy-udp-proxy.log 2>/dev/null; then
    break
  fi
  sleep 0.25
done

python3 - <<'PY'
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
udp_pid=""

printf '%s' "$output" | python3 -c $'import json,sys\n\ndata = json.load(sys.stdin)\noverall = data.get(\"overall\")\nif overall != \"pass\":\n    raise SystemExit(f\"expected overall pass, got {overall}\")\n\nchecks = {c[\"id\"]: c for c in data.get(\"checks\", [])}\nfor required in (\"cfg.load\", \"net.dns\", \"h3.connect\", \"tun.perm\", \"mtu.sanity\"):\n    if required not in checks:\n        raise SystemExit(f\"missing check: {required}\")\n\ndns_status = checks[\"net.dns\"][\"status\"]\nif dns_status != \"pass\":\n    raise SystemExit(f\"net.dns status: {dns_status}\")\nh3_status = checks[\"h3.connect\"][\"status\"]\nif h3_status != \"pass\":\n    raise SystemExit(f\"h3.connect status: {h3_status}\")\ntun_status = checks[\"tun.perm\"][\"status\"]\nif tun_status not in (\"pass\", \"warn\"):\n    raise SystemExit(f\"tun.perm status: {tun_status}\")\nmtu_status = checks[\"mtu.sanity\"][\"status\"]\nif mtu_status != \"pass\":\n    raise SystemExit(f\"mtu.sanity status: {mtu_status}\")\n'

printf '%s' "$output" | python3 -c $'import json,sys\n\ndata = json.load(sys.stdin)\nchecks = {c[\"id\"]: c for c in data.get(\"checks\", [])}\nfor required in (\"masque.connect_udp\", \"masque.connect_udp.datagram\"):\n    if required not in checks:\n        raise SystemExit(f\"missing check: {required}\")\n\nhandshake = checks[\"masque.connect_udp\"][\"status\"]\nif handshake != \"pass\":\n    raise SystemExit(f\"masque.connect_udp status: {handshake}\")\necho = checks[\"masque.connect_udp.datagram\"][\"status\"]\nif echo != \"pass\":\n    raise SystemExit(f\"masque.connect_udp.datagram status: {echo}\")\n'

TOPPY_AUDIT_LOG_PATH="$audit_log" cargo run -p toppy-cli -- audit verify --path "$audit_log"
TOPPY_AUDIT_LOG_PATH="$audit_log" TOPPY_AUDIT_SHIP_URL="$audit_ship_url" TOPPY_AUDIT_SHIP_TOKEN="ship-token" TOPPY_AUDIT_SHIP_BATCH_SIZE=1 cargo run -p toppy-cli -- audit ship --path "$audit_log"
TOPPY_AUDIT_LOG_PATH="$audit_log" TOPPY_AUDIT_VERIFY_URL="$audit_verify_url" TOPPY_AUDIT_VERIFY_TOKEN="verify-token" cargo run -p toppy-cli -- audit remote-verify --path "$audit_log"

python3 - <<'PY' "$audit_requests"
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    requests = [json.loads(line) for line in handle if line.strip()]

ship = [req for req in requests if req["path"] == "/ship"]
verify = [req for req in requests if req["path"] == "/verify"]
if not ship:
    raise SystemExit("missing /ship requests")
if len(verify) != 1:
    raise SystemExit(f"expected 1 /verify request, got {len(verify)}")
if not all(req["authorization"] == "Bearer ship-token" for req in ship):
    raise SystemExit("ship requests missing bearer token")
if verify[0]["authorization"] != "Bearer verify-token":
    raise SystemExit("verify request missing bearer token")

for req in ship:
    body = json.loads(req["body"])
    if not isinstance(body, list) or not body:
        raise SystemExit("ship payload was not a non-empty JSON array")

verify_body = json.loads(verify[0]["body"])
if not isinstance(verify_body, list) or not verify_body:
    raise SystemExit("verify payload was not a non-empty JSON array")
if not any(entry.get("event", {}).get("action") == "doctor" for entry in verify_body):
    raise SystemExit("verify payload missing doctor audit entry")
PY

rm -f "$config_file" "$audit_log" /tmp/toppy-udp-proxy.log /tmp/toppy-audit-mock.log
