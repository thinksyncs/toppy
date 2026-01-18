#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${up_pid:-}" ]]; then
    kill "${up_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${tmpdir:-}" ]]; then
    rm -rf "${tmpdir}"
  fi
}

trap cleanup EXIT

tcp_check() {
  local host="$1"
  local port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -zv -w 2 "${host}" "${port}"
    return
  fi
  python - <<'PY' "${host}" "${port}"
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket()
sock.settimeout(2.0)
sock.connect((host, port))
sock.close()
PY
}

wait_for_port() {
  local host="$1"
  local port="$2"
  for _ in {1..300}; do
    if tcp_check "${host}" "${port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "port ${host}:${port} did not open in time" >&2
  return 1
}

pick_free_port() {
  python - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
print(port)
PY
}

tmpdir="$(mktemp -d)"
config_file="${tmpdir}/config.toml"
port_file="${tmpdir}/allowed_port"

python - <<'PY' "${port_file}" &
import socket
import sys

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(port))
sock.listen(10)

while True:
    conn, _addr = sock.accept()
    conn.sendall(b"ok\n")
    conn.close()
PY
server_pid=$!

for _ in {1..50}; do
  if [[ -s "${port_file}" ]]; then
    allowed_port="$(cat "${port_file}")"
    break
  fi
  sleep 0.1
done
if [[ -z "${allowed_port:-}" ]]; then
  echo "failed to determine allowed port" >&2
  exit 1
fi

if [[ "${allowed_port}" -ge 65535 ]]; then
  denied_port="$((allowed_port - 1))"
else
  denied_port="$((allowed_port + 1))"
fi

cat >"${config_file}" <<EOF
gateway = "127.0.0.1"
port = 4433
mtu = 1350

[policy]
  [[policy.allow]]
  cidr = "127.0.0.1/32"
  ports = [${allowed_port}]
EOF

wait_for_port 127.0.0.1 "${allowed_port}"

listen_port="$(pick_free_port)"
denied_listen_port="$(pick_free_port)"
echo "allowed_port=${allowed_port} listen_port=${listen_port} denied_port=${denied_port} denied_listen_port=${denied_listen_port}"

TOPPY_CONFIG="${config_file}" \
  cargo run -q -p toppy-cli -- up --target 127.0.0.1:${allowed_port} --listen 127.0.0.1:${listen_port} &
up_pid=$!

wait_for_port 127.0.0.1 "${listen_port}"
tcp_check 127.0.0.1 "${listen_port}"
python - <<PY
import socket

sock = socket.socket()
sock.settimeout(2.0)
sock.connect(("127.0.0.1", ${listen_port}))
data = sock.recv(16)
sock.close()
if b"ok" not in data:
    raise SystemExit(f"expected ok payload, got {data!r}")
PY

kill "${up_pid}" >/dev/null 2>&1 || true
wait "${up_pid}" 2>/dev/null || true
unset up_pid

set +e
TOPPY_CONFIG="${config_file}" \
  cargo run -q -p toppy-cli -- up --target 127.0.0.1:${denied_port} --listen 127.0.0.1:${denied_listen_port}
denied_status=$?
set -e
if [[ "${denied_status}" -eq 0 ]]; then
  echo "expected policy denial for 127.0.0.1:${denied_port}" >&2
  exit 1
fi

set +e
tcp_check 127.0.0.1 "${denied_listen_port}" >/dev/null 2>&1
denied_connect=$?
set -e
if [[ "${denied_connect}" -eq 0 ]]; then
  echo "expected connection failure on denied port" >&2
  exit 1
fi

doctor_output="$(
  TOPPY_CONFIG="${config_file}" \
  TOPPY_DOCTOR_NET=skip \
  TOPPY_DOCTOR_TUN=pass \
  TOPPY_DOCTOR_TARGET="127.0.0.1:${denied_port}" \
    cargo run -q -p toppy-cli -- doctor --json
)"

if [[ -z "${doctor_output}" ]]; then
  echo "doctor output was empty" >&2
  exit 1
fi
if ! printf '%s' "${doctor_output}" | grep -q '^[[:space:]]*{'; then
  echo "doctor output was not valid JSON:" >&2
  printf '%s\n' "${doctor_output}" >&2
  exit 1
fi

printf '%s' "${doctor_output}" | python -c "import json,sys
data = json.load(sys.stdin)
checks = {item.get('id'): item for item in data.get('checks', [])}
check = checks.get('policy.denied')
if not check:
    raise SystemExit('missing policy.denied check')
if check.get('status') != 'fail':
    raise SystemExit(f\"expected policy.denied fail, got {check.get('status')}\")
summary = check.get('summary', '')
if 'not allowed' not in summary:
    raise SystemExit(f\"expected denial reason, got {summary}\")"
