#!/usr/bin/env bash
# End-to-end integration tests for a one-destination TCP link.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
LINK=target/debug/fedup-link
ADMIN=target/debug/fedup-admin
[[ -x "$LINK" && -x "$ADMIN" ]] || { echo "Build first: cargo build -p fedup-link -p fedup-admin" >&2; exit 2; }
umask 077
TEMP="$(mktemp -d)"
PIDS=""
cleanup() {
  for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
  for pid in $PIDS; do wait "$pid" 2>/dev/null || true; done
  rm -rf -- "$TEMP"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -noenc -days 1 \
  -subj '/CN=FedUp disposable test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$TEMP/ca.key" -out "$TEMP/ca.pem" >/dev/null 2>&1
cat > "$TEMP/server.ext" <<'X509'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
X509
cat > "$TEMP/client.ext" <<'X509'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
X509
for label in server client unauthorized; do
  name="$label"
  [[ "$label" == server ]] && name=localhost
  openssl req -new -newkey rsa:2048 -noenc -subj "/CN=$name" \
    -keyout "$TEMP/$label.key" -out "$TEMP/$label.csr" >/dev/null 2>&1
  ext=client
  [[ "$label" == server ]] && ext=server
  case "$label" in
    server) serial=1101 ;;
    client) serial=1102 ;;
    unauthorized) serial=1103 ;;
  esac
  openssl x509 -req -in "$TEMP/$label.csr" -CA "$TEMP/ca.pem" -CAkey "$TEMP/ca.key" \
    -set_serial "$serial" -days 1 -out "$TEMP/$label.pem" \
    -extfile "$TEMP/$ext.ext" >/dev/null 2>&1
done
"$ADMIN" init "$TEMP/allowed.txt"
"$ADMIN" add "$TEMP/allowed.txt" family-phone "$TEMP/client.pem"
"$ADMIN" list "$TEMP/allowed.txt" | grep -q 'family-phone'
[[ "$(stat -c '%a' "$TEMP/allowed.txt")" == "600" ]] || {
  echo 'SECURITY FAILURE: allowlist permissions are too broad' >&2
  exit 1
}
get_port() {
  python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    print(s.getsockname()[1])
PY
}
TARGET_PORT="$(get_port)"
SERVER_PORT="$(get_port)"
CLIENT_PORT="$(get_port)"
DENY_PORT="$(get_port)"
python3 -u - "$TARGET_PORT" <<'PY' >"$TEMP/echo.log" 2>&1 &
import socket, sys, threading
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(sys.argv[1])))
sock.listen(8)
def worker(peer):
    with peer:
        while True:
            data = peer.recv(8192)
            if not data: return
            peer.sendall(data)
while True:
    peer, _ = sock.accept()
    threading.Thread(target=worker, args=(peer,), daemon=True).start()
PY
PIDS="$PIDS $!"
if "$LINK" server "0.0.0.0:$SERVER_PORT" "127.0.0.1:$TARGET_PORT" \
  "$TEMP/ca.pem" "$TEMP/server.pem" "$TEMP/server.key" "$TEMP/allowed.txt" \
  >"$TEMP/unsafe.log" 2>&1; then
  echo 'SECURITY FAILURE: server allowed public bind without an explicit flag' >&2
  exit 1
fi
"$LINK" server "127.0.0.1:$SERVER_PORT" "127.0.0.1:$TARGET_PORT" \
  "$TEMP/ca.pem" "$TEMP/server.pem" "$TEMP/server.key" "$TEMP/allowed.txt" \
  >"$TEMP/server.log" 2>&1 &
PIDS="$PIDS $!"
"$LINK" client "127.0.0.1:$CLIENT_PORT" "127.0.0.1:$SERVER_PORT" localhost \
  "$TEMP/ca.pem" "$TEMP/client.pem" "$TEMP/client.key" \
  >"$TEMP/client.log" 2>&1 &
PIDS="$PIDS $!"
"$LINK" client "127.0.0.1:$DENY_PORT" "127.0.0.1:$SERVER_PORT" localhost \
  "$TEMP/ca.pem" "$TEMP/unauthorized.pem" "$TEMP/unauthorized.key" \
  >"$TEMP/unauthorized.log" 2>&1 &
PIDS="$PIDS $!"
sleep 0.8
python3 - "$CLIENT_PORT" "$DENY_PORT" "$TEMP/revocation-ready" <<'PY'
import socket, sys
from pathlib import Path
good, bad, ready = int(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
body = bytes(range(256)) * 300
with socket.create_connection(("127.0.0.1", good), 5) as s:
    s.settimeout(15)
    s.sendall(body)
    s.shutdown(socket.SHUT_WR)
    answer = bytearray()
    while part := s.recv(16384):
        answer.extend(part)
    assert answer == body, f"roundtrip mismatch: {len(answer)} bytes"
print(f"TCP link: verified {len(body)} binary bytes in both directions")
with socket.create_connection(("127.0.0.1", bad), 5) as s:
    s.settimeout(10)
    s.sendall(b"unauthorized")
    s.shutdown(socket.SHUT_WR)
    try: result = s.recv(32)
    except (ConnectionResetError, BrokenPipeError, OSError): result = b""
    assert not result, "unlisted identity exchanged data"
print("Unauthorized certificate: rejected")
PY
# A persistent session must be terminated after revocation.
python3 - "$CLIENT_PORT" "$TEMP/revocation-ready" <<'PY' >"$TEMP/revocation.log" 2>&1 &
import socket, sys
from pathlib import Path
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5) as s:
    s.settimeout(15)
    s.sendall(b"still-here")
    assert s.recv(32) == b"still-here"
    Path(sys.argv[2]).touch()
    try: data = s.recv(1)
    except (ConnectionResetError, BrokenPipeError): data = b""
    assert not data, "established TCP stream outlived revocation"
print("Active session: disconnected after revocation")
PY
REVOKE_PID=$!
PIDS="$PIDS $REVOKE_PID"
for i in $(seq 1 50); do
  [[ -f "$TEMP/revocation-ready" ]] && break
  sleep 0.1
done
[[ -f "$TEMP/revocation-ready" ]] || { echo 'Failed to establish revocation test' >&2; exit 1; }
"$ADMIN" revoke "$TEMP/allowed.txt" family-phone
if "$ADMIN" list "$TEMP/allowed.txt" | grep -q 'family-phone'; then
  echo 'SECURITY FAILURE: revoked identity still listed' >&2
  exit 1
fi
wait "$REVOKE_PID"
cat "$TEMP/revocation.log"
python3 - "$CLIENT_PORT" <<'PY'
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5) as s:
    s.settimeout(10)
    s.sendall(b"revoked")
    s.shutdown(socket.SHUT_WR)
    try: data = s.recv(32)
    except (ConnectionResetError, BrokenPipeError, OSError): data = b""
    assert not data, "revoked client exchanged data"
print("Revoked identity: new session denied")
PY
# A second temporary allowlist exercises named inventory and selective revocation.
"$ADMIN" init "$TEMP/extra-allowlist.txt"
"$ADMIN" add "$TEMP/extra-allowlist.txt" family-phone "$TEMP/client.pem"
"$ADMIN" add "$TEMP/extra-allowlist.txt" family-laptop "$TEMP/unauthorized.pem"
if "$ADMIN" add "$TEMP/extra-allowlist.txt" family-phone "$TEMP/unauthorized.pem" >/dev/null 2>&1; then
  echo 'SECURITY FAILURE: duplicate device name was accepted' >&2
  exit 1
fi
"$ADMIN" revoke "$TEMP/extra-allowlist.txt" "$("$ADMIN" fingerprint "$TEMP/client.pem")"
"$ADMIN" list "$TEMP/extra-allowlist.txt" | grep -q 'family-laptop'
if "$ADMIN" list "$TEMP/extra-allowlist.txt" | grep -q 'family-phone'; then
  echo 'SECURITY FAILURE: revoked device still exists in inventory' >&2
  exit 1
fi
echo "FedUp experimental TCP link + admin smoke test: PASS"
