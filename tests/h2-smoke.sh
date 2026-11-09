#!/usr/bin/env bash
# Real HTTP/2 ALPN + request/response DATA framing, disposable loopback mTLS.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
H2="$PWD/target/debug/fedup-h2-lab"
DEVICE="$PWD/target/debug/fedup-device"
ENROLL="$PWD/target/debug/fedup-enroll"
ADMIN="$PWD/target/debug/fedup-admin"
for tool in "$H2" "$DEVICE" "$ENROLL" "$ADMIN"; do
  [[ -x "$tool" ]] || { echo "Missing binary $tool" >&2; exit 2; }
done
umask 077
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || { kill "$SERVER_PID" 2>/dev/null || :; wait "$SERVER_PID" 2>/dev/null || :; }
  rm -rf "$TMP"
}
trap cleanup EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3 \
  -subj '/CN=FedUp temporary research CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$TMP/ca.key" -out "$TMP/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj '/CN=localhost' -keyout "$TMP/server.key" -out "$TMP/server.csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost' >"$TMP/server.ext"
openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" \
  -set_serial 2081 -days 2 -out "$TMP/server.pem" -extfile "$TMP/server.ext" >/dev/null 2>&1
PASS="lab-only-passphrase-2026-not-for-real-use"
"$ENROLL" init "$TMP/issuer"
"$ENROLL" invite "$TMP/issuer" lab-h2-device 300 "$TMP/ca.pem" localhost "$TMP/invite.json"
printf '%s\n%s\n' "$PASS" "$PASS" | \
  "$DEVICE" request "$TMP/invite.json" "$TMP/identity" "$TMP/request.json" --passphrase-stdin
"$ENROLL" approve "$TMP/issuer" "$TMP/ca.pem" "$TMP/ca.key" \
  "$TMP/request.json" "$TMP/issued.pem" --unsafe-lab-plaintext-ca
printf '%s\n' "$PASS" | \
  "$DEVICE" import "$TMP/identity" "$TMP/issued.pem" --passphrase-stdin
"$ADMIN" init "$TMP/allowed.txt"
"$ADMIN" add "$TMP/allowed.txt" lab-h2-device "$TMP/identity/client.pem"

PORT="$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1',0))
    print(s.getsockname()[1])
PY
)"
"$H2" server "127.0.0.1:$PORT" "$TMP/ca.pem" "$TMP/server.pem" \
  "$TMP/server.key" "$TMP/allowed.txt" >"$TMP/server.log" 2>&1 &
SERVER_PID="$!"
sleep 0.5

# > 64 KiB to exercise real bidirectional HTTP/2 flow control and WINDOW_UPDATE.
if ! printf '%s\n' "$PASS" | timeout 35 "$H2" client "127.0.0.1:$PORT" \
  "$TMP/identity" 196608 --passphrase-stdin; then
  cat "$TMP/server.log" >&2
  echo 'HTTP/2 mTLS streaming failed' >&2
  exit 1
fi

# Unauthorized identity must not be accepted after revoke, even with valid CA.
"$ADMIN" revoke "$TMP/allowed.txt" lab-h2-device
if printf '%s\n' "$PASS" | timeout 12 "$H2" client "127.0.0.1:$PORT" \
  "$TMP/identity" 1024 --passphrase-stdin >"$TMP/rejected.log" 2>&1; then
  echo "SECURITY FAILURE: revoked client established new h2 stream" >&2
  exit 1
fi
echo "HTTP/2 ALPN, 196608-byte data streaming, and certificate revocation: PASS"
