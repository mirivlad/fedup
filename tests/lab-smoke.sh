#!/usr/bin/env bash
# One-shot test CA and mTLS handshake; NEVER deploy any of these credentials.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
LAB=target/debug/fedup-lab
if [[ ! -x "$LAB" ]]; then
  echo "Build first: cargo build -p fedup-lab" >&2
  exit 2
fi
umask 077
TEMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
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
for cert in server client; do
  name="$cert"
  [[ "$cert" == server ]] && name=localhost
  openssl req -new -newkey rsa:2048 -noenc -subj "/CN=$name" \
    -keyout "$TEMP/$cert.key" -out "$TEMP/$cert.csr" >/dev/null 2>&1
  if [[ "$cert" == server ]]; then serial=1001; else serial=1002; fi
  openssl x509 -req -in "$TEMP/$cert.csr" -CA "$TEMP/ca.pem" -CAkey "$TEMP/ca.key" \
    -set_serial "$serial" -days 1 -out "$TEMP/$cert.pem" \
    -extfile "$TEMP/$cert.ext" >/dev/null 2>&1
done

PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1', 0))
print(s.getsockname()[1]); s.close()
PY
)"
ADDR="127.0.0.1:$PORT"

"$LAB" server "$ADDR" "$TEMP/ca.pem" "$TEMP/server.pem" "$TEMP/server.key" \
  >"$TEMP/server.log" 2>&1 & SERVER_PID=$!
sleep 0.4
"$LAB" client "$ADDR" localhost "$TEMP/ca.pem" "$TEMP/client.pem" "$TEMP/client.key"
wait "$SERVER_PID"
SERVER_PID=""
grep -q 'authenticated laboratory ping completed' "$TEMP/server.log"

# Wrong server identity must be rejected even with a valid trust anchor.
"$LAB" server "$ADDR" "$TEMP/ca.pem" "$TEMP/server.pem" "$TEMP/server.key" \
  >"$TEMP/reject.log" 2>&1 & SERVER_PID=$!
sleep 0.4
if "$LAB" client "$ADDR" not-localhost "$TEMP/ca.pem" "$TEMP/client.pem" "$TEMP/client.key" \
  >"$TEMP/rejected-client.log" 2>&1; then
  echo 'SECURITY FAILURE: client accepted a certificate for the wrong hostname' >&2
  exit 1
fi
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo 'FedUp laboratory mTLS smoke test: PASS (positive exchange and wrong-hostname rejection)'
