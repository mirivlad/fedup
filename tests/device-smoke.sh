#!/usr/bin/env bash
# Local integration: encrypted client key -> CSR -> offline issuer ->
# certificate import -> mutually authenticated FedUp TCP link.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
DEVICE=target/debug/fedup-device
ENROLL=target/debug/fedup-enroll
ADMIN=target/debug/fedup-admin
LINK=target/debug/fedup-link
for tool in "$DEVICE" "$ENROLL" "$ADMIN" "$LINK"; do
  [[ -x "$tool" ]] || { echo "Missing $tool; build workspace first" >&2; exit 2; }
done
umask 077
TEMP="$(mktemp -d)"
PIDS=""
cleanup() {
  for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
  for pid in $PIDS; do wait "$pid" 2>/dev/null || true; done
  rm -rf -- "$TEMP"
}
trap cleanup EXIT
PASSWORD="test-only-long-random-passphrase-2026"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3 \
  -subj "/CN=FedUp disposable offline CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$TEMP/ca.key" -out "$TEMP/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj /CN=localhost -keyout "$TEMP/server.key" \
  -out "$TEMP/server.csr" >/dev/null 2>&1
cat > "$TEMP/server.ext" <<'X509'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
X509
openssl x509 -req -in "$TEMP/server.csr" -CA "$TEMP/ca.pem" \
  -CAkey "$TEMP/ca.key" -set_serial 1001 -days 2 \
  -out "$TEMP/server.pem" -extfile "$TEMP/server.ext" >/dev/null 2>&1

"$ENROLL" init "$TEMP/issuer"
"$ENROLL" invite "$TEMP/issuer" family-phone 120 "$TEMP/ca.pem" localhost "$TEMP/invite.json"
printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | \
  "$DEVICE" request "$TEMP/invite.json" "$TEMP/device" "$TEMP/request.json" --passphrase-stdin

[[ "$(stat -c '%a' "$TEMP/device")" == 700 ]] || {
  echo "SECURITY FAILURE: device directory must be 0700" >&2; exit 1;
}
[[ "$(stat -c '%a' "$TEMP/device/client-key.enc.pem")" == 600 ]] || {
  echo "SECURITY FAILURE: encrypted key must be 0600" >&2; exit 1;
}
[[ "$(stat -c '%a' "$TEMP/request.json")" == 600 ]] || {
  echo "SECURITY FAILURE: enrollment request must be 0600" >&2; exit 1;
}
grep -q -- 'BEGIN ENCRYPTED PRIVATE KEY' "$TEMP/device/client-key.enc.pem"
if grep -q -- 'BEGIN PRIVATE KEY-----' "$TEMP/device/client-key.enc.pem"; then
  echo "SECURITY FAILURE: unencrypted private key exposed" >&2
  exit 1
fi
if printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | \
  "$DEVICE" request "$TEMP/invite.json" "$TEMP/device" "$TEMP/overwrite.json" \
   --passphrase-stdin >/dev/null 2>&1; then
  echo "SECURITY FAILURE: reused device directory accepted" >&2; exit 1
fi
"$ENROLL" approve "$TEMP/issuer" "$TEMP/ca.pem" "$TEMP/ca.key" \
  "$TEMP/request.json" "$TEMP/issued.pem" --unsafe-lab-plaintext-ca

if printf '%s\n' 'wrong-passphrase-for-test' | "$DEVICE" import \
  "$TEMP/device" "$TEMP/issued.pem" --passphrase-stdin >/dev/null 2>&1; then
  echo "SECURITY FAILURE: wrong key passphrase was accepted" >&2; exit 1
fi
if printf '%s\n' "$PASSWORD" | "$DEVICE" import \
  "$TEMP/device" "$TEMP/server.pem" --passphrase-stdin >/dev/null 2>&1; then
  echo "SECURITY FAILURE: unrelated certificate was accepted" >&2; exit 1
fi
printf '%s\n' "$PASSWORD" | "$DEVICE" import \
  "$TEMP/device" "$TEMP/issued.pem" --passphrase-stdin
cmp <(openssl x509 -in "$TEMP/device/client.pem" -outform DER) <(openssl x509 -in "$TEMP/issued.pem" -outform DER)

"$ADMIN" init "$TEMP/allowed.txt"
"$ADMIN" add "$TEMP/allowed.txt" family-phone "$TEMP/device/client.pem"

get_port() {
  python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1',0))
    print(s.getsockname()[1])
PY
}
ECHO_PORT="$(get_port)"
SERVER_PORT="$(get_port)"
LOCAL_PORT="$(get_port)"
python3 -u - "$ECHO_PORT" <<'PY' >"$TEMP/echo.log" 2>&1 &
import socket, sys, threading
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
server.bind(('127.0.0.1',int(sys.argv[1])))
server.listen(6)
def handle(c):
    with c:
        while part := c.recv(16384):
            c.sendall(part)
while True:
    c,_ = server.accept()
    threading.Thread(target=handle,args=(c,),daemon=True).start()
PY
PIDS="$PIDS $!"
"$LINK" server "127.0.0.1:$SERVER_PORT" "127.0.0.1:$ECHO_PORT" \
  "$TEMP/ca.pem" "$TEMP/server.pem" "$TEMP/server.key" "$TEMP/allowed.txt" \
  >"$TEMP/server.log" 2>&1 &
PIDS="$PIDS $!"
printf '%s\n' "$PASSWORD" | "$LINK" client-device \
  "127.0.0.1:$LOCAL_PORT" "127.0.0.1:$SERVER_PORT" "$TEMP/device" \
  --passphrase-stdin >"$TEMP/client.log" 2>&1 &
PIDS="$PIDS $!"

python3 - "$LOCAL_PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for attempt in range(40):
    try:
        sock=socket.create_connection(('127.0.0.1',port),1)
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("FedUp client listener never started")
body=bytes(range(256))*400
with sock:
    sock.settimeout(15)
    sock.sendall(body)
    sock.shutdown(socket.SHUT_WR)
    incoming=bytearray()
    while data := sock.recv(16384):
        incoming.extend(data)
assert incoming == body, (len(incoming),len(body))
print("Encrypted-key mTLS TCP forwarding: OK; bytes="+str(len(incoming)))
PY
"$ADMIN" revoke "$TEMP/allowed.txt" family-phone
echo "FedUp encrypted identity + offline enrollment + mTLS connection smoke: PASS"
