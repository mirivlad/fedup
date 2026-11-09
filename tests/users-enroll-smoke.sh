#!/usr/bin/env bash
# Never touch real accounts, network interfaces or CA material.
# This is an UNSAFE-ONLINE-CA laboratory to verify automatic device issuance.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
USERS="$PWD/target/debug/fedup-users"
AUTH="$PWD/target/debug/fedup-auth"
umask 077
TMP="$(mktemp -d)"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
"$USERS" init "$TMP/users"
SECRET="test-only-enrollment-passphrase-123"
printf '%s\n' "$SECRET" | "$USERS" add "$TMP/users" family --password-stdin

# Disposable P-256 CA. This key MUST NEVER be used on a real server.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/ca.key"
openssl req -new -x509 -sha256 -days 10 -key "$TMP/ca.key" \
  -subj "/CN=Disposable FedUp CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$TMP/ca.pem"
openssl ecparam -genkey -name prime256v1 -noout -out "$TMP/phone.key"
openssl req -new -sha256 -key "$TMP/phone.key" \
  -subj '/CN=fedup-android-test' -out "$TMP/phone.csr"

PORT="$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
PY
)"
"$AUTH" serve-enroll-lab "$TMP/users" "$PORT" "$TMP/ca.pem" "$TMP/ca.key" \
  localhost --unsafe-lab-online-ca >"$TMP/auth.log" 2>&1 &
PID="$!"
for _ in $(seq 1 50); do
  if curl -s --max-time 1 "http://127.0.0.1:$PORT/api/fedup/v1/config" \
    > "$TMP/config.json" 2>/dev/null && [[ -s "$TMP/config.json" ]]; then break; fi
  sleep 0.1
done
if [[ ! -s "$TMP/config.json" ]]; then
  cat "$TMP/auth.log" >&2
  exit 1
fi

python3 - "$PORT" "$TMP" <<'PY'
import json, pathlib, sys, urllib.request, urllib.error
port=int(sys.argv[1]); root=pathlib.Path(sys.argv[2])
base=f"http://127.0.0.1:{port}/api/fedup/v1"
config=json.loads((root/"config.json").read_text())
assert config["server_name"]=="localhost"
assert len(config["ca_sha256"])==64
assert "BEGIN CERTIFICATE" in config["ca_pem"]
csr=(root/"phone.csr").read_text()
body={"username":"family","password":"test-only-enrollment-passphrase-123",
      "device":"android-test","csr_pem":csr}
def send(payload):
    req=urllib.request.Request(base+"/devices",data=json.dumps(payload).encode(),
                               headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code,e.read()
status, data=send(body)
assert status==201, (status,data)
issued=json.loads(data)
assert issued["ca_sha256"]==config["ca_sha256"]
assert issued["server_name"]=="localhost"
assert len(issued["fingerprint_sha256"])==64
assert "BEGIN CERTIFICATE" in issued["certificate_pem"]
(root/"issued.pem").write_text(issued["certificate_pem"])
(root/"fingerprint").write_text(issued["fingerprint_sha256"])
status, same=send(body)
assert status==201 and json.loads(same)["certificate_pem"]==issued["certificate_pem"],status
bad=dict(body,password="totally-wrong-password")
assert send(bad)[0]==401
different=dict(body,csr_pem=csr.replace("CERTIFICATE REQUEST","CERTIFICATE").replace("-----BEGIN","-----START"))
assert send(different)[0] in (400,409)
print("HTTPS edge adapter: CA metadata, authenticated issue, stable retry, bad password denial: PASS")
PY
openssl verify -CAfile "$TMP/ca.pem" "$TMP/issued.pem"
openssl x509 -in "$TMP/issued.pem" -noout -text |
  grep -q 'TLS Web Client Authentication'
FP="$(cat "$TMP/fingerprint")"
"$USERS" check-device "$TMP/users" "$FP"
"$USERS" devices "$TMP/users" family | grep -F "$FP"
"$USERS" disable "$TMP/users" family
if "$USERS" check-device "$TMP/users" "$FP" >/dev/null 2>&1; then
  echo "FAIL: disabled account remains authorized" >&2
  exit 1
fi
"$USERS" enable "$TMP/users" family
if "$USERS" check-device "$TMP/users" "$FP" >/dev/null 2>&1; then
  echo "FAIL: enabling account restored an old device" >&2
  exit 1
fi
echo "FedUp account-bound automatic CSR issue + idempotency + revocation: PASS"
