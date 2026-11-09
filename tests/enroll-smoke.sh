#!/usr/bin/env bash
# Offline enrollment end-to-end smoke test using disposable LOCAL test keys.
# The plaintext key below is permitted only for this short-lived test fixture.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
ENROLL=target/debug/fedup-enroll
ADMIN=target/debug/fedup-admin
[[ -x "$ENROLL" && -x "$ADMIN" ]] || { echo "Build fedup-enroll and fedup-admin first" >&2; exit 2; }
umask 077
TEMP="$(mktemp -d)"
trap 'rm -rf -- "$TEMP"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3 \
  -subj "/CN=FedUp disposable issuer" -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$TEMP/ca.key" -out "$TEMP/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj "/CN=untrusted-request-CN" -keyout "$TEMP/device.key" \
  -out "$TEMP/device.csr" >/dev/null 2>&1
"$ENROLL" init "$TEMP/issuer-state"
"$ENROLL" invite "$TEMP/issuer-state" family-phone 120 "$TEMP/ca.pem" localhost "$TEMP/invite.json"
"$ENROLL" request "$TEMP/invite.json" "$TEMP/device.csr" "$TEMP/request.json"

# A tampered request must not consume the invitation.
python3 - "$TEMP/request.json" "$TEMP/tampered.json" <<'PY'
import json,sys
req = json.load(open(sys.argv[1]))
req['token'] = "0"*64
with open(sys.argv[2], 'w') as out: json.dump(req,out)
PY
if "$ENROLL" approve "$TEMP/issuer-state" "$TEMP/ca.pem" "$TEMP/ca.key" \
 "$TEMP/tampered.json" "$TEMP/wrong.pem" --unsafe-lab-plaintext-ca >/dev/null 2>&1; then
  echo "SECURITY FAILURE: modified token was accepted" >&2
  exit 1
fi

"$ENROLL" approve "$TEMP/issuer-state" "$TEMP/ca.pem" "$TEMP/ca.key" \
 "$TEMP/request.json" "$TEMP/issued.pem" --unsafe-lab-plaintext-ca
openssl verify -CAfile "$TEMP/ca.pem" -purpose sslclient "$TEMP/issued.pem" | grep -q OK
openssl x509 -in "$TEMP/issued.pem" -noout -text | grep -q "TLS Web Client Authentication"
openssl x509 -in "$TEMP/issued.pem" -noout -text | grep -q "CA:FALSE"

if "$ENROLL" approve "$TEMP/issuer-state" "$TEMP/ca.pem" "$TEMP/ca.key" \
 "$TEMP/request.json" "$TEMP/replayed.pem" --unsafe-lab-plaintext-ca >/dev/null 2>&1; then
  echo "SECURITY FAILURE: invitation replay signed another certificate" >&2
  exit 1
fi
ID="$(python3 - "$TEMP/invite.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['id'])
PY
)"
"$ENROLL" recover "$TEMP/issuer-state" "$ID" "$TEMP/recovered.pem"
cmp "$TEMP/issued.pem" "$TEMP/recovered.pem"

"$ADMIN" init "$TEMP/allowlist.txt"
"$ADMIN" add "$TEMP/allowlist.txt" family-phone "$TEMP/issued.pem"
"$ADMIN" list "$TEMP/allowlist.txt" | grep -q family-phone
"$ADMIN" revoke "$TEMP/allowlist.txt" family-phone
if "$ADMIN" list "$TEMP/allowlist.txt" | grep -q family-phone; then
  echo "SECURITY FAILURE: enrolled certificate was not revoked" >&2
  exit 1
fi

python3 - "$TEMP/invite.json" "$TEMP/expired.json" <<'PY'
import json,sys
inv = json.load(open(sys.argv[1]))
inv["expires_at"] = 1
with open(sys.argv[2], "w") as out: json.dump(inv,out)
PY
if "$ENROLL" request "$TEMP/expired.json" "$TEMP/device.csr" \
 "$TEMP/expired-request.json" >/dev/null 2>&1; then
  echo "SECURITY FAILURE: expired invitation accepted" >&2
  exit 1
fi
[[ "$(stat -c '%a' "$TEMP/issuer-state")" == 700 ]] || exit 1
[[ "$(stat -c '%a' "$TEMP/issuer-state/state.sqlite3")" == 600 ]] || exit 1
[[ "$(stat -c '%a' "$TEMP/invite.json")" == 600 ]] || exit 1
[[ "$(stat -c '%a' "$TEMP/issued.pem")" == 600 ]] || exit 1

echo "FedUp offline enrollment smoke: PASS (CSR, one-time token, CA trust, recovery and revocation)"
