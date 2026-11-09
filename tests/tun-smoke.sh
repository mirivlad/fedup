#!/usr/bin/env bash
# Ephemeral Linux netns lab; does not alter host routes, firewall or DNS.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ "$(id -u)" == 0 ]] || { echo "Use sudo bash tests/tun-smoke.sh" >&2; exit 2; }
for cmd in ip ping openssl python3 curl timeout; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }; done
[[ -c /dev/net/tun ]] || { echo "No /dev/net/tun" >&2; exit 2; }
for binary in fedup-tun fedup-enroll fedup-device fedup-admin; do
  [[ -x "target/debug/$binary" ]] || { echo "Build $binary first" >&2; exit 2; }
done
TUN="$PWD/target/debug/fedup-tun"
ENROLL="$PWD/target/debug/fedup-enroll"
DEVICE="$PWD/target/debug/fedup-device"
ADMIN="$PWD/target/debug/fedup-admin"
umask 077
TMP="$(mktemp -d)"
CN="fuc$$"; SN="fus$$"; CV="vfc$$"; SV="vfs$$"
PIDS=""
cleanup() {
  set +e
  for pid in $PIDS; do kill "$pid" 2>/dev/null; done
  for pid in $PIDS; do wait "$pid" 2>/dev/null; done
  ip netns del "$CN" 2>/dev/null
  ip netns del "$SN" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# Disposable test CA, never use real user/private infrastructure keys.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3 \
  -subj '/CN=FedUp temporary CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$TMP/ca.key" -out "$TMP/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj /CN=localhost -keyout "$TMP/server.key" -out "$TMP/server.csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost' >"$TMP/server.ext"
openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" \
  -set_serial 1009 -days 2 -out "$TMP/server.pem" -extfile "$TMP/server.ext" >/dev/null 2>&1
PASS="fedup-disposable-lab-passphrase-only"
"$ENROLL" init "$TMP/issuer"
"$ENROLL" invite "$TMP/issuer" lab-device 300 "$TMP/ca.pem" localhost "$TMP/invite.json"
printf '%s\n%s\n' "$PASS" "$PASS" | "$DEVICE" request \
  "$TMP/invite.json" "$TMP/identity" "$TMP/request.json" --passphrase-stdin
"$ENROLL" approve "$TMP/issuer" "$TMP/ca.pem" "$TMP/ca.key" \
  "$TMP/request.json" "$TMP/issued.pem" --unsafe-lab-plaintext-ca
printf '%s\n' "$PASS" | "$DEVICE" import "$TMP/identity" "$TMP/issued.pem" --passphrase-stdin
"$ADMIN" init "$TMP/allowed.txt"
"$ADMIN" add "$TMP/allowed.txt" lab-device "$TMP/identity/client.pem"

ip netns add "$CN"; ip netns add "$SN"
ip link add "$CV" type veth peer name "$SV"
ip link set "$CV" netns "$CN"; ip link set "$SV" netns "$SN"
ip -n "$CN" addr add 172.31.44.2/30 dev "$CV"
ip -n "$SN" addr add 172.31.44.1/30 dev "$SV"
ip -n "$CN" link set "$CV" up; ip -n "$SN" link set "$SV" up
ip -n "$CN" link set lo up; ip -n "$SN" link set lo up
if ip -n "$CN" route get 1.1.1.1 >/dev/null 2>&1; then
  echo "FAIL: test namespace has external route" >&2; exit 1
fi

ip netns exec "$SN" "$TUN" server 172.31.44.1:7443 futserver \
  "$TMP/ca.pem" "$TMP/server.pem" "$TMP/server.key" "$TMP/allowed.txt" \
  >"$TMP/server.log" 2>&1 &
PIDS="$PIDS $!"
for i in $(seq 1 80); do
  ip -n "$SN" link show futserver >/dev/null 2>&1 && break
  sleep 0.1
done
if ! ip -n "$SN" link show futserver >/dev/null 2>&1; then
  cat "$TMP/server.log" >&2; exit 1
fi
ip -n "$SN" addr add 10.77.0.1/30 dev futserver
ip -n "$SN" -6 addr add fd42:fed0::1/64 dev futserver

printf '%s\n' "$PASS" | ip netns exec "$CN" "$TUN" client \
  172.31.44.1:7443 futclient "$TMP/identity" --passphrase-stdin \
  >"$TMP/client.log" 2>&1 &
PIDS="$PIDS $!"
for i in $(seq 1 80); do
  ip -n "$CN" link show futclient >/dev/null 2>&1 && break
  sleep 0.1
done
if ! ip -n "$CN" link show futclient >/dev/null 2>&1; then
  cat "$TMP/client.log" "$TMP/server.log" >&2; exit 1
fi
ip -n "$CN" addr add 10.77.0.2/30 dev futclient
ip -n "$CN" -6 addr add fd42:fed0::2/64 dev futclient

timeout 16 ip netns exec "$CN" ping -n -c 3 -W 2 10.77.0.1 >/dev/null
echo "IPv4 ICMP via mTLS TUN: PASS"
timeout 16 ip netns exec "$CN" ping -6 -n -c 2 -W 2 fd42:fed0::1 >/dev/null
echo "IPv6 ICMP via mTLS TUN: PASS"

ip netns exec "$SN" python3 -u - <<'PY' >"$TMP/http.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"fedup-private-lab-okay")
    def log_message(self, *args): pass
HTTPServer(('10.77.0.1',8083), Handler).serve_forever()
PY
PIDS="$PIDS $!"
for i in $(seq 1 40); do
  if ip netns exec "$CN" curl -4 -fsS --noproxy '*' -m 2 \
    http://10.77.0.1:8083/ 2>/dev/null | grep -q 'fedup-private-lab-okay'; then
    break
  fi
  sleep 0.2
done
ip netns exec "$CN" curl -4 -fsS --noproxy '*' -m 5 \
  http://10.77.0.1:8083/ | grep -q 'fedup-private-lab-okay'
echo "TCP HTTP via encrypted IP TUN: PASS"

"$ADMIN" revoke "$TMP/allowed.txt" lab-device
sleep 6
if timeout 4 ip netns exec "$CN" ping -n -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
  echo "FAIL: revoked session still works" >&2; exit 1
fi
if ip -n "$CN" route get 1.1.1.1 >/dev/null 2>&1; then
  echo "FAIL: external bypass route appeared" >&2; exit 1
fi
echo "Revocation and no external-route fallback: PASS"
echo "FedUp Linux TUN namespace lab: PASS"
