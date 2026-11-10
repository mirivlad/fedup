#!/usr/bin/env bash
# Disposable real HTTP/2 account-authenticated IPv4 gateway + NAT smoke.
# All networking changes are confined to temporary Linux namespaces.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ "$(id -u)" == 0 ]] || { echo "root required" >&2; exit 2; }
for cmd in ip nft curl python3 openssl ping sysctl timeout nghttp; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun unavailable" >&2; exit 2; }
for name in fedup-tun fedup-users fedup-auth fedup-device fedup-enroll; do
  [[ -x "target/debug/$name" ]] || { echo "build $name first" >&2; exit 2; }
done
umask 077
ROOT="$PWD"
TUN="$ROOT/target/debug/fedup-tun"
AUTH_MODE="${FEDUP_VPS_AUTH_MODE:-mtls}"
case "$AUTH_MODE" in
  mtls) SERVER_CMD=server-vps-v4; CLIENT_CMD=client-vps-v4; PROBE_CMD="" ;;
  proof) SERVER_CMD=server-vps-proof-v4; CLIENT_CMD=client-vps-proof-v4; PROBE_CMD=probe-vps-proof ;;
  edge) SERVER_CMD=server-vps-proof-h2c; CLIENT_CMD=client-vps-proof-v4; PROBE_CMD=probe-vps-proof ;;
  *) echo "unknown FEDUP_VPS_AUTH_MODE: $AUTH_MODE" >&2; exit 2 ;;
esac
USERS="$ROOT/target/debug/fedup-users"
AUTH="$ROOT/target/debug/fedup-auth"
DEVICE="$ROOT/target/debug/fedup-device"
ENROLL="$ROOT/target/debug/fedup-enroll"
TMP="$(mktemp -d)"
SN="fvs$BASHPID"; CN="fvc$BASHPID"; EN="fve$BASHPID"
CV="vcc$BASHPID"; SV="vss$BASHPID"; SW="vsw$BASHPID"; EW="vew$BASHPID"
PIDS=""
cleanup() {
  set +e
  for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
  for pid in $PIDS; do wait "$pid" 2>/dev/null || true; done
  ip netns del "$CN" 2>/dev/null || true
  ip netns del "$SN" 2>/dev/null || true
  ip netns del "$EN" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
# Short-lived, throwaway root cert, never a real-world signing key.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3 \
  -subj '/CN=Disposable FedUp IPv4 Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$TMP/ca.key" -out "$TMP/ca.pem" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj '/CN=localhost' -keyout "$TMP/server.key" \
  -out "$TMP/server.csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:localhost' >"$TMP/server.ext"
openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" \
  -set_serial 10029 -days 2 -out "$TMP/server.pem" \
  -extfile "$TMP/server.ext" >/dev/null 2>&1

"$USERS" init "$TMP/users"
PASS="fedup-disposable-long-passphrase"
printf '%s\n' "$PASS" | "$USERS" add "$TMP/users" phone --password-stdin
"$ENROLL" init "$TMP/offline"
"$ENROLL" invite "$TMP/offline" vps-phone 300 "$TMP/ca.pem" localhost "$TMP/invite.json"
printf '%s\n%s\n' "$PASS" "$PASS" |
  "$DEVICE" request "$TMP/invite.json" "$TMP/device" "$TMP/request.json" --passphrase-stdin
# Host-local password enrolment API, no Internet listener.
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
PIDS="$PIDS $!"
for _ in $(seq 1 50); do
  if curl --noproxy '*' -s --max-time 1 \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"phone\",\"password\":\"$PASS\"}" \
    "http://127.0.0.1:$PORT/api/fedup/v1/config" >"$TMP/config"; then
    break
  fi
  sleep 0.1
done
python3 - "$TMP" "$PORT" "$PASS" <<'PY'
import json,pathlib,sys,urllib.request
path,port,password=sys.argv[1:]
folder=pathlib.Path(path)
csr=json.loads((folder/"request.json").read_text())["csr_pem"]
body=json.dumps({"username":"phone","password":password,"device":"vps-phone",
                 "csr_pem":csr}).encode()
req=urllib.request.Request(
    f"http://127.0.0.1:{port}/api/fedup/v1/devices", data=body,
    method="POST",headers={"Content-Type":"application/json"})
with urllib.request.urlopen(req,timeout=10) as response:
    assert response.status==201
    cert=json.loads(response.read())
assert "BEGIN CERTIFICATE" in cert["certificate_pem"]
(folder/"issued.pem").write_text(cert["certificate_pem"])
PY
printf '%s\n' "$PASS" |
  "$DEVICE" import "$TMP/device" "$TMP/issued.pem" --passphrase-stdin

ip netns add "$CN"; ip netns add "$SN"; ip netns add "$EN"
ip link add "$CV" type veth peer name "$SV"
ip link set "$CV" netns "$CN"; ip link set "$SV" netns "$SN"
ip -n "$CN" addr add 172.31.44.2/30 dev "$CV"
ip -n "$SN" addr add 172.31.44.1/30 dev "$SV"
ip -n "$CN" link set lo up
ip -n "$SN" link set lo up
ip -n "$EN" link set lo up
ip -n "$CN" link set "$CV" up
ip -n "$SN" link set "$SV" up
ip link add "$SW" type veth peer name "$EW"
ip link set "$SW" netns "$SN"; ip link set "$EW" netns "$EN"
ip -n "$SN" addr add 172.31.55.1/30 dev "$SW"
ip -n "$EN" addr add 172.31.55.2/30 dev "$EW"
ip -n "$SN" link set "$SW" up
ip -n "$EN" link set "$EW" up
# Synthetic public addresses are on the fake Internet node only.
ip -n "$EN" addr add 9.9.9.9/32 dev lo
ip -n "$EN" addr add 1.1.1.1/32 dev lo
ip -n "$SN" route add default via 172.31.55.2 dev "$SW"
ip -n "$EN" route add 10.77.0.2/32 via 172.31.55.1 dev "$EW"

# TCP/HTTP and UDP/53 responders in the synthetic Internet namespace.
ip netns exec "$EN" python3 -m http.server 8080 --bind 9.9.9.9 \
  >"$TMP/http.log" 2>&1 &
PIDS="$PIDS $!"
ip netns exec "$EN" python3 -u -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("1.1.1.1",53))
while True:
    payload,peer=s.recvfrom(2048)
    s.sendto(b"fedup-test-dns-reply:"+payload+b"|seen-source="+peer[0].encode(),peer)
' >"$TMP/udp.log" 2>&1 &
PIDS="$PIDS $!"
if [[ "$AUTH_MODE" == edge ]]; then
  command -v caddy >/dev/null || { echo "caddy required for edge acceptance" >&2; exit 2; }
  # Caddy holds the only public HTTPS listener. Device identity is verified
  # by the loopback-only h2c backend, not by untrusted HTTP headers.
  ip netns exec "$SN" "$TUN" server-vps-proof-h2c 127.0.0.1:47678 \
    futserver "$TMP/ca.pem" "$TMP/users" --behind-trusted-https-proxy \
    >"$TMP/server.log" 2>&1 &
  PIDS="$PIDS $!"
  # The public homepage is now a genuine independent Caddy file server,
  # NOT the FedUp backend's common default HTML placeholder.
  mkdir -p "$TMP/web"
  printf '%s\n' '<!doctype html><html lang="en"><head><title>Independent Caddy site</title></head><body><h1>Service is online.</h1><p>Caddy-owned public site.</p></body></html>' >"$TMP/web/index.html"
  cat >"$TMP/Caddyfile" <<EOF
{
    auto_https off
    admin off
    # Synthetic test clients using an IP URL omit SNI; real Android uses
    # the HTTPS domain. Use a trusted test-name fallback only in this lab.
    default_sni localhost
}
https://:7443 {
    bind 172.31.44.1
    tls $TMP/server.pem $TMP/server.key
    @public_site path / /index.html
    handle @public_site {
        root * $TMP/web
        file_server
    }
    handle {
        reverse_proxy h2c://127.0.0.1:47678 {
            flush_interval -1
        }
    }
}
EOF
  caddy validate --config "$TMP/Caddyfile" --adapter caddyfile >/dev/null
  ip netns exec "$SN" caddy run --config "$TMP/Caddyfile" --adapter caddyfile \
    >"$TMP/caddy.log" 2>&1 &
  PIDS="$PIDS $!"
else
  ip netns exec "$SN" "$TUN" "$SERVER_CMD" 172.31.44.1:7443 \
    futserver "$TMP/ca.pem" "$TMP/server.pem" "$TMP/server.key" \
    "$TMP/users" --unsafe-experimental-public-egress \
    >"$TMP/server.log" 2>&1 &
  PIDS="$PIDS $!"
fi
for _ in $(seq 1 80); do
  if ip -n "$SN" link show futserver >/dev/null 2>&1; then break; fi
  sleep 0.1
done
ip -n "$SN" link show futserver >/dev/null || {
  cat "$TMP/server.log" >&2; exit 1;
}
# Script changes only the namespace's nft rules, but uses temporary private
# filesystem state instead of the host's global /run path.
FEDUP_EGRESS_STATE="$TMP/egress-state" \
  ip netns exec "$SN" env FEDUP_EGRESS_STATE="$TMP/egress-state" \
  bash scripts/vps-egress-v4.sh install futserver "$SW" \
  --acknowledge-host-network-changes

# A non-authenticated client keeps its TCP socket open without sending TLS.
# An ordinary VPN client MUST still be served, instead of being stuck behind
# the first idle handshake. This is an offline, synthetic slow-client probe.
ip netns exec "$CN" python3 -u -c '
import socket,sys,time
with socket.create_connection(("172.31.44.1",7443),timeout=3) as s:
    open(sys.argv[1],"w").close()
    time.sleep(12)
' "$TMP/idle-ready" >"$TMP/idle.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 30); do
  [[ -f "$TMP/idle-ready" ]] && break
  sleep 0.1
done
[[ -f "$TMP/idle-ready" ]] || { cat "$TMP/idle.log" >&2; exit 1; }
# Anonymous browser must receive real HTML without a client certificate,
# over both standards-compliant HTTP/1.1 and HTTP/2. Device access remains
# independent and is tested below. Everything stays inside Linux namespaces.
if ! timeout 7 ip netns exec "$CN" curl -kfsS --noproxy '*' --http1.1 \
    --connect-timeout 2 "https://172.31.44.1:7443/" | grep -q "Service is online"; then
  echo "FAIL: anonymous HTTP/1.1 fallback unavailable" >&2
  if [[ "$AUTH_MODE" == edge ]]; then
    cat "$TMP/caddy.log" "$TMP/server.log" >&2
    timeout 4 ip netns exec "$CN" curl -vk --noproxy '*' \
      "https://172.31.44.1:7443/" >/dev/null 2>&1 || :
  fi
  exit 1
fi
if ! timeout 7 ip netns exec "$CN" nghttp --no-verify-peer \
    "https://172.31.44.1:7443/" | grep -q "Service is online"; then
  echo "FAIL: anonymous HTTP/2 fallback unavailable" >&2; exit 1
fi
if timeout 5 ip netns exec "$CN" curl -kfsS --noproxy '*' --http1.1 \
    "https://172.31.44.1:7443/fedup-lab/v1/ip-tunnel" >/dev/null 2>&1; then
  echo "FAIL: anonymous access exposed a protected HTTP endpoint" >&2; exit 1
fi
# Independently hosted public Caddy site must NOT return the backend
# placeholder; this isolates the real website from protected VPN handlers.
if [[ "$AUTH_MODE" == edge ]]; then
  timeout 6 ip netns exec "$CN" curl -kfsS --noproxy '*' --http2 \
    "https://172.31.44.1:7443/" | grep -q 'Caddy-owned public site' || {
      echo "FAIL: Caddy's independent public origin was not served" >&2
      exit 1
    }
fi
# Two distinct GETs over ONE HTTP/2 connection must both succeed.
# nghttp is invoked once with two distinct same-origin URLs; its verbose
# connection count is observed instead of assuming connection reuse.
timeout 8 ip netns exec "$CN" nghttp -v --no-verify-peer \
    "https://172.31.44.1:7443/" \
    "https://172.31.44.1:7443/index.html" >"$TMP/http2-reuse.log" 2>&1 || {
  cat "$TMP/http2-reuse.log" >&2
  echo "FAIL: anonymous HTTP/2 multi-request connection broke" >&2
  exit 1
}
if [[ "$(grep -c 'Service is online' "$TMP/http2-reuse.log" || :)" -ne 2 ]] ||
   [[ "$(grep -c 'Connected' "$TMP/http2-reuse.log" || :)" -ne 1 ]]; then
  cat "$TMP/http2-reuse.log" >&2
  echo "FAIL: expected two HTTPS/2 page responses over one TCP/TLS connection" >&2
  exit 1
fi
# Browser HEAD probes should have correct status and NO response body.
# `curl -I` requests remain entirely inside disposable namespaces.
for proto in --http1.1 --http2; do
  timeout 6 ip netns exec "$CN" curl -kfsSI --noproxy '*' "$proto" \
    "https://172.31.44.1:7443/" >"$TMP/head-check.txt"
  grep -q '^HTTP/.* 200' "$TMP/head-check.txt" || {
    cat "$TMP/head-check.txt" >&2
    echo "FAIL: anonymous HEAD has wrong HTTP status" >&2
    exit 1
  }
done
echo "Anonymous HEAD HTTP/1.1 and HTTP/2 status 200: PASS"
# An uncredentialed scanner must not distinguish a protected VPN URL from
# an ordinary missing URL, and public GET / must not mint a device cookie.
ip netns exec "$CN" python3 tools/active-probe.py --lab
if [[ "$AUTH_MODE" == proof || "$AUTH_MODE" == edge ]]; then
  # An active TLS client must NOT be asked for a certificate at handshake.
  # OpenSSL can decrypt its own post-ServerHello handshake for inspection;
  # passive observers cannot read these TLS 1.3 handshake contents.
  timeout 6 ip netns exec "$CN" openssl s_client -connect 172.31.44.1:7443 \
    -servername localhost -tls1_3 -alpn h2 -msg </dev/null \
    >"$TMP/tls-handshake.log" 2>&1 || :
  if grep -q 'CertificateRequest' "$TMP/tls-handshake.log"; then
    cat "$TMP/tls-handshake.log" >&2
    echo "FAIL: app-proof outer TLS requested a device certificate" >&2
    exit 1
  fi
  printf '%s\n' "$PASS" | timeout 12 ip netns exec "$CN" "$TUN" \
    "$PROBE_CMD" 172.31.44.1:7443 "$TMP/device" --passphrase-stdin
  echo "Ordinary TLS without ClientCertificateRequest; signed device proof: PASS"
fi
echo "HTTP/2 reuse: 2 page requests over 1 TLS connection: PASS"
echo "Anonymous HTTP/1.1 and HTTP/2 web fallback; protected URL denied: PASS"
echo "Unauthenticated idle TLS socket deliberately held open"
printf '%s\n' "$PASS" | ip netns exec "$CN" "$TUN" \
  "$CLIENT_CMD" 172.31.44.1:7443 futclient "$TMP/device" \
  --passphrase-stdin >"$TMP/client.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 80); do
  if ip -n "$CN" link show futclient >/dev/null 2>&1; then break; fi
  sleep 0.1
done
ip -n "$CN" link show futclient >/dev/null || {
  cat "$TMP/client.log" "$TMP/server.log" >&2; exit 1;
}
ip -n "$CN" addr add 10.77.0.2/30 dev futclient
ip -n "$CN" route add 9.9.9.9/32 dev futclient
ip -n "$CN" route add 1.1.1.1/32 dev futclient
# A public address is NOT reachable directly through client uplink.
ip -n "$CN" route get 9.9.9.9 | grep -q futclient
for attempt in $(seq 1 15); do
  if timeout 5 ip netns exec "$CN" ping -n -c 1 -W 2 9.9.9.9 >/dev/null; then
    break
  fi
  if [[ "$attempt" == 15 ]]; then
    cat "$TMP/client.log" "$TMP/server.log" >&2
    echo "FAIL: synthetic public-IP ping did not cross HTTP/2 NAT" >&2
    exit 1
  fi
  sleep 0.25
done
timeout 12 ip netns exec "$CN" curl --noproxy '*' -fsS \
  --connect-timeout 3 "http://9.9.9.9:8080/" >/dev/null
timeout 9 ip netns exec "$CN" python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(b"example.test",("1.1.1.1",53))
reply,source=s.recvfrom(1024)
assert reply==b"fedup-test-dns-reply:example.test|seen-source=172.31.55.1",reply
assert source[0]=="1.1.1.1",source
print("UDP/53 over VPN NAT: PASS")
PY
echo "IPv4 public destination ping + TCP HTTP + UDP DNS through FedUp HTTP/2 NAT: PASS"
# Active uncredentialed HTTP/TLS probe from the same synthetic client subnet:
# the VPN gateway must not authorize it, and the established device tunnel
# must remain usable. This is a security check, NOT proof of camouflage.
if timeout 6 ip netns exec "$CN" curl -kfsS --noproxy '*' \
    --connect-timeout 2 --max-time 4 \
    "https://172.31.44.1:7443/fedup-lab/v1/auth-check" >/dev/null 2>&1; then
  echo "FAIL: anonymous TLS/HTTP probe was admitted to protected endpoint" >&2
  exit 1
fi
timeout 6 ip netns exec "$CN" ping -n -c 1 -W 2 9.9.9.9 >/dev/null
echo "Active anonymous probe denied; authenticated tunnel still routes packets: PASS"
# A second ordinary HTTPS visitor must still see a public page WHILE
# the first device maintains its long-lived HTTP/2 TUN. With Caddy h2c
# different client requests can be multiplexed on one backend connection.
if ! timeout 6 ip netns exec "$CN" curl -kfsS --noproxy '*' --http2 \
  "https://172.31.44.1:7443/" | grep -q "Service is online"; then
  echo "FAIL: public website became unavailable during active IP tunnel" >&2
  exit 1
fi
echo "Public HTTPS still responds during authorized long-lived IP tunnel: PASS"
# Refuse a second simultaneous packet session until a real per-device
# address allocator and TUN demultiplexer exist. The second connection can
# authenticate, but must NOT see first device traffic or create another TUN.
if printf '%s\n' "$PASS" | timeout 8 ip netns exec "$CN" "$TUN" \
    "$CLIENT_CMD" 172.31.44.1:7443 futother "$TMP/device" \
    --passphrase-stdin >"$TMP/second-client.log" 2>&1; then
  echo "FAIL: a second session reused the shared single-device TUN" >&2
  exit 1
fi
if ! grep -Eq "HTTP/2 tunnel request rejected by server|application-authorized packet tunnel rejected" "$TMP/second-client.log"; then
  cat "$TMP/second-client.log" >&2
  echo "FAIL: second session did not receive an explicit refusal" >&2
  exit 1
fi
if ip -n "$CN" link show futother >/dev/null 2>&1; then
  echo "FAIL: rejected second session unexpectedly created another TUN" >&2
  exit 1
fi
echo "Concurrent second device session explicitly rejected without TUN creation: PASS"
# Account disable should close a live tunnel in <= 5 seconds.
"$USERS" disable "$TMP/users" phone
sleep 7
if timeout 5 ip netns exec "$CN" ping -n -c 1 -W 2 9.9.9.9 >/dev/null; then
  echo "FAIL: revoked account can still reach synthetic Internet" >&2
  exit 1
fi
echo "Active account revocation prevents further IPv4 Internet egress: PASS"
