#!/usr/bin/env bash
# Ephemeral Linux netns lab; does not alter host routes, firewall or DNS.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ "$(id -u)" == 0 ]] || { echo "Use sudo bash tests/tun-smoke.sh" >&2; exit 2; }
for cmd in ip ping openssl python3 curl timeout; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }; done
[[ -c /dev/net/tun ]] || { echo "No /dev/net/tun" >&2; exit 2; }
for binary in fedup-tun fedup-enroll fedup-device fedup-admin fedup-netguard; do
  [[ -x "target/debug/$binary" ]] || { echo "Build $binary first" >&2; exit 2; }
done
TUN="$PWD/target/debug/fedup-tun"
ENROLL="$PWD/target/debug/fedup-enroll"
DEVICE="$PWD/target/debug/fedup-device"
ADMIN="$PWD/target/debug/fedup-admin"
NETGUARD="$PWD/target/debug/fedup-netguard"
MODE="${FEDUP_TUN_TRANSPORT:-raw}"
FAULT_MODE="${FEDUP_TUN_FAULT:-0}"
[[ "$FAULT_MODE" == 0 || "$FAULT_MODE" == 1 ]] || { echo "FEDUP_TUN_FAULT must be 0 or 1" >&2; exit 2; }
if [[ "$FAULT_MODE" == 1 ]]; then
  for required in tc nft; do command -v "$required" >/dev/null || { echo "Missing $required for fault tests" >&2; exit 2; }; done
fi
case "$MODE" in
  raw) SERVER_CMD="server"; CLIENT_CMD="client" ;;
  h2) SERVER_CMD="server-h2"; CLIENT_CMD="client-h2" ;;
  *) echo "Unknown FEDUP_TUN_TRANSPORT: $MODE" >&2; exit 2 ;;
esac
umask 077
TMP="$(mktemp -d)"
CN="fuc$BASHPID"; SN="fus$BASHPID"; EN="fue$BASHPID"; CV="vfc$BASHPID"; SV="vfs$BASHPID"; SE="vse$BASHPID"; EV="vee$BASHPID"; BW="vbw$BASHPID"; BE="vbe$BASHPID"
PIDS=""
cleanup() {
  set +e
  for pid in $PIDS; do kill "$pid" 2>/dev/null; done
  for pid in $PIDS; do wait "$pid" 2>/dev/null; done
  ip netns del "$CN" 2>/dev/null
  ip netns del "$SN" 2>/dev/null
  ip netns del "$EN" 2>/dev/null
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

ip netns add "$CN"; ip netns add "$SN"; ip netns add "$EN"
ip link add "$CV" type veth peer name "$SV"
ip link set "$CV" netns "$CN"; ip link set "$SV" netns "$SN"
ip -n "$CN" addr add 172.31.44.2/30 dev "$CV"
ip -n "$SN" addr add 172.31.44.1/30 dev "$SV"
ip -n "$CN" link set "$CV" up; ip -n "$SN" link set "$SV" up
ip -n "$CN" link set lo up; ip -n "$SN" link set lo up
ip -n "$EN" link set lo up
# Third isolated namespace acts as a synthetic remote host, not the Internet.
ip link add "$SE" type veth peer name "$EV"
ip link set "$SE" netns "$SN"
ip link set "$EV" netns "$EN"
ip -n "$SN" addr add 10.88.0.1/24 dev "$SE"
ip -n "$EN" addr add 10.88.0.10/24 dev "$EV"
ip -n "$SN" -6 addr add fd42:fed1::1/64 dev "$SE"
ip -n "$EN" -6 addr add fd42:fed1::10/64 dev "$EV"
ip -n "$SN" link set "$SE" up
ip -n "$EN" link set "$EV" up
ip -n "$EN" route add 10.77.0.2/32 via 10.88.0.1 dev "$EV"
ip -n "$EN" -6 route add fd42:fed0::2/128 via fd42:fed1::1 dev "$EV"
# Forwarding is enabled ONLY in the disposable server namespace.
ip netns exec "$SN" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$SN" sysctl -qw net.ipv6.conf.all.forwarding=1

# A deliberately reachable DIRECT path represents a dangerous fallback.
# It exists only in the disposable network namespaces, never on the host.
if [[ "$FAULT_MODE" == 1 ]]; then
  ip link add "$BW" type veth peer name "$BE"
  ip link set "$BW" netns "$CN"
  ip link set "$BE" netns "$EN"
  ip -n "$CN" addr add 172.31.55.2/30 dev "$BW"
  ip -n "$EN" addr add 172.31.55.1/30 dev "$BE"
  ip -n "$CN" -6 addr add fd42:fed2::2/64 dev "$BW"
  ip -n "$EN" -6 addr add fd42:fed2::1/64 dev "$BE"
  ip -n "$CN" link set "$BW" up
  ip -n "$EN" link set "$BE" up
  ip -n "$CN" route add 10.88.0.10/32 via 172.31.55.1 dev "$BW" metric 100
  ip -n "$CN" -6 route add fd42:fed1::10/128 via fd42:fed2::1 dev "$BW" metric 4096
  # Wait until IPv6 duplicate-address detection completes on both new veths.
  sleep 1.3
  # Prove the bypass is real BEFORE installing a deny policy.
  ip -n "$CN" route get 10.88.0.10
  ip -n "$CN" -6 route get fd42:fed1::10
  if ! timeout 12 ip netns exec "$CN" ping -n -c 3 -W 2 10.88.0.10 >/dev/null; then
    echo "FAIL: synthetic IPv4 bypass is not actually reachable" >&2
    ip -n "$CN" addr show dev "$BW" >&2
    ip -n "$EN" addr show dev "$BE" >&2
    exit 1
  fi
  echo "Synthetic direct IPv4 bypass: CONFIRMED"
  if ! timeout 12 ip netns exec "$CN" ping -6 -n -c 3 -W 2 fd42:fed1::10 >/dev/null; then
    echo "FAIL: synthetic IPv6 bypass is not actually reachable" >&2
    ip -n "$CN" -6 route >&2
    ip -n "$EN" -6 addr show dev "$BE" >&2
    exit 1
  fi
  echo "Synthetic direct IPv6 bypass: CONFIRMED"
  # Install an independent, atomically applied policy with a root-only helper.
  # The policy exists before the VPN's TUN is created, and survives its crash.
  cat >"$TMP/netguard.json" <<'JSON'
{
  "version": 1,
  "tun": "futclient",
  "protected_ipv4": ["10.88.0.10"],
  "protected_ipv6": ["fd42:fed1::10"],
  "block_plain_dns": true
}
JSON
  chmod 0600 "$TMP/netguard.json"
  # Attempting to manage the original host namespace must fail before nft runs.
  if "$NETGUARD" install "$TMP/netguard.json" >"$TMP/host-refusal.log" 2>&1; then
    echo "FAIL: netguard accepted the initial host namespace" >&2; exit 1
  fi
  ip netns exec "$CN" "$NETGUARD" install "$TMP/netguard.json"
  ip netns exec "$CN" "$NETGUARD" verify "$TMP/netguard.json"
  # A trusted service may restart without replacing or briefly dropping rules.
  ip netns exec "$CN" "$NETGUARD" ensure "$TMP/netguard.json"
  ip netns exec "$CN" "$NETGUARD" ensure "$TMP/netguard.json"
  if ip netns exec "$CN" "$NETGUARD" install "$TMP/netguard.json" >"$TMP/reinstall.log" 2>&1; then
    echo "FAIL: netguard unexpectedly overwrote an existing table" >&2; exit 1
  fi
  if timeout 4 ip netns exec "$CN" ping -n -c 1 -W 1 10.88.0.10 >/dev/null 2>&1; then
    echo "FAIL: protected IPv4 leaked to direct bypass" >&2; exit 1
  fi
  if timeout 4 ip netns exec "$CN" ping -6 -n -c 1 -W 1 fd42:fed1::10 >/dev/null 2>&1; then
    echo "FAIL: protected IPv6 leaked to direct bypass" >&2; exit 1
  fi
  echo "Per-destination nftables kill switch blocks both direct bypasses: PASS"
fi

# Optional passive TLS capture: only artificial addresses inside this namespace.
# Set FEDUP_CAPTURE_PCAP to an output path (never capture personal browsing).
CAPTURE="$(printenv FEDUP_CAPTURE_PCAP 2>/dev/null || true)"
if [[ -n "$CAPTURE" ]]; then
  command -v tcpdump >/dev/null || { echo "tcpdump required for capture" >&2; exit 2; }
  ip netns exec "$SN" tcpdump -i "$SV" -n -s 0 -U -w "$CAPTURE" \
    '(tcp port 7443 or tcp port 9443)' >"$TMP/tcpdump.log" 2>&1 &
  PIDS="$PIDS $!"
  sleep 0.5
  # Control sample: genuine TLS 1.3 with an HTTP/1.1 application, not a
  # browser fingerprint or HTTP/2 baseline.
  ip netns exec "$SN" openssl s_server -accept 172.31.44.1:9443 \
    -cert "$TMP/server.pem" -key "$TMP/server.key" -tls1_3 -www \
    >"$TMP/https.log" 2>&1 &
  PIDS="$PIDS $!"
  for i in $(seq 1 30); do
    if ip netns exec "$CN" curl -k -fsS --noproxy '*' --http1.1 \
      --connect-timeout 1 -m 3 --resolve localhost:9443:172.31.44.1 \
      https://localhost:9443/ >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
fi
if ip -n "$CN" route get 1.1.1.1 >/dev/null 2>&1; then
  echo "FAIL: test namespace has external route" >&2; exit 1
fi

ip netns exec "$SN" "$TUN" "$SERVER_CMD" 172.31.44.1:7443 futserver \
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

printf '%s\n' "$PASS" | ip netns exec "$CN" "$TUN" "$CLIENT_CMD" \
  172.31.44.1:7443 futclient "$TMP/identity" --passphrase-stdin \
  >"$TMP/client.log" 2>&1 &
CLIENT_PID="$!"
PIDS="$PIDS $CLIENT_PID"
for i in $(seq 1 80); do
  ip -n "$CN" link show futclient >/dev/null 2>&1 && break
  sleep 0.1
done
if ! ip -n "$CN" link show futclient >/dev/null 2>&1; then
  cat "$TMP/client.log" "$TMP/server.log" >&2; exit 1
fi
ip -n "$CN" addr add 10.77.0.2/30 dev futclient
ip -n "$CN" -6 addr add fd42:fed0::2/64 dev futclient
# Route ONLY the synthetic remote host. No default route, no Internet bypass.
ip -n "$CN" route add 10.88.0.10/32 dev futclient
ip -n "$CN" -6 route add fd42:fed1::10/128 dev futclient
if ip -n "$CN" route get 10.88.0.11 >/dev/null 2>&1; then
  echo "FAIL: unexpected route to an unapproved synthetic destination" >&2; exit 1
fi

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

# UDP datagrams also travel as IP payloads inside FrameKind::Datagram.
ip netns exec "$SN" python3 -u - <<'PY' >"$TMP/udp.log" 2>&1 &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.77.0.1',53533))
while True:
    data,peer=s.recvfrom(4096)
    s.sendto(data[::-1],peer)
PY
PIDS="$PIDS $!"
sleep 0.2
ip netns exec "$CN" python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b'fedup-udp-packet',('10.77.0.1',53533))
data,_=s.recvfrom(4096)
assert data == b'tekcap-pdu-pudef', repr(data)
print('UDP datagram across IP TUN: PASS')
PY


# Routed IPv4/IPv6 beyond the VPN server, in a third namespace.
timeout 16 ip netns exec "$CN" ping -n -c 2 -W 2 10.88.0.10 >/dev/null
timeout 16 ip netns exec "$CN" ping -6 -n -c 2 -W 2 fd42:fed1::10 >/dev/null
echo "Routed IPv4/IPv6 ICMP to third namespace: PASS"

ip netns exec "$EN" python3 -u - <<'PY' >"$TMP/remote-http.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
class Remote(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b'fedup-routed-egress-ok')
    def log_message(self,*args): pass
HTTPServer(('10.88.0.10',8084),Remote).serve_forever()
PY
PIDS="$PIDS $!"
for i in $(seq 1 40); do
  if ip netns exec "$CN" curl -4 -fsS --noproxy '*' -m 2 \
      http://10.88.0.10:8084/ 2>/dev/null | grep -q fedup-routed-egress-ok; then
    break
  fi
  sleep 0.2
done
ip netns exec "$CN" curl -4 -fsS --noproxy '*' -m 5 \
  http://10.88.0.10:8084/ | grep -q fedup-routed-egress-ok
echo "Routed TCP/HTTP in third namespace: PASS"

# Controlled DNS wire protocol (UDP/53), never modifies host or namespace resolv.conf.
# Accept only the synthetic name remote.fedup.test with A 10.88.0.10.
ip netns exec "$EN" python3 -u - <<'PY' >"$TMP/dns.log" 2>&1 &
import socket, struct
server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
server.bind(('10.88.0.10',53))
while True:
    query,peer=server.recvfrom(1024)
    try:
        if len(query)<12 or query[2:4] != b'\x01\x00' or query[4:6]!=b'\x00\x01':
            continue
        pos=12; labels=[]
        while pos<len(query) and query[pos]:
            size=query[pos]; pos+=1
            if size>63 or pos+size>=len(query): raise ValueError()
            labels.append(query[pos:pos+size].decode('ascii'));pos+=size
        if pos+5>len(query): continue
        pos+=1
        qtype,qclass=struct.unpack('!HH',query[pos:pos+4])
        if (labels,qtype,qclass)!=(['remote','fedup','test'],1,1): continue
        question=query[12:pos+4]
        answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.88.0.10')
        response=query[:2]+b'\x81\x80'+struct.pack('!HHHH',1,1,0,0)+question+answer
        server.sendto(response,peer)
    except (ValueError,UnicodeError):
        continue
PY
PIDS="$PIDS $!"
sleep 0.2
ip netns exec "$CN" python3 - <<'PY'
import socket, struct
labels=(b'remote',b'fedup',b'test')
question=b''.join(bytes([len(s)])+s for s in labels)+b'\x00'+struct.pack('!HH',1,1)
id=b'\xab\xcd'
query=id+struct.pack('!HHHHH',0x0100,1,0,0,0)+question
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(query,('10.88.0.10',53))
answer,_=sock.recvfrom(512)
assert answer[:2]==id and answer[6:8]==b'\x00\x01' and answer[-4:]==socket.inet_aton('10.88.0.10')
print('Routed DNS UDP/53 lookup to third namespace: PASS')
PY

# An unauthorized remote IPv4 destination remains unreachable.
if timeout 3 ip netns exec "$CN" ping -n -c 1 -W 1 10.88.0.11 >/dev/null 2>&1; then
  echo "FAIL: unapproved egress address reachable" >&2; exit 1
fi

if [[ "$FAULT_MODE" == 1 ]]; then
  # TCP-in-TCP under controlled delay/loss. No promises about throughput:
  # record the observed elapsed time for an identical synthetic binary echo.
  ip netns exec "$CN" tc qdisc add dev "$CV" root netem delay 20ms 5ms loss 1% seed 24817
  ip netns exec "$SN" tc qdisc add dev "$SV" root netem delay 20ms 5ms loss 1% seed 90241
  ip netns exec "$EN" python3 -u - <<'PY' >"$TMP/bulk-echo.log" 2>&1 &
import socket, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.88.0.10", 8899))
s.listen(8)
def work(connection):
    with connection:
        while True:
            packet = connection.recv(32768)
            if not packet: break
            connection.sendall(packet)
while True:
    connection, _ = s.accept()
    threading.Thread(target=work, args=(connection,), daemon=True).start()
PY
  PIDS="$PIDS $!"
  sleep 0.2
  ip netns exec "$CN" env FEDUP_MEASURE_MODE="$MODE" python3 - <<'PY'
import json, os, socket, time
body = bytes(range(256)) * 768  # 196608 bytes; many TUN packets
started = time.monotonic()
with socket.create_connection(("10.88.0.10", 8899), timeout=30) as sock:
    sock.settimeout(45)
    sock.sendall(body)
    sock.shutdown(socket.SHUT_WR)
    chunks = bytearray()
    while len(chunks) < len(body):
        part = sock.recv(65536)
        if not part: break
        chunks.extend(part)
assert chunks == body, f"binary echo mismatch {len(chunks)} != {len(body)}"
print(json.dumps({"mode": os.environ["FEDUP_MEASURE_MODE"], "scenario": "netem-delay20ms-loss1percent", "roundtrip_bytes": len(body), "duration_seconds": round(time.monotonic()-started,3)}))
PY
  # Disable impairment before subsequent revocation assertions.
  ip netns exec "$CN" tc qdisc del dev "$CV" root
  ip netns exec "$SN" tc qdisc del dev "$SV" root
  echo "Netem 1% loss, bidirectional 20ms delay, 192KiB TCP over tunneled IP: PASS"
fi
"$ADMIN" revoke "$TMP/allowed.txt" lab-device
sleep 6
if timeout 4 ip netns exec "$CN" ping -n -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
  echo "FAIL: revoked session still works" >&2; exit 1
fi
if ip -n "$CN" route get 1.1.1.1 >/dev/null 2>&1; then
  echo "FAIL: external bypass route appeared" >&2; exit 1
fi
if timeout 4 ip netns exec "$CN" ping -n -c 1 -W 1 10.88.0.10 >/dev/null 2>&1; then
  echo "FAIL: revoked client still reaches synthetic egress" >&2; exit 1
fi
echo "Revocation, routed-egress cut-off and no external-route fallback: PASS"
if [[ "$FAULT_MODE" == 1 ]]; then
  # Abrupt client process loss must not select the working direct bypass.
  kill -9 "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  for i in $(seq 1 50); do
    if ! ip -n "$CN" link show futclient >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  if ip -n "$CN" link show futclient >/dev/null 2>&1; then
    echo "FAIL: TUN remained after client process termination" >&2; exit 1
  fi
  # The kernel now tries a REAL alternative route. nftables must block it.
  ip -n "$CN" route get 10.88.0.10 | grep -Fq "dev $BW" || {
    echo "FAIL: alternate IPv4 route did not become active" >&2; exit 1;
  }
  ip -n "$CN" -6 route get fd42:fed1::10 | grep -Fq "dev $BW" || {
    echo "FAIL: alternate IPv6 route did not become active" >&2; exit 1;
  }
  if timeout 4 ip netns exec "$CN" ping -n -c 1 -W 1 10.88.0.10 >/dev/null 2>&1; then
    echo "FAIL: protected IPv4 leaked when TUN crashed" >&2; exit 1
  fi
  if timeout 4 ip netns exec "$CN" ping -6 -n -c 1 -W 1 fd42:fed1::10 >/dev/null 2>&1; then
    echo "FAIL: protected IPv6 leaked when TUN crashed" >&2; exit 1
  fi
  ip netns exec "$CN" "$NETGUARD" verify "$TMP/netguard.json"
  ip netns exec "$CN" nft list chain inet fedup_lab_guard output >"$TMP/nft-counters.txt"
  grep -q "counter packets" "$TMP/nft-counters.txt" || {
    echo "FAIL: nftables output counters unavailable" >&2; exit 1;
  }
  echo "Crash with available direct bypass: nftables blocks IPv4 and IPv6 leaks: PASS"
  # Policy is independent of the now-dead VPN process. Removing it requires
  # an explicit operator-only action, and must never happen on process exit.
  ip netns exec "$CN" "$NETGUARD" verify "$TMP/netguard.json"
  # An unexpected extra kernel rule must fail integrity verification and
  # prevent accidental removal of a table someone else has modified.
  ip netns exec "$CN" nft add rule inet fedup_lab_guard output ip daddr 198.51.100.252 counter drop
  if ip netns exec "$CN" "$NETGUARD" verify "$TMP/netguard.json" >"$TMP/drift.log" 2>&1; then
    echo "FAIL: netguard ignored unexpected extra firewall rule" >&2; exit 1
  fi
  if ip netns exec "$CN" "$NETGUARD" ensure "$TMP/netguard.json" >"$TMP/drift-ensure.log" 2>&1; then
    echo "FAIL: netguard restarted over a tampered policy" >&2; exit 1
  fi
  if ip netns exec "$CN" "$NETGUARD" remove "$TMP/netguard.json" --confirm-lab-remove >"$TMP/drift-remove.log" 2>&1; then
    echo "FAIL: netguard removed tampered firewall policy" >&2; exit 1
  fi
  handle="$(ip netns exec "$CN" nft -a list chain inet fedup_lab_guard output |
    awk '/198[.]51[.]100[.]252/ {print $NF; exit}')"
  if ! [[ "$handle" =~ ^[0-9]+$ ]]; then
    echo "FAIL: cannot safely identify synthetic drift rule handle" >&2; exit 1
  fi
  ip netns exec "$CN" nft delete rule inet fedup_lab_guard output handle "$handle"
  ip netns exec "$CN" "$NETGUARD" verify "$TMP/netguard.json"
  echo "Kernel-policy drift and unsafe deletion both detected: PASS"
  ip netns exec "$CN" "$NETGUARD" remove "$TMP/netguard.json" --confirm-lab-remove
  if ip netns exec "$CN" "$NETGUARD" verify "$TMP/netguard.json" >/dev/null 2>&1; then
    echo "FAIL: netguard policy survived its explicit removal" >&2; exit 1
  fi
  timeout 12 ip netns exec "$CN" ping -n -c 2 -W 2 10.88.0.10 >/dev/null
  timeout 12 ip netns exec "$CN" ping -6 -n -c 2 -W 2 fd42:fed1::10 >/dev/null
  echo "Explicit laboratory unguard restores deliberately direct IPv4/IPv6 path: PASS"
fi
echo "FedUp Linux TUN namespace lab ($MODE): PASS"
