# FedUp — isolated Linux IP tunnel and observability

fedup-tun is an experimental Linux TUN-based IPv4/IPv6 transport over mutually authenticated TLS 1.3. It forwards real L3 packets using the FedUp Datagram frame type, with a **fixed two-endpoint lab allowlist**. It is NOT an Internet VPN, general proxy, browser-like HTTPS connection, or production system.

## Controlled test

The script tests/tun-smoke.sh creates two temporary Linux network namespaces and a veth link. The outer test network uses 172.31.44.0/30; the inner fixed peer addresses are 10.77.0.1/30 and 10.77.0.2/30, and fd42:fed0::1/64 and fd42:fed0::2/64. MTU is 1280. No host routing, DNS, or firewall is changed.

Validated functionality: IPv4 and IPv6 ICMP, HTTP over tunneled TCP, UDP datagrams, certificate revocation and absence of an external route **inside the namespace only**. There is no NAT, DNS management, route default policy, Internet access, auto-reconnect or production kill switch.

~~~sh
cargo build -p fedup-tun -p fedup-identity -p fedup-enroll -p fedup-admin
sudo bash tests/tun-smoke.sh
~~~

## Passive fingerprint analysis

With tcpdump installed, a reproducible synthetic PCAP can be collected by setting FEDUP_CAPTURE_PCAP. The local, standard-library-only tools/traffic-profile.py parses classic PCAP with FedUp TLS on port 7443 and OpenSSL/curl HTTP/1.1 TLS on port 9443.

It reports visible SNI/ALPN and ClientHello size/extensions, TCP packet length and timing, but **does not claim real-world DPI classification accuracy**. An OpenSSL/curl test is not a representative browser workload. Raw TLS does not automatically equal HTTP/2 or HTTP/3. Adding false ALPN values without the corresponding protocol is not a valid solution.

The network observer can still see the destination IP, handshake metadata and traffic patterns. TLS over TCP also creates head-of-line blocking for tunneled datagrams.

## Limitations

- Packet addresses and maximum length are deliberately restricted to two isolated peers.
- No Internet egress, NAT or actual split/full tunnel; no production deployment.
- Only one active client at a time in this proof of concept.
- No robust routing/DNS leak policy, service install or system privileges isolation.
- No certification of cryptographic or operational security.
- Do not publish real user captures, server addresses or private keys.

References: Linux TUN https://docs.kernel.org/networking/tuntap.html ; TLS 1.3 https://www.rfc-editor.org/rfc/rfc8446 .

## First measured lab fingerprint (9 Nov 2026)

The synthetic capture (GitHub Actions run 42563767605) extracted one FedUp and one curl/OpenSSL ClientHello:

| Field | FedUp | HTTP/1.1 control |
| --- | --- | --- |
| SNI | localhost | localhost |
| ALPN | none | http/1.1 |
| ClientHello size | 223 bytes | 1561 bytes |
| Advertised cipher suites | 9 | 30 |
| TCP frames in this specific test | 103 | 20 |

The applications exercised **different workloads**. TCP frame counts, flow duration and timing are therefore not controlled comparisons. The ClientHello and ALPN differences are observable and reproducible; they do NOT prove that any particular censorship system classifies the protocol.

The next experiment must use matched workloads, larger samples, negative tests and a real standards-compliant application protocol rather than false HTTP ALPN labels.
