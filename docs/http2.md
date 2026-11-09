# FedUp: standards-compliant HTTP/2 streaming lab

The experimental **fedup-h2-lab** is a separate loopback-only application transport prototype using the maintained Rust h2 library, real TLS 1.3 with ALPN h2, correctly framed HTTP/2 SETTINGS/HEADERS/DATA, a fixed POST path and a bounded binary response stream.

This is not a general CONNECT proxy, browser impersonator or production VPN. The HTTP/2 byte-stream adapter has now also been integrated into fedup-tun for an isolated IP-packet test.

## Architecture and controls

- TLS server checks an operator-issued client certificate chain and exact SHA-256 fingerprint against the device allowlist; denied identities cannot issue requests.
- TLS client pins the server CA and name from its own imported device identity and unlocks only encrypted PKCS#8 private keys.
- Only POST /fedup-lab/v1/duplex with a fixed content type is accepted; other requests return 404. The socket binds only to loopback.
- Bidirectional DATA transfer is bounded at 256 KiB and uses HTTP/2 stream- and connection-level flow control. The sender reserves capacity and waits for a window before emitting each 8 KiB data chunk, preventing unbounded h2 library buffering.
- Tests use a disposable local CA, send 196608 binary bytes (more than one initial HTTP/2 stream window), validate the round trip and refuse a newly revoked certificate.

~~~sh
cargo build -p fedup-h2-lab -p fedup-identity -p fedup-enroll -p fedup-admin
bash tests/h2-smoke.sh
~~~

## Security and research boundaries

- A legitimate HTTP/2 session is not necessarily indistinguishable from browser HTTPS. rustls ClientHello, TLS record sizes, SNI, connection durations and stream behavior remain observable.
- TLS client certificate authentication is unusual for public websites. Any redesign to application-layer device authentication must retain replay prevention, auditable revocation and cryptographic binding.
- There is not yet a full TUN-over-HTTP/2 mode, an HTTP/3/QUIC datagram transport, mobile app, production host routing or DNS leak policy.
- No claim of stealth, immunity to national DPI, IP/ASN blocking resistance or anonymity is justified by this test.
- Keep the public listener disabled. Only synthetic 127.0.0.1 data is permitted.

Technical standards: RFC 9113, RFC 9297, RFC 9298.

## Routed IPv4/IPv6 over HTTP/2

The experimental fedup-tun binary now supports server-h2 and client-h2, alongside its original raw mTLS modes. These use a genuine HTTP/2 POST at /fedup-lab/v1/ip-tunnel and bridge the FedUp Datagram byte-stream through bounded HTTP/2 DATA streams, backpressure and flow control.

Run the full disposable network namespace integration with:

~~~sh
cargo build -p fedup-tun -p fedup-enroll -p fedup-identity -p fedup-admin
sudo env FEDUP_TUN_TRANSPORT=h2 bash tests/tun-smoke.sh
~~~

The test verifies routed IPv4/IPv6 ICMP, TCP/HTTP, UDP and synthetic DNS through three namespaces; active certificate revocation breaks the routed connection. The GitHub Actions run 42570359233 passed and confirmed ALPN h2 in the passive ClientHello capture. The raw mode remains the baseline and does not advertise ALPN.

This is not a general-purpose VPN. The server accepts only the lab's exact synthetic routed host, and no host default route or firewall is changed.
