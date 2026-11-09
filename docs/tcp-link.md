# FedUp experimental TCP link — operator notes

**This is not a VPN or an HTTPS/HTTP2 camouflage transport.** It forwards exactly one local TCP socket per authenticated session to one operator-configured TCP destination on the server host. It does not carry arbitrary IP traffic, UDP datagrams, DNS queries or routes.

## Architecture

~~~text
local application -> 127.0.0.1:CLIENT_PORT -> TLS 1.3 mTLS -> server -> 127.0.0.1:TARGET_PORT
~~~

- **Client identity:** TLS client certificate signed by the operator-controlled CA. Server verifies the chain, then checks the SHA-256 fingerprint of the DER leaf certificate against an allowlist.
- **Server identity:** client validates DNS Subject Alternative Name and CA, even if the TCP connection uses an IP address. Verification cannot be disabled.
- **Revocation:** the server re-reads its allowlist every five seconds during an established stream and before each new connection. Removing a fingerprint terminates an active session under normal operating conditions; this is not a hard real-time guarantee.
- **Admission:** no more than 16 concurrent sessions on each client or server process. Every frame has an independently validated maximum of 64 KiB; TCP Data chunks are 16 KiB.
- **Endpoint restrictions:** client can only listen on loopback; server can only forward to loopback. Server binds to loopback by default; an explicit --allow-public-bind flag is mandatory for any non-loopback address.
- **Connection semantics:** each TLS connection opens stream ID 1, awaits an acknowledgment, then carries Data and Close frames in both directions. Close represents one TCP half-close. Frames are not multiplexed.
- **Idle behavior:** incomplete framed reads time out after 300 seconds. No connection keepalive or reconnect yet.
- **Trust boundaries:** TLS protects bytes between the FedUp processes only. Traffic between the server process and its configured local TCP service is outside that protection.

## CLI and tests

Build on Linux with Rust, OpenSSL and Python 3:

~~~sh
cargo test --workspace --all-targets
cargo build -p fedup-link -p fedup-identity
bash tests/link-smoke.sh
~~~

The smoke script creates **temporary** test CA and certificates, starts a TCP echo service, exercises binary transfer, and checks unlisted identities and active-session revocation. It deletes those credentials after the test.

~~~text
fedup-link fingerprint CLIENT_CERT.pem
fedup-link server LISTEN_IP:PORT 127.0.0.1:TARGET_PORT ca.pem server.pem server.key allowlist.txt [--allow-public-bind]
fedup-link client 127.0.0.1:CLIENT_PORT SERVER_IP:PORT SERVER_NAME ca.pem client.pem client.key --unsafe-lab-plaintext-key
fedup-link client-device 127.0.0.1:CLIENT_PORT SERVER_IP:PORT /path/to/imported-device-dir
~~~

The allowlist contains one 64-character SHA-256 fingerprint of a client's DER leaf certificate per line. Blank and # comment lines are ignored. Missing, oversized or malformed allowlist files fail closed. The client SERVER_NAME must match the DNS Subject Alternative Name of the server certificate. A newly enrolled client should instead use the client-device command, which reads the pinned server identity and CA certificate from its imported private identity directory. Unencrypted key files are allowed only under explicit unsafe-lab-plaintext-key for legacy test fixtures.

For two Linux machines, arrange a **private lab network**, operator-issued certificates, a server listener on a known interface and the explicit non-loopback flag if required. The destination still must be a single loopback TCP address **on the server machine**. No automatic host firewall, invitation generation or certificate lifecycle management is implemented.

## Incomplete and unsafe for production

There is no device enrollment UI, key rotation, multi-host revocation replication, TUN, DNS, IPv6 leak prevention, UDP, multiplexing, traffic shaping, HTTP/2 or HTTP/3, failover, or DPI classification evidence. No publicly accessible VPN should be deployed from this experiment. There is no established, audited security guarantee.
