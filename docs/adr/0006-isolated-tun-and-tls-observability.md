# ADR-0006: Isolated TUN transport and passive TLS fingerprint measurement

- Date: 2026-11-09
- Status: Accepted for lab stage only

## Decision

Use tokio-tun to create ephemeral Linux TUN devices, and the versioned FedUp Datagram frame to transport bounded IPv4/IPv6 packets over a mutually authenticated TLS 1.3 connection.

Restrict traffic to one synthetic IPv4/IPv6 peer pair and require existing per-device certificate authorization. Test two separate Linux network namespaces, not a live host route. Check IPv4/IPv6 ping, tunneled TCP/HTTP, UDP, active revocation and no external route in the test namespace.

Capture traffic on a synthetic veth interface and compare the current raw TLS ClientHello and flow metadata with an actual OpenSSL/curl HTTP/1.1 TLS reference. Use reproducible measurements, not a claim of invisibility.

## Consequences

This is a real L3 packet proof, not a VPN with Internet egress. There is no NAT, policy routing, DNS, kill switch, resilient reconnection, Windows or Android adapter. Datagram frames over TLS/TCP can suffer head-of-line blocking.

Current TLS handshake/application behavior is not equivalent to a browser. IP/ASN blocking remains possible. Production deployment is out of scope until further security testing and independent review.
