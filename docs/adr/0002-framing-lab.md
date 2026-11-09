# ADR-0002: Bounded framing and a loopback mTLS laboratory

- **Date:** 2026-11-09
- **Status:** Accepted for experimental scope; may change before deployment

## Decision

1. Implement the preliminary FedUp v1 12-byte header and maximum 64 KiB payload, with strict validation **before allocation**.
2. Keep the Rust codec free of external dependencies, with malformed-frame and fragmentation tests.
3. Implement a one-shot, loopback-only TLS 1.3 lab using the maintained rustls crate and mutual certificate authentication.
4. The laboratory only exchanges one Ping/Pong; do **not** expose it publicly or claim it is a VPN, proxy, stealth service or production-ready identity system.
5. Require CI unit tests and local mTLS smoke tests before claiming this stage is verified.

## Consequences

The protocol is experimental and can change. Authentication depends on a disposable test CA; there is no certificate revocation, enrollment, user database, control plane, HTTP/2 transport, or routing. Network classification must be studied separately after a functional candidate transport exists.
