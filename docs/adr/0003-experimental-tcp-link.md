# ADR-0003: Experimental fixed-destination TCP transport

- **Date:** 2026-11-09
- **Status:** Accepted for laboratory stage only

## Problem

A one-shot Ping/Pong lab cannot establish that session framing can carry real binary TCP traffic. We need a controlled end-to-end experiment before attempting TUN, UDP, multi-node relays, or browser-like transport experiments.

## Decision

1. Create fedup-link, using tokio + tokio-rustls TLS 1.3 with mutual certificate authentication.
2. Require a server-maintained explicit SHA-256 fingerprint allowlist of client certificates in addition to CA validation; refuse absent or malformed authorization files.
3. Re-read the allowlist for active sessions at a five-second interval, terminating those no longer authorized.
4. Support one logical bidirectional TCP stream per TLS connection. A client never supplies a destination; the operator configures one fixed server loopback TCP address.
5. Bound sessions at 16 per process, restrict public binds by default, validate all frames, and reject unexpected stream actions. Use TLS identity verification with no insecure override.
6. Prove binary roundtrip, unknown-device rejection, and active revocation in automated loopback smoke tests.
7. Do not market this as a VPN, an anonymity network, HTTP/2, or resistance to DPI.

## Consequences

This verifies only initial authenticated TCP forwarding, not arbitrary tunneling or a scalable production service. Passwordless certificate enrollment, administrative UI, replay tests beyond TLS, revocation propagation across nodes and independent cryptographic review are outstanding. Allowlisting by leaf certificate fingerprint is a deliberately temporary operational mechanism.
