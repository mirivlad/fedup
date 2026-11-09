# ADR-0001: Security and Transport Baseline

- **Status:** Accepted for research; transport implementation choice pending measured evaluation
- **Date:** 2026-11-09

## Context

FedUp is a self-hosted family-oriented privacy tunnel. The project intends to minimize easily recognized VPN traits without treating obscurity as security. Network classification and direct IP/ASN blocking remain possible.

## Decision

1. Design a **versioned FedUp application-layer protocol** and session management model.
2. Run it over standard, maintained TLS implementations. Do **not** invent ciphers, a key exchange or a private TLS handshake.
3. Explore HTTP/2 over TLS 1.3 first as a **candidate**, not a predetermined stealth solution.
4. Separate enrollment/admin functions from the publicly reachable data path.
5. One credential per device, explicit revocation, fail-closed protected routes.
6. Start with one Linux entry+egress host; allow separate relays and backup entries in the architecture.
7. Android supports one active VPN service per profile. Split tunnel by app does not imply concealment of VPN state.

## Consequences

- TLS interoperability and security improve, but traffic fingerprinting remains a real risk.
- Data plane can evolve independently from user interface and platform-specific TUN components.
- More components create more failure states: every fallback and downgrade must be specified.
- The first deliverable must include negative tests and measurement baselines, not solely a working echo tunnel.

## Revisit triggers

Measured classification problems, security audit findings, routing leaks, client-platform constraints or changes to the required privacy properties.

## References

- RFC 8446: https://www.rfc-editor.org/rfc/rfc8446
- RFC 9113: https://www.rfc-editor.org/rfc/rfc9113
- Android VPN: https://developer.android.com/develop/connectivity/vpn
