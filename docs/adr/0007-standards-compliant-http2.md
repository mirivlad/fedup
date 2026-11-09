# ADR-0007: Genuine HTTP/2 instead of fabricated TLS fingerprint

Date: 2026-11-09
Status: Experimental, no production deployment

## Context

A synthetic PCAP of the initial FedUp mTLS/TCP carrier showed no ALPN and a smaller ClientHello than an OpenSSL/curl HTTP/1.1 baseline. Setting ALPN=h2 without implementing HTTP/2 would create a detectable protocol inconsistency and break standards-compliant clients.

## Decision

Prototype a genuine loopback HTTP/2 application with TLS 1.3, ALPN h2, valid request/response streams and HTTP/2 flow control. Start with a fixed POST binary echo application, authenticated by the existing client certificate allowlist. Do not use a generic open proxy or public tunnel.

Require tests of binary transfer exceeding 65535 bytes, bounded memory behavior, and new-connection rejection on certificate revocation before considering an IP-packet carrier.

## Consequences

The HTTP/2 framing is correct but the current TLS and application traffic profile still differs from typical browser sessions; this cannot be called censorship-proof. mTLS itself is an additional distinguishability risk. TUN integration, matched multi-sample packet captures, application-layer authentication alternatives, and QUIC/HTTP3 datagram semantics are separate future changes.
