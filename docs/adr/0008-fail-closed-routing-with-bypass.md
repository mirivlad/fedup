# ADR-0008: Prove leak protection against a real alternate route

- Date: 2026-11-09
- Status: Lab-only accepted

## Context

Prior TUN tests checked the absence of a default route inside a disposable namespace. This does not model the existence of ordinary Internet routing when a VPN crashes.

## Decision

Create and demonstrate a working direct bypass link in disposable namespaces, then apply client-only nftables policy that forbids the protected IPv4 and IPv6 hosts on any interface other than TUN. Exercise both authenticated transport modes and abrupt process death while the alternative route exists. Use Linux tc-netem for controlled packet loss and jitter, and measure one identical binary TCP workload per mode.

## Limitations

This is test code, not a production firewall installer. Fail-closed security on a real desktop requires independent privileged policy, correct DNS/IPv6 handling, atomic route updates and tested rollback. Synthetic link loss cannot establish resistance to active DPI or IP/ASN blocking.
