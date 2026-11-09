# ADR-0009: Privileged nftables policy separated from VPN transport

- Date: 2026-11-09
- Status: Experimental, namespace-only

## Problem

A TUN client can die and leave an ordinary network route usable. A kill switch cannot be a set of rules owned by or automatically removed with the transport process. Previous smoke tests embedded nft directly inside a shell script, without independently validated configuration, integrity checks or safe administration.

## Decision

Implement fedup-netguard as an isolated privileged Rust helper with a strict versioned JSON manifest and no arbitrary nft expressions. It runs only inside non-initial Linux network namespaces, validates exact destination hosts, TUN interface name and mandatory direct-DNS block, and creates a dedicated output hook table in one atomic nft transaction. It refuses to replace existing tables, provides an idempotent ensure entry point that verifies rules on service restart without modifying existing policy, verifies independently of runtime counters and allows explicit, verified operator removal only.

The VPN process does not need to hold netguard permissions. Kernel rules outlive the VPN and netguard processes. No host firewall, default routes or DNS are modified in this stage.

## Consequences

Atomic nft transactions do not make rules reboot-persistent; persistence requires a separate trusted boot/service process and recovery journal. The helper is a proof of the separation of duties and of fail-closed behavior in a controlled namespace, not a ready-to-run system-wide firewall. Production design must handle protected CIDRs, explicit transport exception routing, DNS/IPv6 policy, pre-existing firewall state, least privileges, revocation and safe recovery without weakening the default protections.
