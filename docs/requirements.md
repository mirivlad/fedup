# FedUp — Product Requirements (Draft v0.1)

**Status:** design baseline, not an implemented feature list. Changes require an ADR and tests.

## 1. Purpose and users

A self-hosted private network connection for an individual and a small number of trusted family members. It must be usable by non-technical recipients after enrollment. Open source does not mean that public endpoints or credentials are published.

## 2. Priorities

P0, in order: **confidentiality and integrity**, reliable reconnection, no inadvertent direct-route leaks when protection is requested, reproducible diagnosis, usability. Resistance to classification is a **measured research goal**, never a security guarantee.

## 3. Core requirements

| ID | Priority | Requirement | Verification |
| --- | --- | --- | --- |
| SEC-01 | P0 | Strong authenticated session security using maintained, audited crypto/TLS libraries; no custom ciphers | Independent security review, negative tests |
| SEC-02 | P0 | Each device has a unique identity; admin can revoke one without rotating all family devices | Integration test |
| SEC-03 | P0 | Credentials never appear in logs, diagnostics, screenshots, or public repository | Secret scanning and tests |
| SEC-04 | P0 | Strict limits on message sizes, session count, timeouts and resource use | Fuzzing and load tests |
| NET-01 | P0 | User traffic never exits via an unprotected route when the selected protected profile has fail-closed enabled | Network-disruption tests |
| NET-02 | P0 | DNS and IPv6 behavior are explicit, correctly routed, and tested; no silent fallback | Packet capture tests |
| NET-03 | P0 | Graceful disconnect, suspend/resume and reconnect with bounded backoff | Fault-injection tests |
| NET-04 | P0 | TCP and UDP transport are supported with documented semantics | Protocol tests |
| OPS-01 | P0 | Linux headless server install, systemd service, unprivileged execution where feasible, minimal open ports | Clean-install test |
| OPS-02 | P0 | SSH-first admin: add/revoke/list users, devices, entries, diagnostic status | Automated admin tests |
| UX-01 | P0 | Invite by file/QR; one device per credential; safe invitation expiry | End-to-end enrollment |
| UX-02 | P0 | Clear explanation of offline, authentication, DNS and route failures | UX acceptance |
| AND-01 | P1 | Android VpnService, system permission, per-app allow-list; only one active VPN service is assumed | Physical-device test |
| DESK-01 | P1 | Linux TUN and Windows TUN driver integrations; process-based filtering only if reliable | Platform-specific tests |
| OPS-03 | P1 | Optional private web admin, auditable role permissions | Security tests |
| NET-05 | P1 | Optional exit/relay separation and backup entries; never leak entry list publicly | Failover tests |
| RSH-01 | P1 | Collect reproducible traffic-classification evidence and compare a web-traffic baseline | Published test method |

## 4. User workflows

1. **Operator:** install the Linux service, initialize admin trust, create an expiring enrollment invitation without opening an admin UI to the public.
2. **Family member:** install a signed client, scan/import invitation, verify server identity, connect/disconnect without handling command-line configuration.
3. **Compromised or lost device:** revoke it; active sessions terminate within a defined and tested maximum window.
4. **Endpoint outage:** client clearly displays failure and either switches to an authorized backup or stops protected traffic; **never silently bypasses**.
5. **Android selection:** apps in the VPN allow-list use the tunnel; other apps use their normal network; this does **not** conceal the presence of a system VPN.
6. **Troubleshooting:** produce redacted diagnostics and an optional locally captured PCAP, with explicit confirmation and no automatic upload.

## 5. Explicit constraints

- Only one active Android VPN service per user/profile is required; coexistence with a simultaneous Naive Proxy VPN is out of scope.
- Public GitHub; **no real hostnames, IPs, user keys, invitations, or family device metadata** committed.
- One-node install must work without relay or Docker; multi-node is optional.
- No promise of anonymity, guaranteed DPI evasion or immunity from IP-range blocking.
- Not a commercial multi-tenant VPN service.

## 6. Definition of the first usable release

A testable Linux server, Linux and Android clients, authenticated encrypted traffic, safe enrollment and revocation, DNS/IPv4/IPv6 routing, reconnect and leak tests, signed artifacts, documentation and a declared list of limitations. Windows support remains a required project goal but is not hidden behind a claim that v0.1 supports it.

## References

- Android VpnService: https://developer.android.com/develop/connectivity/vpn
- Android VpnService.Builder allow-list: https://developer.android.com/reference/android/net/VpnService.Builder
- Wintun: https://www.wintun.net/
