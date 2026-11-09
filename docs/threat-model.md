# FedUp — Threat Model (Draft v0.1)

## Scope

Protect application traffic in transit between an enrolled device and a user-controlled egress node, while studying the detectability of that connection. This is **not** an anonymity network and not an assurance against a nation-state adversary.

## Assets

- Content, destination metadata and integrity of tunneled traffic.
- Per-device identity keys, server trust anchors, enrollment secrets and revocation status.
- Private infrastructure endpoints, routing policies and admin credentials.
- Availability of service and privacy of diagnostic data.

## Adversaries and capabilities

| Adversary | Capabilities | Defenses / limits |
| --- | --- | --- |
| On-path passive observer | Sees client IP, server IP, times, sizes, TLS metadata where exposed, and flow patterns; correlates traffic | Correct encryption and measurement of fingerprints; **cannot hide IP endpoints by TLS alone** |
| Active network prober | Opens sessions, sends malformed inputs, replays packets, observes error/timing behavior | Authenticated and bounded protocol processing; uniform safe errors; no reliance on a fake website as a security boundary |
| Blocking middlebox | Filters by destination IP/ASN, ports, TLS traits and traffic patterns, including statistical classifiers | Multiple independently hosted entry endpoints and evaluated standard transports; no guaranteed bypass |
| Untrusted local app | May observe OS network/VPN state, public interface addresses, and locally reachable services within OS permissions | Android app allow-list limits traffic, **not VPN detectability**; secure local IPC, no debugging endpoints |
| Compromised exit node | Observes destination IP/port, and plaintext sent without end-to-end application TLS | Prefer application HTTPS; do not market exit node as untrusted-safe |
| Malicious / stolen client | Uses its own credential and attempts enumeration or persistence | Least privilege, one key per device, fast revocation, limits and audit without sensitive contents |
| Hosting provider | Knows customer's identity/payment details and traffic metadata, can suspend service | Avoid false privacy promises; separable infrastructure and documented provider risks |
| Compromised admin | Can issue new devices, change endpoints, potentially see operational metadata | Strong admin authentication, role separation where possible, audit changes, back-ups |

## Security properties that MUST hold

1. Authenticated encryption with modern, maintained libraries. No custom cryptographic primitive or ad hoc handshake.
2. Replay-resistant, versioned protocol; frame length bounds enforced **before** allocation and parsing.
3. Enrollment codes expire, are single-use, and never serve as long-lived device credentials.
4. Per-device identities and revocation, not a shared static family password.
5. Admin endpoint not co-hosted on the publicly exposed user access path by default.
6. No cleartext fallback when the operating-system keyring is unavailable; offer an explicit, user-understandable secure option or refuse enrollment.
7. Routing failures must not cause direct-route fallback when fail-closed is configured.
8. No automatic telemetry upload. Logs are minimal and omit traffic payloads, destinations and keys by default.
9. Depend on standard TLS implementations but verify client behavior and certificates; no blindly disabled certificate checks.
10. Configuration and update integrity, including rollback considerations for signed binary releases.

## Out of scope / residual risk

- Hiding the *existence* of a VPN from all Android apps. Some OS APIs can expose VPN state even for excluded apps.
- Hiding the address of the entry from the access ISP; the peer IP is visible on the network.
- Surviving blocking of an entire VPS provider/ASN or network disconnection.
- Avoiding correlation solely by encrypting an observable long-lived connection.
- Protection if the endpoint device or administrator is compromised.
- E2EE beyond the egress unless the destination application uses its own secure transport.

## Questions to answer before implementation

- Which standard transport(s) can be implemented and independently profiled without inventing TLS fingerprints?
- What is the exact revocation propagation SLA, and what happens when the control plane is offline?
- Which Linux/Windows credential-store fallback policies are acceptable without fail-open behavior?
- How will UDP datagrams be carried reliably where the underlying transport is stream-based?
- How can third-party contributors reproduce tests without publishing live private endpoints?

Every threat-model revision should document **what changed**, affected tests, and residual risks.
