# FedUp — Measurement & Acceptance Plan (Draft v0.1)

A standard TLS connection is **not sufficient evidence of stealth**. Claim only the outcomes demonstrated by reproducible experiments.

## 1. Safety and scope

- Test on systems and endpoints under the testers' control, with appropriate authorization.
- Use synthetic identities and destinations; do not upload private user browsing PCAPs.
- Exclude credentials and raw device keys from all CI artifacts.
- Keep a pre-registered test design to avoid cherry-picking a favorable trace.
- No attempt to claim an ISP/authority's real-world classification rules from a small test.

## 2. Baselines

Collect traffic from:
1. ordinary HTTPS/HTTP2 sessions of comparable size and duration,
2. FedUp under idle, browsing, streaming, calls, file-transfer and bursty traffic,
3. no-tunnel direct connections,
4. optionally a separately labeled reference VPN for internal comparison.

Record platform, transport, client build SHA, MTU, link speed, RTT, packet loss, NAT type and software versions.

## 3. Fingerprints and classification

Measure:
- TLS implementation/cipher/extension profile, SNI and ALPN behavior, certificates and supported versions;
- flow duration, connections per minute, bytes per direction, packet-length distributions, inter-arrival-time distributions;
- multiplexing cadence, idle traffic, reconnect frequency and failure responses;
- active probing reactions to unauthenticated, malformed, replayed and expired requests;
- endpoint ASN/IP observability (cannot be hidden from the access network);
- classifier false-positive/false-negative rates on **held-out** traces if developing a local classifier.

Document data collection, sample size, train/test split, effects of traffic workload and limitations. Never convert 'not detected in our lab' to 'undetectable'.

## 4. Required correctness tests

| Failure | Expected result |
| --- | --- |
| Invalid/expired/replayed invitation | Enrollment rejected; no credential issued |
| Revoked device | New connection refused and established one disconnected within SLA |
| Wrong server certificate | Connection fails without insecure override |
| Malformed length field / oversized frame | Process stays alive, no unbounded memory allocation |
| DNS server outage | Error clearly reported; no unauthorized direct fallback |
| IPv4/IPv6 route mismatch | All traffic governed by policy, no unplanned escape |
| Wi-Fi ↔ cellular | Reconnect with bounded backoff and correct policies |
| Server process crash | Protected traffic stops if fail-closed enabled |
| One entry node blocked/unreachable | Switch only to another authorized entry, or fail closed |
| Android non-selected app | Uses ordinary network; presence of system VPN may remain observable |
| Keyring unavailable | Clear user action or secure refusal; no silent plaintext downgrade |
| Two clients with same invitation | Only one successfully enrolls |

## 5. Engineering test tiers

- Every push: formatting, static checks, unit tests, dependency/license audit, bounded parsers.
- PR/release: integration over Linux network namespaces, fault injection, API compatibility.
- Nightly / release candidate: fuzzing with corpus and sanitizer builds, long connection soak test, platform devices, performance regression.
- Manual release gate: full routing/DNS/IPv6 leak capture on Android, Linux and Windows when supported.

## 6. Release report template

For each release list: supported OS builds, verified transport versions, threat-model changes, known leaks/limitations, key storage behavior, tests run and not run, and an explicit statement that network blocking can still occur.

## 7. Environment constraints

Automated tests may not establish the detectability of behavior inside an unrelated real censorship network. Real-world validation is opt-in, within authorized networks, and must not compromise personal endpoint identities.
