# FedUp — Roadmap

**Status:** planned; no stage completed until its acceptance conditions are demonstrated.

## Milestone M0: research and specification

- [x] Create public repository and choose GNU GPL-3.0-only.
- [x] Publish initial requirements, threat model, architecture and measurement approach.
- [ ] Resolve ADRs for first transport, credential model, server admin protocol and DNS routing.
- [ ] Produce a reproducible baseline capture/test fixture in an isolated lab.
- [ ] Choose a precise v0.1 release acceptance matrix and platforms.

**Exit:** reviewed protocol draft, recorded risks and a runnable measurement procedure.

## Milestone M1: minimal authenticated Linux-to-Linux transport

- [x] Rust workspace and `fedup-protocol` parser with strict frame-size limits and fuzz target.
- [x] Experimental TLS-backed fixed-destination TCP link with server certificate validation and mTLS.
- [ ] Per-device identity, short-lived enrollment and revocation. *(certificate fingerprint authorization, live revocation, SSH CLI, offline CSR approval, and local passphrase-encrypted PKCS#8 client keys are implemented; OS keystore, secure CA-key handling and automatic enrollment remain pending)*
- [ ] Multiplexed TCP streams; explicit UDP semantics. *(one bounded TCP stream per TLS session implemented)*
- [x] Linux command-line test client and isolated integration test (fixed target, not a full VPN).
- [ ] Packet capture and network behavior measurement against baselines. *(Repeatable three-run-per-mode synthetic PCAP study of raw TLS vs genuine HTTP/2 under an identical IP workload is implemented; a representative Firefox/Chromium HTTPS dataset, held-out classifier validation and real-network behavior are pending.)*

**Additional research:** genuine mTLS HTTP/2 (ALPN h2, real POST/DATA and bounded flow control) now carries the experimental TUN IP traffic through three network namespaces. Raw TLS and HTTP/2 pass matched functional tests; matched browser PCAP datasets and realistic security/performance testing remain pending.

**Exit:** one authorized client can securely exchange synthetic traffic through a controlled server; tests prove auth, limits and errors. **Not yet an installable consumer VPN.**

## Milestone M2: Linux operational system

- [ ] TUN integration and route/DNS handling for IPv4 and IPv6. *(Experimental Linux TUN now routes IPv4, IPv6, TCP, UDP and synthetic DNS to one exact allowed remote address in a **third isolated namespace**, with tested revocation; host routing, real NAT, automatic DNS policy and production leak controls remain pending.)*
- [ ] Protection policy and network-failure leak tests. *(A separate Rust **fedup-netguard** helper now installs a create-only atomic nftables table from strict JSON inside an isolated namespace and verifies kernel rule integrity; it blocks real alternate IPv4/IPv6 routes through client crashes, detects unexpected changes and tests explicit removal. Both transports transfer 192 KiB under 1% packet loss and delay. A real host-safe policy daemon, DNS/application split, restart behavior and long-term operation remain pending.)*
- [ ] Systemd service, DEB and straightforward SSH admin. *(experimental SSH CLI is implemented; packaging, roles and managed enrollment pending)*
- [ ] Stable config with documented backups and upgrades.

**Exit:** usable and demonstrably fail-closed on a Linux test host.

## Milestone M3: Android client

- [ ] Kotlin `VpnService` bridge to shared Rust core. *(The new OS-independent `fedup-core` packet admission is compiled in CI for Android ARM64; there is no Kotlin/VpnService integration yet.)*
- [ ] Per-app allow-list and explicit kill-switch behavior.
- [ ] Signed APK, device enrollment QR, background operation and roaming tests.
- [ ] Clear disclosure that apps may detect VPN state on Android.

**Exit:** Android + Linux + server end-to-end acceptance, with limitations published.

## Milestone M4: Windows and operational hardening

- [ ] Windows driver and route integration, leak tests, user-friendly installer. *(The OS-independent `fedup-core` is also compile-checked for Windows GNU; there is no Windows driver or client yet.)*
- [ ] Optional admin UI, backups and rotation/revocation SLAs.
- [ ] CI release artifacts and security audit.

## Milestone M5: experimental multi-node resilience

- [ ] Signed backup-entry catalog and policy-safe failover.
- [ ] Optional relay/egress separation and distributed revocation.
- [ ] Comparative measurement and published limitations.

## Never call a milestone complete solely because CI is green

A release needs a user-facing install procedure, safe default configuration, demonstrable functionality, and a known-limitations report.
