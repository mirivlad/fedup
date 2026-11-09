# FedUp — Roadmap

**Status (10 Nov 2026):** experimental Android/VPS IPv4 routing, account-based auto-enrollment, and isolated SNAT/UDP DNS tests are implemented. Physical acceptance and a protected delegated signer are NOT complete. See [evidence-based status](ru/status-2026-11-10.md).

## Milestone M0: research and specification

- [x] Create public repository and choose GNU GPL-3.0-only.
- [x] Publish initial requirements, threat model, architecture and measurement approach.
- [ ] Resolve ADRs for first transport, credential model, server admin protocol and DNS routing.
- [x] Produce reproducible isolated captures (curl/OpenSSL HTTP/1.1 control; browser-matched HTTP/2 is pending).
- [ ] Choose a precise v0.1 release acceptance matrix and platforms.

**Exit:** reviewed protocol draft, recorded risks and a runnable measurement procedure.

## Milestone M1: minimal authenticated Linux-to-Linux transport

- [x] Rust workspace and `fedup-protocol` parser with strict frame-size limits and fuzz target.
- [x] Experimental TLS-backed fixed-destination TCP link with server certificate validation and mTLS.
- [ ] Per-device identity, short-lived enrollment and revocation. *(certificate fingerprint authorization, live revocation, SSH CLI, offline CSR approval, and local passphrase-encrypted PKCS#8 client keys are implemented; automatic Android Keystore device enrollment is implemented only with the disposable lab signer; production CA-key custody and renewal are pending)*
- [ ] Multiplexed TCP streams; explicit UDP semantics. *(one bounded TCP stream per TLS session implemented)*
- [x] Linux command-line test client and isolated integration test (fixed target, not a full VPN).
- [ ] Packet capture and network behavior measurement against baselines. *(Repeatable three-run-per-mode synthetic PCAP study of raw TLS vs genuine HTTP/2 under an identical IP workload is implemented; a representative Firefox/Chromium HTTPS dataset, held-out classifier validation and real-network behavior are pending.)*

**Additional research:** genuine mTLS HTTP/2 (ALPN h2, real POST/DATA and bounded flow control) now carries the experimental TUN IP traffic through three network namespaces. Raw TLS and HTTP/2 pass matched functional tests; matched browser PCAP datasets and realistic security/performance testing remain pending.

**Exit:** one authorized client can securely exchange synthetic traffic through a controlled server; tests prove auth, limits and errors. **Not yet an installable consumer VPN.**

## Milestone M2: Linux operational system

- [ ] TUN integration and route/DNS handling for IPv4 and IPv6. *(Experimental Linux TUN now routes IPv4, IPv6, TCP, UDP and synthetic DNS to one exact allowed remote address in a **third isolated namespace**, with tested revocation; real VPS IPv4 SNAT and Android default-route/DNS are now implemented experimentally and pass isolated namespace CI; physical host acceptance, IPv6 egress and production leak controls remain pending.)*
- [ ] Protection policy and network-failure leak tests. *(A separate Rust **fedup-netguard** helper now installs a create-only atomic nftables table from strict JSON inside an isolated namespace and verifies kernel rule integrity; it blocks real alternate IPv4/IPv6 routes through client crashes, detects unexpected changes and tests explicit removal. Both transports transfer 192 KiB under 1% packet loss and delay. A real host-safe policy daemon, DNS/application split, restart behavior and long-term operation remain pending.)*
- [ ] Systemd service, DEB and straightforward SSH admin. *(experimental SSH CLI is implemented; packaging, roles and managed enrollment pending)*
- [ ] Stable config with documented backups and upgrades.

**Exit:** usable and demonstrably fail-closed on a Linux test host.

## Account onboarding usability (in progress)

- [x] SSH-first named accounts using salted Argon2id, user disable/enable, password rotation, private SQLite state.
- [x] Local-only, rate-limited password validation API designed for a verified HTTPS reverse proxy.
- [x] Android primary server/login/password screen, HTTPS-only authentication, encrypted remembered password using Android Keystore AES-GCM.
- [ ] **Automatic first-login enrollment:** phone-generated Keystore key and automatic CSR/PEM import now work against an explicitly lab-only seven-day CA issuer; device owner/revision/fingerprint are stored and checked on every VPN session + every 5 seconds. **A protected delegated signer, renewal and device lifecycle remain pending before acceptance.**
- [ ] Real server Android test: connection, IP routing, DNS/IPv6, background resume, emergency recovery, application upgrades.
- [x] Revoke account-bound devices on user disable/password reset and recheck during active lab TUN sessions (5-second interval).

**Current result:** the Android three-field login now automatically registers a Keystore device certificate in the **unsafe lab issuer** mode, and the isolated Linux HTTP/2 VPN server can verify account-bound device fingerprints. **No full-tunnel, safe public signer or real-device acceptance yet.**

## Milestone M3: Android client

- [ ] Kotlin `VpnService` bridge to shared Rust core. *(Real lab-only TUN + mTLS/HTTP2 packet relay exists and automatic account-based certificate provisioning is implemented; the advanced lab mode uses four fixed synthetic destinations, while the separate VPS IPv4 preview adds a default route and DNS. **No production full-device VPN, safe online issuer or real-phone acceptance yet.**)*
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
