# FedUp

**FedUp** is an early-stage, open-source project for a self-hosted, cross-platform private network tunnel for personal and family use.

> Status: **experimental routed Linux IPv4/IPv6 TUN over raw TLS or genuine HTTP/2, with encrypted device identities**. The Rust framing codec, one-shot mTLS lab, fixed-destination TCP forwarder, SSH-first device admin, offline invitation issuer and encrypted Linux device identity are NOT a VPN or production-ready network service. Do not rely on this project for anonymity or security-critical connectivity.

## Simple account login and automatic device enrollment (LAB only)

FedUp now has SSH-first Argon2id user accounts and an experimental loopback-only
provisioning API for an authenticated HTTPS reverse proxy. Android accepts **server,
username and password**, creates a non-exportable Android Keystore device key, generates
its own signed CSR and automatically verifies the seven-day client certificate.
The experimental Linux HTTP/2 server can authorize those certificate fingerprints
against the live user database and recheck revocation every five seconds.

**Online signing is deliberately restricted to `--unsafe-lab-online-ca` with a
disposable issuer. It is NOT safe for a real root CA or public VPS.** There is
no full-tunnel Internet routing/DNS, production kill switch, real-phone verification
or signed upgradeable Android release. See [Russian account guide](docs/ru/accounts.md)
and [English guide](docs/accounts.md).

## Goals

- **Privacy and security:** authenticated sessions, vetted cryptographic primitives, per-device credentials, revocation, minimal metadata retention.
- **Measurable resistance to traffic classification:** study protocol fingerprints and network behavior, test rather than promise invisibility.
- **Platform support:** Android, Linux, and Windows. At most one active VPN service per Android user/profile is assumed.
- **Selective routing:** allow-list apps on Android; appropriate platform routing and filtering on desktop, with clear limitations.
- **Self-hosting:** Linux server, optional relay and backup entry nodes, SSH-first administration and optional web UI.
- **Usability:** simple enrollment, QR/file invitations, clear connection and failure states, safe upgrades.
- **Free software:** GNU GPL-3.0-only (subject to compatibility checks for incorporated code).

## Non-goals and honest limits

- No claims of untraceability, guaranteed anonymity, or being undetectable by DPI or active network probing.
- No reliance on proprietary secrecy, private protocol names, or hidden source code as a security property.
- No custom cryptographic algorithms.
- No assumption that app-level split tunneling hides the existence of an Android system VPN.
- No collection or publication of real server addresses, private keys, or family device identities.

## Architecture direction (provisional)

1. **Client core:** cross-platform session logic; routing adapters for TUN, DNS, kill-switch and app policies.
2. **Entry service:** authenticated access over standard, maintained TLS/HTTPS implementations; no bespoke TLS handshake.
3. **Transport framing:** versioned FedUp application protocol over selected standard transports.
4. **Egress / optional relay:** user-controlled nodes with separate identity and authorization.
5. **Control plane:** enrollment, device credentials, configuration updates, revocation and telemetry without private content.
6. **Admin:** SSH/TUI first, optional private web interface.

**Technology candidates:** Rust for core and server, Kotlin Android VPN bridge, and a cross-platform desktop GUI. These are design candidates, not implementation commitments yet.

## Experimental laboratory

An Android Kotlin **diagnostic-only** shell and its arm64 JNI adapter now exist (see [Russian Android guide](docs/ru/android.md) and [English guide](docs/android.md)); it deliberately cannot connect or establish TUN until server auth, identity, DNS and routes are verified.

The current implementation includes an OS-independent **fedup-core** IP packet ACL (cross-checked for Windows GNU and Android ARM64 Rust targets), a separate namespace-only **fedup-netguard** privileged nftables policy helper, and a Linux TUN IP-packet laboratory with a third isolated routed/DNS endpoint (docs/tun.md), a genuine HTTP/2 streaming laboratory, also bridged into the isolated TUN modes server-h2/client-h2 (docs/http2.md), alongside a dependency-free Rust framing codec, a one-shot **loopback-only** mTLS 1.3 Ping/Pong lab, and an experimental **single-destination TCP forwarder**. The forwarder requires mutually authenticated TLS, an explicit device certificate allowlist and a fixed operator-configured target. The Linux fedup-admin CLI can initialize, list, add and revoke those allowed certificate fingerprints with atomic file updates. A new fedup-device CLI creates **encrypted client keys and signed CSRs** locally, verifies issued certificates, and fedup-link client-device uses enrollment-pinned server trust. It is not a full VPN, web protocol, or production-ready Internet-facing server.

On Linux with the Rust toolchain, OpenSSL and Python 3:

```sh
cargo test --workspace --all-targets
cargo build --workspace
bash tests/lab-smoke.sh
bash tests/link-smoke.sh
bash tests/enroll-smoke.sh
bash tests/device-smoke.sh
# Requires root and isolated Linux network namespaces:
sudo bash tests/tun-smoke.sh
# The same routed IP/DNS tests over genuine HTTP/2:
sudo env FEDUP_TUN_TRANSPORT=h2 bash tests/tun-smoke.sh
# Emulated packet loss and demonstrable direct-bypass kill switch:
sudo env FEDUP_TUN_TRANSPORT=raw FEDUP_TUN_FAULT=1 bash tests/tun-smoke.sh
sudo env FEDUP_TUN_TRANSPORT=h2 FEDUP_TUN_FAULT=1 bash tests/tun-smoke.sh
# Loopback HTTP/2 + mTLS streaming fixture:
bash tests/h2-smoke.sh
# Login, password reset and disable checks in a disposable account database:
bash tests/users-smoke.sh
# Disposable P-256 CA + password -> signed CSR -> account revocation:
bash tests/users-enroll-smoke.sh
# Pure Python safety tests for repeated PCAP reports:
python3 tools/test-traffic-study.py
```

For [portable IP admission](docs/ru/platform-core.md) and the [repeated synthetic TLS study](docs/ru/traffic-study.md), see the Russian guides. The shared packet core is not an Android or Windows VPN application, and the measured profiles are not DPI detection rates.

For the new independent firewall-policy helper, see [Russian operator guide](docs/ru/netguard.md) and [English operator guide](docs/netguard.md). The test installs and verifies this helper's kernel rules separately from the tunnel process, detects unexpected rule changes, and requires explicit removal. This is **still not a host-wide kill switch**.

For parser fuzzing, install cargo-fuzz and run `cargo fuzz run frame_parser` from the `fuzz/` directory. See [fail-closed lab and network faults (Russian)](docs/ru/fault-testing.md), [network fault lab (English)](docs/fault-testing.md), [genuine HTTP/2 research (Russian)](docs/ru/http2.md), [HTTP/2 operator reference](docs/http2.md), [IP tunnel + DPI research (Russian)](docs/ru/tun.md), [network observability](docs/tun.md), [encrypted Linux identity (Russian)](docs/ru/device.md), [device identity reference](docs/device.md), [offline enrollment (Russian)](docs/ru/enrollment.md), [offline enrollment reference](docs/enrollment.md), [SSH device administration (Russian)](docs/ru/admin.md), [admin reference](docs/admin.md), [lab instructions (Russian)](docs/ru/lab.md), [TCP link instructions (Russian)](docs/ru/tcp-link.md), [link design & limitations](docs/tcp-link.md) and [experimental wire framing](docs/protocol-v1.md).

## Read the design

- [Project overview in Russian / О проекте по-русски](docs/ru/README.md)
- [Product requirements](docs/requirements.md)
- [Threat model](docs/threat-model.md)
- [Architecture decisions](docs/architecture.md)
- [Measurement and acceptance plan](docs/testing.md)
- [Development roadmap](docs/roadmap.md)
- [Security policy](SECURITY.md)

## Community

Security findings: see [SECURITY.md](SECURITY.md). Keep live endpoints, configs and personal data out of issues and pull requests.

## License

FedUp is intended to be distributed under **GNU GPL-3.0-only**. See [LICENSE](LICENSE).
