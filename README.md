# FedUp

**FedUp** is an early-stage, open-source project for a self-hosted, cross-platform private network tunnel for personal and family use.

> Status: **research and design**. No usable VPN, production server, or client has been released. Do not deploy or rely on this project for security or anonymity.

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

## Read the design

- [Product requirements](docs/requirements.md)
- [Threat model](docs/threat-model.md)
- [Architecture decisions](docs/architecture.md)
- [Measurement and acceptance plan](docs/testing.md)
- [Development roadmap](docs/roadmap.md)
- [Security policy](SECURITY.md)

## Community

Security findings: see [SECURITY.md](SECURITY.md). Keep live endpoints, configs and personal data out of issues and pull requests.

## License

FedUp is intended to be distributed under **GNU GPL-3.0-only**. See [LICENSE](LICENSE) once added.
