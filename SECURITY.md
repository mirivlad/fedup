# Security Policy

FedUp is currently **research software** with no production release. Do **not** use it to protect sensitive traffic or assume it provides anonymity.

## Reporting vulnerabilities

Until a dedicated security-reporting address is published, avoid public disclosure of exploitable vulnerabilities, credentials or active infrastructure information. Prefer GitHub's **private vulnerability reporting** if enabled for this repository. If it is unavailable, ask the maintainer for a private reporting channel without posting exploit details publicly.

Please include affected commit/version, a minimal reproduction with **synthetic credentials and hosts**, impact, and suggested mitigation if available. Never upload private keys, real account invitations or other people's packet captures.

## Secure engineering requirements

- No custom crypto; maintained TLS and trusted libraries only.
- Authenticated device enrollment and revocation, least privilege, no shared permanent client secrets.
- Parse untrusted traffic using explicit size limits and resource bounds; fuzz critical parsers.
- Fail closed on cryptographic verification errors and protected-route failures.
- No secret material in logs or diagnostics.
- Do not collect telemetry without a clear opt-in.
- Keep dependencies audited; publish source and release artifacts together.

## Deployment warning

Real endpoint/IP addresses are visible to network observers. TLS does not make an application protocol unclassifiable. Multi-node setups do not guarantee reachability when IP ranges are blocked.
