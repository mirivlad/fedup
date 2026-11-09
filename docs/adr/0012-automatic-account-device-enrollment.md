# ADR-0012: Automatic account-bound device issuance, lab-gated signer

- Date: 2026-11-09
- Status: Experimental, not production-approved

## Context

FedUp's intended user experience is entering a server, username and password once. Manual CSR/PEM is unacceptable. Device private keys must remain non-exportable, account changes must revoke existing devices, and a lost registration response must not strand the user's key or accidentally grant duplicate identities.

## Decision

- On Android, keep private P-256 keys in Android Keystore and use the existing signed PKCS#10 request and strict certificate verifier, with the CA sourced only from standard authenticated HTTPS.
- Add a bounded, rate-limited loopback issuer endpoint in fedup-auth. Keep its CA plaintext signing key strictly behind \`serve-enroll-lab ... --unsafe-lab-online-ca\`, never in ordinary \`serve\` mode.
- Issue only seven-day, clientAuth + digitalSignature, non-CA certificates. Never copy CSR-provided certificate extensions or subject.
- Atomically store certificate fingerprint, CSR hash, owner, owner revision, expiry and certificate. Repeated identical CSRs return the identical certificate. Distinct CSRs cannot reuse an active device label.
- Enforce account disabled/revision/device-disabled checks on every new VPN mTLS connection and every five seconds during active sessions. Re-enabling a user does not restore revoked certificates.
- Do not call this a production issuer or full VPN. The TUN is still limited to a fixed lab topology.

## Exit requirements

A separately isolated signer with delegated, short-lived intermediate authority and audited key custody; robust identity renewal, partial-failure recovery, cap/revocation stress tests, properly constrained full-tunnel routing/DNS, Android emulator and real-device tests, staged VPS deployment, signed upgradeable APK and security review.
