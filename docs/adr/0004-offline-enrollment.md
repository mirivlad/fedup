# ADR-0004: Offline invitation/CSR enrollment before network enrollment

- **Date:** 2026-11-09
- **Status:** Experimental, accepted for laboratory implementation

## Context

The existing experimental TCP link requires device certificates. The first SSH admin tool can manage certificate fingerprints, but cannot provision a new client securely. Placing a CA signing key on the publicly reachable transport server would greatly expand the compromise blast radius.

## Decision

- Maintain a private, operator-local SQLite invitation ledger, not an enrollment endpoint exposed to the Internet.
- Invite using 256-bit OS-CSPRNG bearer tokens stored **only as SHA-256 digests** in the issuer ledger, with 128-bit random IDs and a maximum 24-hour lifetime.
- Put the CA certificate/public pin in an invitation transferred over an authenticated out-of-band channel.
- Accept only cryptographically verified signed CSRs, never client private keys. Do not adopt CSR-supplied key usages or CA flags; issue only short-lived client-auth certificates.
- Commit exactly one resulting certificate in a SQLite immediate transaction before attempting file export. Recovery exports identical bytes.
- Require a separate, explicit device allowlist step via fedup-admin. Signing alone does not authorize a connection.
- Treat this as laboratory-stage software until protected CA-key unlock, platform key stores, invitation identity verification and client UX are implemented.

## Known residual risks

- Stealing the bearer token before use may allow a race.
- The invitation trust anchor is only secure if the delivery channel is authenticated.
- The test-only issuer currently reads unencrypted CA PKCS#8 keys. Production use is prohibited until hardened.
- The issuer database contains sensitive enrollment metadata and signed public certs; filesystem compromise remains a risk.
- Revocation is local to a single server allowlist. Key rotation and multi-server replication are not implemented.
