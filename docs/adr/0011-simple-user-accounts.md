# ADR-0011: Simple account UX, PKI internal

Date: 2026-11-09
Status: First stage

A user should not handle CSR files or CA keys. Adopt username/password onboarding backed by salted Argon2id; expose a local-only rate-limited check behind trusted HTTPS; use Android Keystore AES-GCM to remember the account secret, without plaintext fallback.

Current HTTP 204 proves password validity only. The CA key remains offline; no unprotected online CA signer has been introduced. Automatic device enrollment, secure delegated issuer or alternative data-plane authentication, live-session revocation and end-to-end VPN routing remain outstanding. Do not treat this as production-ready.
