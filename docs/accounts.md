# FedUp simple account login — first phase

The intended family VPN UX is server, username and password. The new fedup-users SSH CLI supports init, add, list, password, disable, enable and check. Passwords are accepted only from stdin and stored in private SQLite as individually salted Argon2id PHC verifiers.

The fedup-auth API is restricted to loopback (127.0.0.1), intended behind a correctly authenticated HTTPS reverse proxy. POST /api/fedup/v1/login returns 204 for correct credentials, 401 for denial, or 429 for throttling. Request body, concurrency and per-user/global attempts are limited. Do not expose this plaintext loopback listener outside the machine.

Android's main screen now requests server, username and password with HTTPS-only certificate validation. On success the remembered password is encrypted with AES-GCM under an Android Keystore key; no plaintext fallback. Previous manual PKI workflow is under Advanced Diagnostics.

**This is not yet credential-based VPN connectivity.** The login endpoint validates only the account; it does not issue device certificates, register devices or grant data-plane access. The existing VPN transport still expects mTLS enrollment. Future tasks include automatic device-key issuance, delegated signing, user/device revocation and real Android↔server acceptance testing before any production installation. See docs/ru/accounts.md.
