# FedUp automatic device enrollment, laboratory only

**Current UX:** user enters HTTPS server, username, password. Android downloads the inner VPN CA over verified public HTTPS, creates a non-exportable P-256 key in Android Keystore, signs PKCS#10 CSR, authenticates to the provisioning API and imports the certificate automatically. No manual invitation or PEM transfer.

**Not production:** the lab auto-issuer requires the explicit \`--unsafe-lab-online-ca\` option and a disposable plaintext PKCS#8 CA key. Never expose a real root CA or use this issuer on production VPS. Only the user-login endpoint is suitable for future production hardening. A separate, protected delegated intermediate signer is required.

Command-line account administration: \`fedup-users init/add/password/disable/enable/devices/check-device/revoke-device/migrate\`. Argon2id hashes remain private in SQLite. A registered cert fingerprint binds to a username and exact account revision. Disabling or resetting a user invalidates all prior devices, including active VPN connections on the server's next 5-second check.

Laboratory API: \`fedup-auth serve-enroll-lab <users-dir> <port> <ca.pem> <ca.key> <server-dns> --unsafe-lab-online-ca\`, bound only to 127.0.0.1. Endpoints: POST /api/fedup/v1/login; GET /api/fedup/v1/config (public CA and hash); POST /api/fedup/v1/devices (username/password/device/CSR, returns 7-day client certificate). Request sizes, login attempts and Argon2id concurrency are bounded. Exact identical CSR retries return the originally stored certificate rather than creating duplicates. HTTPS reverse proxy and edge-level rate limits are mandatory before any exposure.

Experimental TUN server: \`fedup-tun server-h2-accounts <private-ip:port> <tun> <ca.pem> <server.pem> <server.key> <users-dir>\`, only in isolated namespaces and with fixed lab addresses. It requires mTLS plus active account device authorization and continuously rechecks authorization.

Acceptance test: \`bash tests/users-enroll-smoke.sh\` builds a disposable CA, signs a real OpenSSL P-256 CSR through the API, verifies the certificate, tests retries, bad password and user revocation. Android compiles in CI but has **not** been tested against a live phone or server.

No full-tunnel Internet routing, DNS protection, real online issuer isolation, certificate renewal, stable Android APK signing or censorship-resistance testing yet. See docs/ru/accounts.md for detailed steps.
