# FedUp — experimental offline device enrollment

This is an **offline CSR certificate-approval experiment**, not a finished VPN enrollment flow. It is Linux-only at this stage. It does not run a public enrollment HTTP endpoint, automatically provision Android/Windows clients, store client private keys, or safely unlock encrypted CA private keys.

## Architecture and trust

1. **Offline issuer machine:** the operator keeps the client certificate-authority private key (CA key) and a private SQLite invitation ledger. Do not copy that key or ledger to a public VPS.
2. **Operator creates invitation:** a fresh 256-bit random secret token, 128-bit identifier, limited lifetime (1 to 86400 seconds), intended device, CA certificate fingerprint and server name. The invitation file itself contains a **bearer secret** and must be delivered to the intended device over a trusted channel.
3. **Device makes CSR:** the device generates a key pair **locally using its secure key store or an encrypted key format** and signs a CSR. The private key must never be placed in the invitation, request, GitHub repository, chat or issuer database.
4. **Device prepares request:** the request contains the signed CSR and invitation token, and is returned over a trusted channel to the operator.
5. **Offline issuer approves:** checks the invitation ledger, expiry, matching metadata, constant-time token hash and CSR proof-of-possession. Issues a new certificate with operator-defined client-auth-only permissions and random serial. CSR-requested CA permissions are never copied.
6. **Export:** the ledger commits the certificate and consumes the invitation **before** writing the resulting certificate file. If saving the file fails, an operator can recover the **same issued certificate** by invitation ID. Replays cannot sign additional certificates.
7. **Authorization:** after issuance, the operator adds the public client certificate via fedup-admin to the target server's allowlist. Without that step, issuance does not grant network access.

## Commands

Build:

~~~sh
cargo build -p fedup-enroll -p fedup-admin
cargo test --workspace --all-targets
bash tests/enroll-smoke.sh
~~~

The automated smoke test creates temporary, unencrypted test keys **only inside a disposable local test directory**. It is not a key management recipe for real devices.

Offline issuer:

~~~sh
target/debug/fedup-enroll init /secure/offline/fedup-issuer
target/debug/fedup-enroll invite /secure/offline/fedup-issuer phone 900 \
    /secure/offline/ca.pem localhost /secure/exchange/phone-invite.json
~~~

On a device, after generating a CSR through a secure local key-storage workflow:

~~~sh
target/debug/fedup-enroll request phone-invite.json phone.csr.pem phone-request.json
~~~

Offline issuer:

~~~sh
target/debug/fedup-enroll approve /secure/offline/fedup-issuer \
    /secure/offline/ca.pem /secure/offline/ca.key \
    phone-request.json phone-cert.pem --unsafe-lab-plaintext-ca
~~~

The issuer exports only the public certificate for the device to import. To enable it on the server:

~~~sh
fedup-admin add /etc/fedup/allowed.txt phone phone-cert.pem
~~~

If the issuer committed a certificate but the export failed:

~~~sh
fedup-enroll recover /secure/offline/fedup-issuer INVITATION_ID recovered-cert.pem
~~~

This is a **manual approval** flow. No automatic transport of the invitation, CSR or certificate is implemented. The CA key loader currently supports **unencrypted PKCS#8 PEM** and explicitly requires **--unsafe-lab-plaintext-ca**. This is strictly a disposable-lab facility, not a production issuer. A protected CA-key unlock mechanism is required before real device enrollment.

## Important limitations

- A copied invitation can be used by the first party who presents a valid CSR; use a trusted channel and short expiry. Offline issuance prevents an exposed server from becoming a public enrollment oracle but does not authenticate the person holding a stolen invitation.
- The CA certificate fingerprint in the invitation is only trustworthy if the invitation itself arrives over an authenticated channel. This is not automated identity verification.
- The client must provide its own secure key-generation and key-storage workflow. There is no plaintext-key fallback in fedup-enroll.
- The issuer ledger must remain on a private Linux filesystem. Atomic SQLite transactions protect the invitation state; they do not defend against a compromised admin account or malicious disk access.
- Database and certificate exports must be backed up and permission-checked; the project has not implemented automated encrypted backups.
- Certificate validity and expiration are checked by rustls during TLS connections. Renewals, CRLs, explicit cert expiration policy bounded to CA expiration, clock rollback and central multi-node revocation are not finished.
- The current fedup-link still accepts a public PEM key on disk and lacks OS keyring integration; it is not production-ready. Do not deploy this as a family VPN yet.
