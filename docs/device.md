# FedUp — encrypted Linux device identity prototype

fedup-identity provides the **fedup-device** command and an encrypted PKCS#8 loader used by the experimental fedup-link client. It is a prototype for Linux, not yet an Android Keystore / Windows CNG / system keyring implementation, a finished self-service app, or a production VPN.

## Enrollment

1. Receive a one-time invitation file from your operator over a **trusted authenticated channel**. Its bearer token must remain confidential.
2. Run fedup-device request to generate a fresh P-256 device key, an **AES-256-CBC encrypted PKCS#8** file with a passphrase and a signed CSR, and produce an enrollment request containing the token. The device key is never transmitted to the issuer.
3. The offline issuer approves the CSR under the trust anchor identified by the invitation. Issuance is exactly once.
4. The operator explicitly adds the issued client certificate fingerprint to the server via fedup-admin.
5. Run fedup-device import to verify the certificate's chain, SSL-client purpose, invited device name and local public/private key match.

~~~sh
cargo build -p fedup-identity -p fedup-link
target/debug/fedup-device request invitation.json ./my-device request.json
# Transfer request.json to the OFFLINE issuer through a private channel.
# Receive the signed client certificate, not a private key.
target/debug/fedup-device import ./my-device signed-client.pem
target/debug/fedup-link client-device 127.0.0.1:8080 SERVER_IP:7443 ./my-device
~~~

The imported directory contains the encrypted private key, signed CSR, pinned CA certificate, non-secret metadata and imported public client certificate. The one-time bearer token remains **only in the invitation and external request files** and must be deleted after enrollment.

The client-device command loads the name and CA pin from the invitation metadata; it does not rely on a manually typed new server identity. It prompts for the passphrase once at startup and decrypts PKCS#8 only in process memory; plaintext key material is not written to the filesystem.

### Headless testing

For disposable CI fixtures only, fedup-device request/import and fedup-link client-device support --passphrase-stdin. Avoid typing passwords in shell arguments, setting them in environment variables, storing them in the GitHub repository, or piping literal real passwords from terminal command history.

~~~sh
cargo build --workspace
cargo test --workspace --all-targets
bash tests/device-smoke.sh
~~~

The end-to-end smoke fixture uses one-time ephemeral keys, verifies the encrypted file and file modes, refuses wrong passphrases and certificate/identity mismatches, performs offline signing + allowlisting and exchanges binary data through a real mTLS link.

## Trust and limitations

- This is a passphrase-encrypted private key stored in a 0700 Linux directory, not TPM-backed or OS-keyring-backed storage.
- PKCS#8 uses OpenSSL, not a custom cipher. The exact PBES2/KDF parameters need review and hardening before production release.
- Decrypted key material is briefly present in process memory and in the TLS crypto library. Neither the application nor the library can claim hardware protection on a generic Linux desktop.
- This stage does not independently authenticate the issuer who sends a stolen or substituted invitation: the CA pin is only secure if the invitation is delivered through an authenticated channel.
- If the keyring is unavailable, the caller must explicitly unlock the encrypted file. An unencrypted key is **never silently accepted** as a fallback in the secure client mode.
- A separate --unsafe-lab-plaintext-key flag retains compatibility with the disposable TCP smoke test; this mode is prohibited for user deployment.
- There is no auto-renewal, enrollment over HTTPS, mobile GUI, egress/IP router, secure CA signing key or measured traffic-classification resistance yet.

Do not expose this prototype as a production VPN or on a public VPS without further hardening.
