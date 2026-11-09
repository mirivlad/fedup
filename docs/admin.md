# Experimental device administration (Linux)

FedUp now includes a small SSH-first CLI, fedup-admin, for the experimental mTLS TCP link. This is **not** a certificate authority, complete device enrollment, or a production VPN panel.

## Build

~~~sh
cargo build -p fedup-admin -p fedup-link
cargo test --workspace --all-targets
bash tests/link-smoke.sh
~~~

## Commands

~~~sh
target/debug/fedup-admin init /path/to/allowed.txt
target/debug/fedup-admin add /path/to/allowed.txt family-phone /path/to/client.pem
target/debug/fedup-admin add /path/to/allowed.txt family-laptop /path/to/laptop.pem
target/debug/fedup-admin list /path/to/allowed.txt
target/debug/fedup-admin revoke /path/to/allowed.txt family-phone
target/debug/fedup-admin fingerprint /path/to/client.pem
~~~

The client.pem argument is a **public client certificate**, NOT a private key or a CSR. Device names support 1-48 ASCII letters, digits, dots, dashes and underscores. Revocation accepts an exact device name or a full 64-character SHA-256 leaf-certificate fingerprint. Existing unlabeled fingerprints are supported as legacy records.

The experimental server still verifies the device certificate chain against its configured client CA. Adding a fingerprint alone does not make an untrusted certificate valid.

## Security behavior

- Init uses exclusive creation; it will not overwrite an existing list.
- Add/revoke obtain an advisory lock file beside the allowlist.
- Changes are validated before writing, then written into a 0600 temporary file, synced, and atomically renamed into place in the same directory.
- Duplicate device names and certificate fingerprints are rejected.
- Missing, malformed, oversized or symlinked allowlists fail closed.
- The experimental server reads the same file before authorizing each connection and checks it periodically during active TCP sessions (five-second interval).
- The CLI does not automatically distribute key material, private CA keys or invitations.

Use SSH and restrictive directory permissions. Do not edit the allowlist concurrently with fedup-admin using an editor, because external editors may ignore advisory locks. Generic comments may be removed when the CLI normalizes the file.

## Not implemented

Automatic client key generation and storage, CSR approval, CA signing, one-time enrollment invitations, device key rotation, administrative roles, audit history, web interface, backups, and multi-node revocation propagation. These are separate tasks. Keep the CA signing key off public VPS servers.

Full transport context: [experimental TCP link](tcp-link.md).
