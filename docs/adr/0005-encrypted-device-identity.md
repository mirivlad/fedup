# ADR-0005 — Encrypted local device identity, no silent plaintext fallback

- Date: 2026-11-09
- Status: Accepted for Linux laboratory prototype

## Context

Device private keys must be generated on the device, not on a central admin host, and not transferred with the CSR. Minimal Linux environments may lack unlocked GNOME Keyring/KWallet. Strict reliance on a keyring alone would prevent deployment on some minimal systems.

## Decision

- Generate a fresh P-256 key and CSR locally with a maintained OpenSSL implementation.
- Encrypt the private key into standard PEM PKCS#8 using a user-provided passphrase, never write plaintext PEM, and keep files in a new 0700 directory with mode 0600.
- Use rpassword for no-echo input. Only disposable headless test fixtures may use an explicit --passphrase-stdin option.
- Decrypt in process memory as required for TLS. Strictly refuse plaintext key headers and unsafe file modes in secure client mode.
- Import issued certificates only after verifying the pinned CA chain, SSL-client certificate purpose, the intended device name and correspondence to the private key.
- Use a client-device command that reads the server DNS identity and CA pin from enrollment metadata.
- Preserve an explicit --unsafe-lab-plaintext-key path for the older test harness only, never as an automatic fallback.

## Consequences and future work

A passphrase-encrypted PKCS#8 file is a portable explicit secure fallback, **not equivalent to hardware-backed key storage**. The passphrase KDF parameters, secure interactive unlock, Linux Secret Service/KWallet, Android Keystore, Windows CNG, certificate renewal and recovery still require dedicated implementation and review. The prototype must not claim production readiness.
