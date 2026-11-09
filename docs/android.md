# Android client: automatic account onboarding and narrow lab TUN

This is an experimental APK, not a production VPN or full-device Internet protection.

The primary UI asks for HTTPS server, username and password. After verification, it downloads the inner-VPN CA via a publicly authenticated HTTPS connection, generates a non-exportable P-256 private key in Android Keystore, signs a PKCS#10 CSR and automatically imports the user-linked signed certificate. The private key never leaves Android. Lost responses can be retried using the same CSR; the issuer returns the same certificate.

**The issuer is NOT production-safe.** Automatic signing is available only through explicitly enabled private, one-time, unsafe lab CA mode. Before public deployment replace it with an isolated, protected delegated signer; implement renewal and device lifecycle.

The Android VpnService does create a real TUN in an explicitly confirmed LAB-only diagnostic mode. The outer HTTP/2 mTLS socket is protected with VpnService.protect() before connect, and all packets are checked through fedup-core. The Advanced Diagnostics lab mode still only routes four synthetic IPs. A SEPARATE experimental VPS IPv4 mode is now reachable from the main Connect flow: automatic account enrollment, Android VPN consent, IPv4 default route, in-tunnel DNS 1.1.1.1, intentional IPv6 blackhole and a VPS HTTP/2 mTLS/SNAT gateway. It remains unaccepted on a physical phone and does not provide Always-on, Lockdown, IPv6 egress or production safety.

GitHub CI builds Rust ARM64 JNI, Kotlin, debug APK and unit tests, but the current device/issuer/tunnel chain has NOT been tested on real hardware or against a real VPS. The debug APK signing identity is ephemeral, not suitable for stable updates.

See docs/ru/accounts.md for the server user/enrollment lab and exact commands. Do not install this as your only VPN.
