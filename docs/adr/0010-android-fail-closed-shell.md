# ADR-0010 — Refuse Android TUN activation without verified transport

- Date: 2026-11-09
- Status: Accepted for lab scaffolding only

Android VpnService can alter operating-system routing and interfere with the existing VPN. A fake or unauthenticated connection must not establish TUN or report protected status.

The first Android module therefore includes a real VpnService declaration and Kotlin/Rust JNI packet-policy bridge, but the service refuses activation and Always-on support. Native admission uses shared fedup-core with fail-closed behavior. The five independent prerequisites are Android consent, authenticated server, authorized device, available Rust core and verified DNS/routes; none is asserted by this diagnostic shell.

Next integrate protected sockets and actual authenticated TLS, a bounded TUN I/O loop, platform route policy and Android Keystore; test system Lockdown, roaming, crash and upgrade. Do not publish this debug shell as a VPN.
