# Android diagnostic shell (NOT a VPN)

The Kotlin project android/ and Rust crate fedup-android introduce a native JNI bridge to the portable fedup-core IP admission policy. The JNI method rejects oversized input *before copying*, malformed IP packets and wrong synthetic peer directions. Missing native library or JNI failures cause denial.

The AndroidManifest.xml registers a real system-bound VpnService but disables Always-on support. The service immediately stops and does not establish TUN, request VPN consent, connect to a server or alter DNS/routes. The app is **not usable as a VPN**; it offers diagnostics only. Unit tests cover fail-closed activation preconditions; no verified transport exists yet.

The android-lab CI job uses JDK 17, SDK 35, NDK 27.2.12479018 and Gradle 8.13 to compile Rust for arm64-v8a, package the JNI shared library into a debug APK and run Kotlin unit tests. No emulator or real-phone tests have been performed. No signed/release APK is provided.

Future work: trusted gateway and device enrollment, secure Android Keystore, VpnService.prepare()/protect(), TUN forwarding, routes/DNS/IPv6, split tunnel, Always-on/Lockdown, background lifecycle, device tests and stable signing/upgrades.

Official API docs: https://developer.android.com/develop/connectivity/vpn .
