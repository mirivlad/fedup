# FedUp OS-independent IP packet admission

The Rust workspace now contains **fedup-core**, a small portable library that admits explicit IPv4/IPv6 packet pairs and rejects malformed lengths, fragments and unsupported IPv6 extension headers. It is independent of Linux TUN, nftables, TLS, certificate handling and networking privileges.

\`fedup-tun\` uses this shared immutable \`IpPolicy\` in both raw TLS and real HTTP/2 carriers, removing duplicated Linux-only parsing. The initial mode is intentionally fixed to synthetic client 10.77.0.2/fd42:fed0::2 and server/remote 10.77.0.1, 10.88.0.10, fd42:fed0::1, fd42:fed1::10, with MTU 1280. It is not a generic Internet VPN ACL.

CI cross-checks the library using \`cargo check -p fedup-core --target x86_64-pc-windows-gnu\` and \`--target aarch64-linux-android\`, plus native Linux unit tests. Cross-compilation does not prove functional Windows or Android VPN support.

Next platform adapters must implement OS routing, VPN interface lifecycle, DNS, credential storage, system protection and resume/suspend independently while sharing the protocol and packet policy. There is no Windows WFP or Android VpnService code yet.

This library neither alters the OS network configuration nor claims stealth or resistance to real-world traffic classification.
