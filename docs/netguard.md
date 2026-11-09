# FedUp Netguard: independent nftables policy helper

**Lab-only** Linux proof of concept. NOT an installable production kill switch.

fedup-netguard is a separate privileged command that runs **only inside a disposable Linux network namespace** and uses an atomic nftables transaction to create its own output hook table (inet fedup_lab_guard). It rejects protected IPv4/IPv6 destinations routed to any interface other than an explicitly named TUN, and blocks ordinary UDP/TCP port 53 DNS outside the TUN.

The kernel policy remains in effect after the command exits and after a VPN client crash, until it is **explicitly removed** or the namespace is destroyed. It does not survive reboot without an out-of-band service. It neither modifies existing host tables nor flushes the nftables ruleset.

## Strict configuration

~~~json
{
  "version": 1,
  "tun": "futclient",
  "protected_ipv4": ["10.88.0.10"],
  "protected_ipv6": ["fd42:fed1::10"],
  "block_plain_dns": true
}
~~~

Only exact IPv4/IPv6 hosts are supported, with limited sizes, duplicate checks, strict unknown-field rejection and an ASCII-only interface name. Arbitrary CIDR routing or user-defined nftables expressions are deliberately unsupported. Values never enter a shell.

Operations are plan (read-only), install (create-only), ensure (safe idempotent restart: verifies existing rules without replacing them), verify (full expected-rule comparison, ignoring dynamic packet counters), and remove (requires explicit --confirm-lab-remove and a successful integrity check). An existing table is **not** overwritten; ensure refuses modified rules, and rule installation failures do not trigger an automatic unsafe remove. This helper invokes nft from a fixed trusted system path.

## Run the isolated integration tests

~~~sh
sudo apt install nftables iproute2 iputils-ping curl python3 \
  openssl libssl-dev pkg-config tcpdump
cargo build --workspace
sudo env FEDUP_TUN_TRANSPORT=raw FEDUP_TUN_FAULT=1 bash tests/tun-smoke.sh
sudo env FEDUP_TUN_TRANSPORT=h2 FEDUP_TUN_FAULT=1 bash tests/tun-smoke.sh
~~~

The script creates a demonstrably functional synthetic direct bypass, installs policy before TUN starts, tests safe tunneled traffic, simulates packet loss, revokes the device and forcibly kills the client. It verifies the protected IPv4/IPv6 traffic stays blocked on the alternative route and that netguard can detect extra kernel rules, refuse untrusted removal, and accept deliberate operator removal.

## Not finished

The current lab-only policy protects only exact synthetic hosts, not every application on the operating system. There is no production DNS/IPv6 leak policy, full-tunnel routing, managed service, NetworkManager integration, secure endpoint route exception, least-privilege IPC or durable installation/upgrade recovery. A user with root can change the rules, and DNS-over-HTTPS is not recognized by these port 53 filters.

Design and implement a separate privileged host-policy controller before real desktop deployment. Do not paste the laboratory nftables plan into a live host configuration.
