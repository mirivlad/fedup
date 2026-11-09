# FedUp — controlled packet loss and fail-closed policy laboratory

This is an isolated Linux network namespace experiment, NOT a production host kill switch. The tests never modify the actual host default route, firewall, DNS or network devices.

## Failure model

TUN disappearance does not establish leak resistance: when a tunnel fails, Linux may choose an alternative ordinary route. The test must have a **working direct bypass** in order to verify that an independent firewall policy prevents protected traffic from leaking.

With FEDUP_TUN_FAULT=1, tests/tun-smoke.sh creates three disposable namespaces (client, VPN server, remote service) and another direct veth link between client and remote. It proves that IPv4 and IPv6 traffic can reach the remote host over the direct path. Only then it installs a private nftables output policy restricting the protected destinations to the TUN interface.

The script then checks routed IP, HTTP/TCP, UDP and synthetic DNS; applies Linux tc-netem 20ms delay plus 5ms jitter and 1% loss to each direction of the outer transport; exchanges 192 KiB of binary data over TCP; revokes access; kills the client and verifies that the kernel has an alternative route but nftables continues blocking protected IPv4 and IPv6. Both raw TLS and real HTTP/2 transports are exercised.

~~~sh
sudo apt install iproute2 iputils-ping nftables curl python3 \
  openssl libssl-dev pkg-config tcpdump
cargo build --workspace
sudo env FEDUP_TUN_TRANSPORT=raw FEDUP_TUN_FAULT=1 bash tests/tun-smoke.sh
sudo env FEDUP_TUN_TRANSPORT=h2 FEDUP_TUN_FAULT=1 bash tests/tun-smoke.sh
~~~

## Limits

- Rules cover only two exact synthetic destinations, not a general full-device VPN routing/DNS policy.
- One run is NOT a throughput benchmark. Wider repeated loss/latency distributions and confidence intervals are needed.
- This does not protect a real host from DNS, IPv6, WebRTC or direct-IP leaks.
- Neither real censor behavior nor IP/ASN blocking has been tested.
- Production needs a separate privileged and persistent network policy controller with safe atomic install, rollback and independent crash recovery.

Linux netem documentation: https://man7.org/linux/man-pages/man8/tc-netem.8.html .
