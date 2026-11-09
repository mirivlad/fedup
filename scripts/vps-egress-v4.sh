#!/usr/bin/env bash
# Explicit, one-device IPv4 VPS egress; never changes SSH/default route.
set -Eeuo pipefail
TABLE=fedup_v4
STATE="${FEDUP_EGRESS_STATE:-/run/fedup-vps-v4.state}"
# Test-only override permits network-namespace CI without touching /run.
[[ "$STATE" == /* ]] || die "state path must be absolute"
usage() {
  cat >&2 <<'USAGE'
sudo bash scripts/vps-egress-v4.sh install <tun> <wan> --acknowledge-host-network-changes
sudo bash scripts/vps-egress-v4.sh status
sudo bash scripts/vps-egress-v4.sh remove --acknowledge-host-network-changes
Requires root, iproute2, nft and sysctl. Start fedup-tun FIRST.
ONLY 10.77.0.2/32 is NATed, IPv6 is NOT forwarded.
USAGE
}
die() { echo "FedUp egress: $*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "root required"
for cmd in ip nft sysctl; do command -v "$cmd" >/dev/null || die "missing $cmd"; done
valid_iface() { [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] && [[ "$1" != -* ]]; }
[[ $# -ge 1 ]] || { usage; exit 2; }
case "$1" in
  status)
    [[ $# == 1 ]] || { usage; exit 2; }
    if [[ -f "$STATE" ]]; then
      echo "FedUp egress state:"
      cat "$STATE"
    else
      echo "No active FedUp VPS egress state."
    fi
    nft list table ip "$TABLE" 2>/dev/null || true
    ;;
  install)
    [[ $# == 4 && "$4" == "--acknowledge-host-network-changes" ]] || { usage; exit 2; }
    TUN="$2"
    WAN="$3"
    valid_iface "$TUN" && valid_iface "$WAN" || die "invalid interface name"
    [[ "$TUN" != "$WAN" ]] || die "TUN and WAN must differ"
    [[ ! -e "$STATE" ]] || die "FedUp egress already installed"
    ! nft list table ip "$TABLE" >/dev/null 2>&1 || die "existing nft table; refusing overwrite"
    ip link show dev "$TUN" >/dev/null || die "TUN does not exist; start server first"
    ip link show dev "$WAN" >/dev/null || die "WAN does not exist"
    [[ -z "$(ip -4 -o addr show dev "$TUN")" ]] ||
      die "TUN has an IPv4 address; refusing to modify it"
    ROUTE="$(ip -4 route get 1.1.1.1)" ||
      die "VPS cannot route a public IPv4 address"
    [[ " $ROUTE " == *" dev $WAN "* ]] ||
      die "WAN is not the outgoing interface for public IPv4; check: ip route get 1.1.1.1"
    if ip -4 route show | grep -qE '(^| )10\.77\.0\.0/30( |$)'; then
      die "10.77.0.0/30 route already exists; refusing overlap"
    fi
    ip -4 addr add 10.77.0.1/30 dev "$TUN"
    rollback() {
      nft delete table ip "$TABLE" 2>/dev/null || true
      ip -4 addr del 10.77.0.1/30 dev "$TUN" 2>/dev/null || true
    }
    trap rollback ERR
    # Dedicated nft table only. Existing firewalls can still deny forwarding.
    nft -f /dev/stdin <<EOF
add table ip $TABLE
add chain ip $TABLE forward { type filter hook forward priority 0; policy accept; }
add rule ip $TABLE forward iifname "$TUN" oifname "$WAN" ip saddr 10.77.0.2/32 accept
add rule ip $TABLE forward iifname "$WAN" oifname "$TUN" ip daddr 10.77.0.2/32 ct state established,related accept
add rule ip $TABLE forward iifname "$TUN" drop
add rule ip $TABLE forward oifname "$TUN" drop
add chain ip $TABLE postrouting { type nat hook postrouting priority 100; policy accept; }
add rule ip $TABLE postrouting ip saddr 10.77.0.2/32 oifname "$WAN" masquerade
EOF
    sysctl -qw net.ipv4.ip_forward=1
    printf 'tun=%s\nwan=%s\nipv4=10.77.0.1/30\n' "$TUN" "$WAN" >"$STATE"
    chmod 0600 "$STATE"
    trap - ERR
    echo "Experimental IPv4 egress installed. IPv6 remains blocked."
    echo "SSH/default route untouched; inspect existing firewall FORWARD rules."
    ;;
  remove)
    [[ $# == 2 && "$2" == "--acknowledge-host-network-changes" ]] || { usage; exit 2; }
    [[ -f "$STATE" && ! -L "$STATE" ]] || die "missing private state file"
    [[ "$(stat -c %a "$STATE")" == "600" ]] || die "unsafe state file permissions"
    TUN="$(sed -n 's/^tun=//p' "$STATE")"
    valid_iface "$TUN" || die "invalid stored TUN"
    nft delete table ip "$TABLE"
    ip -4 addr del 10.77.0.1/30 dev "$TUN" ||
      die "nft removed, but could not remove TUN address; check manually"
    rm -f "$STATE"
    echo "FedUp rules and address removed. IPv4 forwarding left unchanged for other services."
    ;;
  *)
    usage; exit 2
    ;;
esac
