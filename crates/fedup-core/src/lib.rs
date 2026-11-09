//! OS-independent IPv4/IPv6 packet admission for FedUp.
//!
//! This crate does not create TUN adapters, alter routes, or hold TLS keys.
//! A platform adapter supplies the received IP packet and the trusted
//! direction; the same verified policy runs on Linux, Windows and Android.
//!
//! Initial laboratory policy allows one device and explicit peer *hosts*.
//! This is not a full-tunnel policy and does not replace an OS kill switch.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const LAB_MTU: usize = 1280;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidMtu,
    MissingPeers,
    DuplicateOrInvalidPeer,
    InvalidClientAddress,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMtu => write!(f, "IP admission MTU must be 1280-65535"),
            Self::MissingPeers => write!(f, "an explicit peer is required for both IP families"),
            Self::DuplicateOrInvalidPeer => write!(f, "duplicate or invalid peer address"),
            Self::InvalidClientAddress => write!(f, "invalid client address"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Immutable address allowlist shared by all packet transports and OS adapters.
///
/// The client address may communicate only with explicitly configured peers.
/// This does NOT authorize arbitrary subnets or source-address spoofing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPolicy {
    client_v4: Ipv4Addr,
    client_v6: Ipv6Addr,
    peers_v4: Vec<Ipv4Addr>,
    peers_v6: Vec<Ipv6Addr>,
    mtu: usize,
}

impl IpPolicy {
    pub fn new(
        client_v4: Ipv4Addr,
        client_v6: Ipv6Addr,
        peers_v4: Vec<Ipv4Addr>,
        peers_v6: Vec<Ipv6Addr>,
        mtu: usize,
    ) -> Result<Self, PolicyError> {
        if !(1280..=65535).contains(&mtu) {
            return Err(PolicyError::InvalidMtu);
        }
        if !valid_v4(client_v4) || !valid_v6(client_v6) {
            return Err(PolicyError::InvalidClientAddress);
        }
        if peers_v4.is_empty() || peers_v6.is_empty() {
            return Err(PolicyError::MissingPeers);
        }
        let mut v4 = HashSet::new();
        let mut v6 = HashSet::new();
        if peers_v4
            .iter()
            .any(|address| !valid_v4(*address) || *address == client_v4 || !v4.insert(*address))
            || peers_v6
                .iter()
                .any(|address| !valid_v6(*address) || *address == client_v6 || !v6.insert(*address))
        {
            return Err(PolicyError::DuplicateOrInvalidPeer);
        }
        Ok(Self {
            client_v4,
            client_v6,
            peers_v4,
            peers_v6,
            mtu,
        })
    }

    /// Synthetic CI topology only, **not** public Internet access.
    pub fn isolated_lab() -> Self {
        Self::new(
            Ipv4Addr::new(10, 77, 0, 2),
            "fd42:fed0::2".parse().expect("constant lab IPv6"),
            vec![Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(10, 88, 0, 10)],
            vec![
                "fd42:fed0::1".parse().expect("constant lab IPv6"),
                "fd42:fed1::10".parse().expect("constant lab IPv6"),
            ],
            LAB_MTU,
        )
        .expect("static lab packet admission policy")
    }

    pub fn admits(&self, packet: &[u8], direction: Direction) -> bool {
        if packet.len() < 20 || packet.len() > self.mtu {
            return false;
        }
        match packet[0] >> 4 {
            4 => self.admit_v4(packet, direction),
            6 => self.admit_v6(packet, direction),
            _ => false,
        }
    }

    fn admit_v4(&self, packet: &[u8], direction: Direction) -> bool {
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        // Conservative lab policy: reject options until explicitly supported.
        if ihl != 20 || packet.len() < ihl {
            return false;
        }
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total != packet.len() {
            return false;
        }
        let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
        // Reject reserved flag, MF and every nonzero fragment offset. DF is OK.
        if flags_fragment & 0xbfff != 0 {
            return false;
        }
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        match direction {
            Direction::ClientToServer => src == self.client_v4 && self.peers_v4.contains(&dst),
            Direction::ServerToClient => dst == self.client_v4 && self.peers_v4.contains(&src),
        }
    }

    fn admit_v6(&self, packet: &[u8], direction: Direction) -> bool {
        if packet.len() < 40 {
            return false;
        }
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        if payload_len + 40 != packet.len() {
            return false;
        }
        // No IPv6 fragment/reassembly state exists yet. Reject extension
        // headers (including nested fragments), ESP, AH and routing headers
        // rather than accidentally accepting packets we cannot inspect.
        if matches!(packet[6], 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140) {
            return false;
        }
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("length checked"));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("length checked"));
        match direction {
            Direction::ClientToServer => src == self.client_v6 && self.peers_v6.contains(&dst),
            Direction::ServerToClient => dst == self.client_v6 && self.peers_v6.contains(&src),
        }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn peers(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.peers_v4
            .iter()
            .copied()
            .map(IpAddr::V4)
            .chain(self.peers_v6.iter().copied().map(IpAddr::V6))
    }
}

/// IPv4-only Internet acceptance for a *single* device. IPv6 is rejected
/// until a genuine IPv6 egress path and DNS/kill-switch policy are tested.
/// This is a packet-spoofing boundary, NOT a host firewall or a VPN itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct InternetV4Policy;

impl InternetV4Policy {
    pub fn admits(self, packet: &[u8], direction: Direction) -> bool {
        if !(20..=LAB_MTU).contains(&packet.len()) || packet[0] != 0x45 {
            return false;
        }
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if length != packet.len() {
            return false;
        }
        // Reject all fragments, IPv4 options and reserved flags to avoid
        // bypassing policy via reassembly or nested headers. DF is permitted.
        let flags = u16::from_be_bytes([packet[6], packet[7]]);
        if flags & 0xbfff != 0 || packet[8] == 0 {
            return false;
        }
        let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let phone = Ipv4Addr::new(10, 77, 0, 2);
        match direction {
            Direction::ClientToServer => src == phone && public_destination_v4(dst),
            Direction::ServerToClient => dst == phone && public_destination_v4(src),
        }
    }
}

/// Exclude RFC1918, loopback, link-local, CGNAT, documentation, multicast,
/// broadcast, and other special ranges. Explicitly forbid the gateway's
/// management networks even when the Android device requests them.
fn public_destination_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    match a {
        0 | 10 | 127 | 224..=255 => false,
        100 if (64..=127).contains(&b) => false,
        169 if b == 254 => false,
        172 if (16..=31).contains(&b) => false,
        192 if b == 168 || (b == 0 && (c == 0 || c == 2)) => false,
        198 if (b == 18 || b == 19) || (b == 51 && c == 100) => false,
        203 if b == 0 && c == 113 => false,
        _ => true,
    }
}

fn valid_v4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() && !ip.is_loopback()
}
fn valid_v6(ip: Ipv6Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(28u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    fn v6(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(8u16).to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet
    }

    #[test]
    fn accepted_ipv4_pairs_both_directions() {
        let policy = IpPolicy::isolated_lab();
        for remote in [[10, 77, 0, 1], [10, 88, 0, 10]] {
            assert!(policy.admits(&v4([10, 77, 0, 2], remote), Direction::ClientToServer));
            assert!(policy.admits(&v4(remote, [10, 77, 0, 2]), Direction::ServerToClient));
            assert!(!policy.admits(&v4(remote, [10, 77, 0, 2]), Direction::ClientToServer));
        }
    }

    #[test]
    fn accepted_ipv6_pairs_both_directions() {
        let policy = IpPolicy::isolated_lab();
        for remote in ["fd42:fed0::1", "fd42:fed1::10"] {
            let remote: Ipv6Addr = remote.parse().unwrap();
            let client: Ipv6Addr = "fd42:fed0::2".parse().unwrap();
            assert!(policy.admits(&v6(client, remote), Direction::ClientToServer));
            assert!(policy.admits(&v6(remote, client), Direction::ServerToClient));
            assert!(!policy.admits(&v6(client, remote), Direction::ServerToClient));
        }
    }

    #[test]
    fn rejects_spoofed_and_unapproved_targets() {
        let policy = IpPolicy::isolated_lab();
        for packet in [
            v4([10, 77, 0, 3], [10, 88, 0, 10]),
            v4([10, 77, 0, 2], [10, 88, 0, 11]),
            v4([10, 77, 0, 2], [8, 8, 8, 8]),
        ] {
            assert!(!policy.admits(&packet, Direction::ClientToServer));
        }
        let client = "fd42:fed0::2".parse().unwrap();
        let bad = "fd42:fed1::11".parse().unwrap();
        assert!(!policy.admits(&v6(client, bad), Direction::ClientToServer));
    }

    #[test]
    fn validates_ipv4_declared_lengths_options_and_fragment_flags() {
        let policy = IpPolicy::isolated_lab();
        let base = v4([10, 77, 0, 2], [10, 77, 0, 1]);
        for (byte, value) in [(0, 0x46), (2, 1), (3, 27), (6, 0x20), (6, 0x80), (7, 1)] {
            let mut packet = base.clone();
            packet[byte] = value;
            assert!(
                !policy.admits(&packet, Direction::ClientToServer),
                "{byte} {value}"
            );
        }
        let mut with_df = base;
        with_df[6] = 0x40;
        assert!(policy.admits(&with_df, Direction::ClientToServer));
    }

    #[test]
    fn ipv6_extensions_fragmentation_and_length_are_refused() {
        let policy = IpPolicy::isolated_lab();
        let src = "fd42:fed0::2".parse().unwrap();
        let dst = "fd42:fed1::10".parse().unwrap();
        let base = v6(src, dst);
        for next_header in [0, 43, 44, 50, 51, 60, 135, 139, 140] {
            let mut packet = base.clone();
            packet[6] = next_header;
            assert!(!policy.admits(&packet, Direction::ClientToServer));
        }
        let mut wrong = base;
        wrong[5] = 7;
        assert!(!policy.admits(&wrong, Direction::ClientToServer));
    }

    #[test]
    fn mtu_and_truncation_are_fail_closed() {
        let policy = IpPolicy::isolated_lab();
        let packet = v4([10, 77, 0, 2], [10, 88, 0, 10]);
        for length in 0..packet.len() {
            assert!(!policy.admits(&packet[..length], Direction::ClientToServer));
        }
        assert!(!policy.admits(&vec![0u8; LAB_MTU + 1], Direction::ClientToServer));
        assert_eq!(policy.mtu(), 1280);
    }

    #[test]
    fn rejects_invalid_or_duplicated_configuration() {
        let config = IpPolicy::isolated_lab();
        let peers: Vec<IpAddr> = config.peers().collect();
        assert_eq!(peers.len(), 4);
        assert!(IpPolicy::new(
            Ipv4Addr::new(10, 77, 0, 2),
            "fd42:fed0::2".parse().unwrap(),
            vec![Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(10, 77, 0, 1)],
            vec!["fd42:fed0::1".parse().unwrap()],
            LAB_MTU
        )
        .is_err());
        assert!(IpPolicy::new(
            Ipv4Addr::new(10, 77, 0, 2),
            "fd42:fed0::2".parse().unwrap(),
            vec![Ipv4Addr::new(10, 77, 0, 1)],
            vec![],
            LAB_MTU
        )
        .is_err());
        assert!(IpPolicy::new(
            Ipv4Addr::UNSPECIFIED,
            "fd42:fed0::2".parse().unwrap(),
            vec![Ipv4Addr::new(10, 77, 0, 1)],
            vec!["fd42:fed0::1".parse().unwrap()],
            LAB_MTU
        )
        .is_err());
    }

    #[test]
    fn random_untrusted_bytes_never_panic() {
        let policy = IpPolicy::isolated_lab();
        let mut state = 0x7e62_35bb_ca21_1001u64;
        for length in 0..1024usize {
            let mut packet = vec![0; length];
            for byte in &mut packet {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = policy.admits(&packet, Direction::ServerToClient);
            let _ = policy.admits(&packet, Direction::ClientToServer);
        }
    }
    #[test]
    fn internet_ipv4_only_requires_phone_source_and_public_destination() {
        let internet = InternetV4Policy;
        for remote in [[9, 9, 9, 9], [1, 1, 1, 1], [8, 8, 8, 8]] {
            assert!(internet.admits(&v4([10, 77, 0, 2], remote), Direction::ClientToServer));
            assert!(internet.admits(&v4(remote, [10, 77, 0, 2]), Direction::ServerToClient));
            assert!(!internet.admits(&v4(remote, [10, 77, 0, 2]), Direction::ClientToServer));
        }
        for invalid in [
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            [172, 16, 1, 1],
            [127, 0, 0, 1],
            [169, 254, 1, 2],
            [100, 64, 0, 1],
            [198, 51, 100, 7],
            [203, 0, 113, 1],
            [224, 0, 0, 1],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ] {
            assert!(!internet.admits(&v4([10, 77, 0, 2], invalid), Direction::ClientToServer));
        }
        assert!(!internet.admits(&v4([10, 77, 0, 3], [9, 9, 9, 9]), Direction::ClientToServer));
        assert!(!internet.admits(&v4([9, 9, 9, 9], [10, 77, 0, 3]), Direction::ServerToClient));
        let ipv6 = v6(
            "fd42:fed0::2".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        );
        assert!(!internet.admits(&ipv6, Direction::ClientToServer));
        let mut fragmented = v4([10, 77, 0, 2], [9, 9, 9, 9]);
        fragmented[6] = 0x20;
        assert!(!internet.admits(&fragmented, Direction::ClientToServer));
    }
}
