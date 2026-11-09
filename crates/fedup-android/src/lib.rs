//! JNI boundary for the experimental Android shell.
//!
//! Input is an untrusted Java byte array, never an OS file descriptor or a
//! packet capture. Reject oversized packets before copying, and enforce the
//! same immutable synthetic lab policy used by Linux.
//!
//! No VPN socket, device identity, transport, or Android routing is created.

use fedup_core::{Direction, IpPolicy, LAB_MTU};
use jni::objects::{JByteArray, JObject};
use jni::sys::jboolean;
use jni::JNIEnv;
use std::sync::OnceLock;

static POLICY: OnceLock<IpPolicy> = OnceLock::new();

fn lab_policy() -> &'static IpPolicy {
    POLICY.get_or_init(IpPolicy::isolated_lab)
}

fn admit_untrusted(packet: &[u8], client_to_server: bool) -> bool {
    if packet.len() > LAB_MTU {
        return false;
    }
    let direction = if client_to_server {
        Direction::ClientToServer
    } else {
        Direction::ServerToClient
    };
    lab_policy().admits(packet, direction)
}

/// Native bridge returns FALSE on any JNI exception, invalid data or panic.
/// It is not a VPN connection and cannot bypass a platform kill switch.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_top_mirv_fedup_android_NativePacketPolicy_nativeAdmit(
    mut env: JNIEnv<'_>,
    _receiver: JObject<'_>,
    packet: JByteArray<'_>,
    client_to_server: jboolean,
) -> jboolean {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if client_to_server > 1 {
            return 0;
        }
        let Ok(length) = env.get_array_length(&packet) else {
            return 0;
        };
        if length < 20 || length as usize > LAB_MTU {
            return 0;
        }
        let Ok(bytes) = env.convert_byte_array(&packet) else {
            return 0;
        };
        u8::from(admit_untrusted(&bytes, client_to_server != 0))
    }))
    .unwrap_or(0)
}

/// A diagnostic only: "bridge loaded" does not mean an authenticated tunnel
/// exists. The Android UI must not call this "VPN connected".
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_top_mirv_fedup_android_NativePacketPolicy_nativeBridgeReady(
    _env: JNIEnv<'_>,
    _receiver: JObject<'_>,
) -> jboolean {
    u8::from(lab_policy().mtu() == LAB_MTU)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumbo_packet_is_discarded_before_jni_copy() {
        assert!(!admit_untrusted(&vec![0_u8; LAB_MTU + 1], true));
        assert!(!admit_untrusted(&[], false));
    }

    #[test]
    fn synthetic_allowed_peer_is_directional() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[12..16].copy_from_slice(&[10, 77, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 88, 0, 10]);
        assert!(admit_untrusted(&packet, true));
        assert!(!admit_untrusted(&packet, false));
        packet[16] = 8;
        assert!(!admit_untrusted(&packet, true));
    }
}
