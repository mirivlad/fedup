package top.mirv.fedup.android

/**
 * Fail-closed bridge to the real Rust fedup-core IP admission policy.
 *
 * The bridge only checks packets for the fixed synthetic test topology.
 * Loading it does NOT establish a VPN or authorize any network connection.
 */
object NativePacketPolicy {
    private val loaded: Boolean by lazy {
        try {
            System.loadLibrary("fedup_android")
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    private external fun nativeBridgeReady(): Boolean
    private external fun nativeAdmit(packet: ByteArray, clientToServer: Boolean): Boolean

    fun available(): Boolean = loaded && try {
        nativeBridgeReady()
    } catch (_: UnsatisfiedLinkError) {
        false
    } catch (_: SecurityException) {
        false
    }

    fun admits(packet: ByteArray, clientToServer: Boolean): Boolean {
        if (!available() || packet.size !in 20..1280) return false
        return try {
            nativeAdmit(packet, clientToServer)
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: SecurityException) {
            false
        }
    }
}
