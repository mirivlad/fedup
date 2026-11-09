package top.mirv.fedup.android

/**
 * Preconditions to creating an Android VPN interface.
 *
 * NONE of the transport / certificate verification predicates is implemented
 * by this Android lab application yet. FedUpVpnService never establishes TUN.
 */
internal object VpnActivationGate {
    fun mayEstablish(
        systemConsent: Boolean,
        authenticatedServer: Boolean,
        authorizedDevice: Boolean,
        nativePacketPolicy: Boolean,
        verifiedRoutesAndDns: Boolean
    ): Boolean =
        systemConsent && authenticatedServer && authorizedDevice &&
            nativePacketPolicy && verifiedRoutesAndDns
}
