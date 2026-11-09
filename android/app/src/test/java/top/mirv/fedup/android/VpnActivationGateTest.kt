package top.mirv.fedup.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnActivationGateTest {
    private fun check(flags: List<Boolean>) = VpnActivationGate.mayEstablish(
        systemConsent = flags[0],
        authenticatedServer = flags[1],
        authorizedDevice = flags[2],
        nativePacketPolicy = flags[3],
        verifiedRoutesAndDns = flags[4]
    )

    @Test
    fun everyPreconditionMustHold() {
        assertTrue(check(List(5) { true }))
        for (missing in 0..4) {
            assertFalse(check(List(5) { it != missing }))
        }
        assertFalse(check(List(5) { false }))
    }

    @Test
    fun consentAloneMustNeverStartAnUnverifiedTunnel() {
        assertFalse(check(listOf(true, false, false, true, false)))
        assertFalse(check(listOf(true, true, false, true, true)))
        assertFalse(check(listOf(true, true, true, true, false)))
    }
}
