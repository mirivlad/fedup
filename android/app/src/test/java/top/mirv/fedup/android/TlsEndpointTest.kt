package top.mirv.fedup.android

import org.junit.Assert.assertEquals
import org.junit.Test

class TlsEndpointTest {
    @Test fun acceptsExplicitHostAndPortWithoutMutatingTlsName() {
        val endpoint = TlsProbe.Endpoint.parse("192.168.1.141:7443")
        assertEquals("192.168.1.141", endpoint.hostname)
        assertEquals(7443, endpoint.port)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMissingPort() {
        TlsProbe.Endpoint.parse("192.168.1.141")
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesUnexpectedUrlPath() {
        TlsProbe.Endpoint.parse("vpn.example:7443/other")
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesEmbeddedScheme() {
        TlsProbe.Endpoint.parse("https://vpn.example:7443")
    }
}
