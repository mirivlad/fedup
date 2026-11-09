package top.mirv.fedup.android

import org.junit.Assert.assertEquals
import org.junit.Test

class AccountLoginTest {
    @Test fun validServerUsesOnlyHttpsAndExpectedLoginPath() {
        assertEquals(
            "https://vpn.example.net/api/fedup/v1/login",
            AccountLogin.endpoint("vpn.example.net").toString()
        )
        assertEquals(
            "https://vpn.example.net:8443/api/fedup/v1/login",
            AccountLogin.endpoint("https://vpn.example.net:8443").toString()
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsHttpFallback() { AccountLogin.endpoint("http://vpn.example.net") }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsInjectedPath() { AccountLogin.endpoint("vpn.example.net/evil") }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsCredentialsInUrl() { AccountLogin.endpoint("admin:password@vpn.example.net") }
}
