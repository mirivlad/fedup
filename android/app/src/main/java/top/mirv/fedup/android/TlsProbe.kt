package top.mirv.fedup.android

import android.os.Build
import okhttp3.ConnectionSpec
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.TlsVersion
import java.net.InetAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

/**
 * Diagnostic-only real HTTPS/2 and mutual TLS authorization check.
 *
 * Uses the phone's AndroidKeyStore EC private key without exporting it.
 * The server exposes GET /fedup-lab/v1/auth-check only AFTER matching the
 * client cert fingerprint against its allowlist. No TUN or VPN route exists.
 *
 * NEVER call this as a substitute for an actual protected VPN socket:
 * routing and VpnService.protect() are not implemented in this lab probe.
 */
internal object TlsProbe {
    data class Endpoint(val hostname: String, val port: Int) {
        companion object {
            fun parse(value: String): Endpoint {
                require(value.length in 3..253 && !value.contains("://"))
                val uri = URI("https://" + value)
                val host = uri.host ?: error("Expected host:port")
                require(host.isNotBlank() && uri.port in 1..65535)
                require(uri.rawUserInfo == null && uri.rawPath.isNullOrEmpty() &&
                    uri.rawQuery == null && uri.rawFragment == null) {
                    "Endpoint must have only a hostname and TCP port"
                }
                return Endpoint(host, uri.port)
            }
        }
    }

    private class DeviceKeyManager(
        private val alias: String,
        private val privateKey: PrivateKey,
        private val certificate: X509Certificate
    ) : X509ExtendedKeyManager() {
        private fun supported(types: Array<out String>?): Boolean =
            types?.any { it.equals("EC", true) || it.startsWith("EC_", true) } == true

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
            if (keyType == "EC" || keyType?.startsWith("EC_") == true) arrayOf(alias) else null

        override fun chooseClientAlias(
            keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?
        ): String? = if (supported(keyType)) alias else null

        override fun chooseEngineClientAlias(
            keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?
        ): String? = if (supported(keyType)) alias else null

        override fun getCertificateChain(name: String?): Array<X509Certificate>? =
            if (name == alias) arrayOf(certificate) else null

        override fun getPrivateKey(name: String?): PrivateKey? =
            if (name == alias) privateKey else null

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun chooseServerAlias(
            keyType: String?, issuers: Array<out Principal>?, socket: Socket?
        ): String? = null
        override fun chooseEngineServerAlias(
            keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?
        ): String? = null
    }

    fun createClient(identity: EnrollmentManager, endpointText: String, vpn: android.net.VpnService? = null, live: Boolean = false): Pair<OkHttpClient, String> {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            "Android 10 or later is needed for the TLS 1.3/ALPN diagnostic"
        }
        val device = identity.device() ?: error("Register device first")
        require(device.enrolled) { "Import the signed client certificate first" }
        val endpoint = Endpoint.parse(endpointText)

        // Verify stored CA pin and X.509 certificate even if app-private files
        // were modified since the original enrollment operation.
        val ca = identity.pinnedCa() ?: error("Missing pinned CA")
        val clientCert = identity.clientCertificate() ?: error("Missing client cert")
        ca.checkValidity()
        clientCert.checkValidity()
        clientCert.verify(ca.publicKey)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = identity.privateKeyAlias()
        val key = store.getKey(alias, null) as? PrivateKey
            ?: error("Non-exportable AndroidKeystore private key was lost")
        val localCert = store.getCertificate(alias) ?: error("Android device key is missing")
        require(java.security.MessageDigest.isEqual(
            localCert.publicKey.encoded,
            clientCert.publicKey.encoded
        )) { "Client certificate does not match device key" }

        val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("fedup-private-ca", ca)
        }
        val trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustFactory.init(anchors)
        val verifier = trustFactory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val tls = SSLContext.getInstance("TLSv1.3")
        tls.init(
            arrayOf<KeyManager>(DeviceKeyManager(alias, key, clientCert)),
            arrayOf(verifier),
            SecureRandom()
        )
        // The request URL uses the SIGNED invitation's server name, not the
        // host/IP entered for routing. Standard OkHttp HTTPS hostname checking
        // remains enabled, with a trust store containing ONLY the pinned CA.
        val safeUrl = "https://" + device.serverName + ":" + endpoint.port +
            "/fedup-lab/v1/auth-check"
        val dns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                if (hostname != device.serverName) {
                    throw UnknownHostException("Unexpected DNS name")
                }
                return InetAddress.getAllByName(endpoint.hostname).toList()
            }
        }
        val builder = OkHttpClient.Builder()
            .dns(dns)
            .proxy(Proxy.NO_PROXY)
            .sslSocketFactory(tls.socketFactory, verifier)
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .connectionSpecs(
                listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_3).build())
            )
            .retryOnConnectionFailure(false)
            .followRedirects(false)
            .followSslRedirects(false)
            .callTimeout(12, TimeUnit.SECONDS)
            .connectTimeout(6, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
        if (vpn != null) {
            // Calls VpnService.protect(socket) before OkHttp connects to the gateway.
            builder.socketFactory(ProtectedSocketFactory(vpn))
            // No DNS when full device routes are active: the experimental
            // protected connection must use an explicitly supplied numeric IPv4.
            val octets = endpoint.hostname.split(".")
            require(octets.size == 4 && octets.all {
                it.isNotEmpty() && it.all(Char::isDigit) &&
                    it.toIntOrNull() in 0..255
            }) { "Live lab transport needs numeric IPv4 endpoint, not DNS" }
        }
        if (live) {
            builder.callTimeout(0, TimeUnit.SECONDS).readTimeout(0, TimeUnit.SECONDS)
                .pingInterval(15, TimeUnit.SECONDS)
        }
        return Pair(builder.build(), safeUrl.substringBefore("/fedup-lab/"))
    }

    fun check(identity: EnrollmentManager, endpointText: String): String {
        val (client, url) = createClient(identity, endpointText)
        verifyAuthorization(client, url)
        return "Подтверждены TLS 1.3, HTTP/2, подпись сервера и допуск устройства. " +
            "VPN-туннель ещё не запущен."
    }

    fun verifyAuthorization(client: OkHttpClient, baseUrl: String) {
        val request = Request.Builder()
            .url(baseUrl + "/fedup-lab/v1/auth-check")
            .header("Cache-Control", "no-store")
            .get().build()
        // This request must terminate after 12 seconds even if a long-lived
        // transport client was supplied.
        val probe = client.newBuilder().callTimeout(12, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS).build()
        probe.newCall(request).execute().use { response ->
            require(response.protocol == Protocol.HTTP_2) {
                "Server did not negotiate actual HTTP/2"
            }
            require(response.code == 204) {
                "Server did not authorize this device (status " + response.code + ")"
            }
        }
    }
}
