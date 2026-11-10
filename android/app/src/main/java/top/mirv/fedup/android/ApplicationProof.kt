package top.mirv.fedup.android

import android.net.VpnService
import okhttp3.ConnectionSpec
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.TlsVersion
import java.net.InetAddress
import java.net.Proxy
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Normal HTTPS/2 to a trusted Caddy edge; no TLS client certificate.
 * Key possession is proven inside HTTP with a non-exportable AndroidKeyStore key.
 * The server checks the signed certificate, its chain, nonce and live revocation.
 */
internal object ApplicationProof {
    private const val PROBE = "/fedup-lab/v1/auth-check"
    private const val TUNNEL = "/fedup-lab/v1/ip-tunnel"
    private val noncePattern = Regex("[A-Za-z0-9_-]{43}")

    fun createClient(
        identity: EnrollmentManager,
        endpointText: String,
        vpn: VpnService,
    ): Pair<OkHttpClient, String> {
        val endpoint = TlsProbe.Endpoint.parse(endpointText)
        require(endpoint.port == 443) { "Application proof requires HTTPS TCP 443" }
        val device = identity.device() ?: error("Device identity is missing")
        require(device.enrolled) { "Device not enrolled" }
        val ca = identity.pinnedCa() ?: error("Missing pinned device CA")
        val cert = identity.clientCertificate() ?: error("Missing device cert")
        ca.checkValidity()
        cert.checkValidity()
        cert.verify(ca.publicKey)
        require(cert.extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.2") == true)
        require(cert.keyUsage?.getOrNull(0) == true)
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = identity.privateKeyAlias()
        val key = keystore.getKey(alias, null) as? PrivateKey
            ?: error("Device Keystore key missing")
        require(MessageDigest.isEqual(
            cert.publicKey.encoded,
            keystore.getCertificate(alias)?.publicKey?.encoded ?: ByteArray(0)
        )) { "Device certificate and Keystore key do not match" }
        require(key.algorithm.equals("EC", ignoreCase = true))
        val dns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                if (hostname != device.serverName) {
                    throw UnknownHostException("Unexpected HTTPS hostname")
                }
                val octets = endpoint.hostname.split(".")
                require(octets.size == 4 && octets.all {
                    it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255
                }) { "Protected VPN connection requires numeric IPv4" }
                return InetAddress.getAllByName(endpoint.hostname).toList()
            }
        }
        val client = OkHttpClient.Builder()
            .dns(dns)
            .proxy(Proxy.NO_PROXY)
            .socketFactory(ProtectedSocketFactory(vpn))
            // No X509KeyManager and no private CA trusted by public TLS.
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3).build()))
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .callTimeout(0, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .connectTimeout(6, TimeUnit.SECONDS)
            .pingInterval(15, TimeUnit.SECONDS)
            .build()
        return Pair(client, "https://${device.serverName}:443")
    }

    /** Exactly one server-generated nonce for each signed HTTP request. */
    fun signedRequest(
        identity: EnrollmentManager,
        client: OkHttpClient,
        baseUrl: String,
        method: String,
        path: String,
    ): Request.Builder {
        require((method == "GET" && path == PROBE) ||
            (method == "POST" && path == TUNNEL)) {
            "Unsupported proof purpose"
        }
        val cert = identity.clientCertificate() ?: error("No signed device identity")
        val ca = identity.pinnedCa() ?: error("No pinned issuer")
        ca.checkValidity()
        cert.checkValidity()
        cert.verify(ca.publicKey)
        val certDer = cert.encoded
        val fp = MessageDigest.getInstance("SHA-256").digest(certDer)
            .joinToString("") { "%02x".format(it) }
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .getKey(identity.privateKeyAlias(), null) as? PrivateKey
            ?: error("Device Keystore key unavailable")
        val encoder = Base64.getUrlEncoder().withoutPadding()
        fun sign(message: String): String {
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(key)
            signer.update(message.toByteArray(Charsets.UTF_8))
            return encoder.encodeToString(signer.sign())
        }
        // Prove possession of the existing Keystore key BEFORE a server
        // challenge is issued. Anonymous GET / receives exactly the same
        // page but no special Set-Cookie; no public challenge oracle.
        val initBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val initNonce = encoder.encodeToString(initBytes)
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val initPayload = "FedUp-App-Init-v1\nGET\n/assets/site.js\n$initNonce\n$timestamp\n$fp\n"
        val page = Request.Builder().url("$baseUrl/assets/site.js")
            .header("x-device-init", initNonce)
            .header("x-device-time", timestamp)
            .header("x-device-certificate", encoder.encodeToString(certDer))
            .header("x-device-proof", sign(initPayload))
            .header("Cache-Control", "no-store").get().build()
        val nonce = client.newBuilder().callTimeout(12, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS).build()
            .newCall(page).execute().use { result ->
                require(result.protocol == Protocol.HTTP_2 && result.code == 200) {
                    "HTTPS/2 edge did not provide a web session"
                }
                val cookie = result.header("Set-Cookie")?.substringBefore(";")
                    ?: error("Device initiation was not accepted")
                require(cookie.startsWith("visitor_session="))
                val value = cookie.removePrefix("visitor_session=")
                require(noncePattern.matches(value))
                value
            }
        val payload = "FedUp-App-Proof-v1\n$method\n$path\n$nonce\n$fp\n"
        val signature = sign(payload)
        return Request.Builder().url(baseUrl + path)
            .header("Cookie", "visitor_session=$nonce")
            .header("x-device-certificate", encoder.encodeToString(certDer))
            .header("x-device-proof", signature)
            .header("Cache-Control", "no-store")
    }

    fun verifyAuthorization(
        identity: EnrollmentManager,
        client: OkHttpClient,
        baseUrl: String,
    ) {
        val req = signedRequest(identity, client, baseUrl, "GET", PROBE).get().build()
        client.newBuilder().callTimeout(12, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS).build()
            .newCall(req).execute().use { reply ->
                require(reply.protocol == Protocol.HTTP_2 && reply.code == 204) {
                    "Server rejected signed device proof (HTTP ${reply.code})"
                }
            }
    }
}
