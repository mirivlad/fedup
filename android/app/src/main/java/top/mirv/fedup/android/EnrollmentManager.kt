package top.mirv.fedup.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.security.auth.x500.X500Principal

/**
 * Offline device enrollment: only the signed CSR and a one-time token are
 * returned to the issuer. Private P-256 key is non-exportable AndroidKeyStore.
 * Invitation authenticity relies on verified out-of-band operator delivery.
 */
internal class EnrollmentManager(private val context: Context) {
    companion object {
        private const val MAX_TEXT = 32768
        private const val STATE = "device-metadata.json"
        private const val REQUEST = "pending-request.json"
        private const val CERT = "client.pem"
        private val hex32 = Regex("[a-fA-F0-9]{32}")
        private val hex64 = Regex("[a-fA-F0-9]{64}")
        private val devicePattern = Regex("[A-Za-z0-9._-]{1,48}")
        private val serverPattern = Regex("[A-Za-z0-9.-]{1,253}")

        private fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }

        private fun certificate(pem: String): X509Certificate {
            require(pem.length in 1..MAX_TEXT) { "Certificate size is invalid" }
            val match = Regex(
                "\\A-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\s]+)" +
                    "-----END CERTIFICATE-----\\s*\\z"
            ).matchEntire(pem) ?: error("Exactly one PEM certificate is required")
            val data = Base64.getMimeDecoder().decode(match.groupValues[1])
            require(data.size in 1..MAX_TEXT) { "Certificate DER is too large" }
            return CertificateFactory.getInstance("X.509")
                .generateCertificate(data.inputStream()) as X509Certificate
        }
    }

    data class Device(
        val device: String, val serverName: String, val caPin: String, val enrolled: Boolean
    )

    private fun file(name: String): File = File(context.filesDir, name)
    private val keyStore get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun keyAlias(id: String) = "fedup-device-$id"

    private fun metadata(): JSONObject? = file(STATE).let {
        if (it.exists()) JSONObject(it.readText(Charsets.UTF_8)) else null
    }

    fun device(): Device? = metadata()?.let {
        Device(
            it.getString("device"),
            it.getString("server_name"),
            it.getString("ca_sha256"),
            file(CERT).isFile
        )
    }

    /** Return the pinned CA fingerprint to display/compare with the operator. */
    fun begin(invitationJson: String): Device {
        require(invitationJson.length in 1..MAX_TEXT) { "Invitation exceeds size limit" }
        require(metadata() == null && !file(REQUEST).exists() && !file(CERT).exists()) {
            "Device already exists; refusing replacement of its identity"
        }
        val invite = JSONObject(invitationJson)
        require(invite.getInt("version") == 1) { "Unsupported invitation" }
        val id = invite.getString("id")
        val token = invite.getString("token")
        val name = invite.getString("device")
        val server = invite.getString("server_name")
        val caPin = invite.getString("ca_sha256").lowercase()
        val caPem = invite.getString("ca_pem")
        require(hex32.matches(id) && hex64.matches(token))
        require(devicePattern.matches(name) && serverPattern.matches(server))
        require(hex64.matches(caPin))
        require(System.currentTimeMillis() / 1000 < invite.getLong("expires_at")) {
            "Invitation expired"
        }
        val ca = certificate(caPem)
        ca.checkValidity()
        require(ca.basicConstraints >= 0) { "Invitation certificate is not a CA" }
        require(sha256(ca.encoded) == caPin) { "Invitation CA fingerprint mismatch" }

        val alias = keyAlias(id)
        require(!keyStore.containsAlias(alias)) { "Existing Keystore device key" }
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateSubject(X500Principal("CN=fedup-$name"))
                .setUserAuthenticationRequired(false)
                .build()
        )
        val pair = generator.generateKeyPair()
        try {
            val csr = CsrEncoder.create(pair, name)
            val request = JSONObject()
                .put("version", 1).put("id", id)
                .put("token", token).put("device", name)
                .put("server_name", server).put("ca_sha256", caPin)
                .put("csr_pem", csr)
            val state = JSONObject()
                .put("version", 1).put("id", id)
                .put("device", name).put("server_name", server)
                .put("ca_sha256", caPin).put("ca_pem", caPem)

            // State and request are app-private and excluded from Android backup.
            // Only create new files; never silently replace an existing identity.
            val requestTemp = file("$REQUEST.tmp")
            val stateTemp = file("$STATE.tmp")
            requestTemp.writeText(request.toString(2), Charsets.UTF_8)
            stateTemp.writeText(state.toString(2), Charsets.UTF_8)
            check(requestTemp.renameTo(file(REQUEST))) { "Cannot save request" }
            check(stateTemp.renameTo(file(STATE))) { "Cannot save device identity" }
            return Device(name, server, caPin, false)
        } catch (error: Exception) {
            keyStore.deleteEntry(alias)
            for (nameToDelete in arrayOf(REQUEST, STATE, "$REQUEST.tmp", "$STATE.tmp")) {
                file(nameToDelete).delete()
            }
            throw error
        }
    }

    fun pendingRequest(): String {
        require(metadata() != null && !file(CERT).exists()) { "No pending enrollment" }
        val request = file(REQUEST)
        require(request.isFile && request.length() <= MAX_TEXT) { "Missing request" }
        return request.readText(Charsets.UTF_8)
    }

    fun finish(pem: String): Device {
        require(!file(CERT).exists()) { "Certificate already imported" }
        val state = metadata() ?: error("No pending device identity")
        require(state.getInt("version") == 1)
        val ca = certificate(state.getString("ca_pem"))
        require(sha256(ca.encoded) == state.getString("ca_sha256")) {
            "Stored CA fingerprint changed"
        }
        ca.checkValidity()
        val signed = certificate(pem)
        signed.checkValidity()
        signed.verify(ca.publicKey)
        require(signed.basicConstraints == -1) { "Issuer supplied a CA, not a client cert" }
        require(signed.extendedKeyUsage?.contains("1.3.6.1.5.5.7.3.2") == true) {
            "Client authentication EKU missing"
        }
        require(signed.keyUsage?.getOrNull(0) == true) {
            "Client digital signature usage missing"
        }
        val alias = keyAlias(state.getString("id"))
        val local = keyStore.getCertificate(alias) ?: error("Android device key is missing")
        require(MessageDigest.isEqual(signed.publicKey.encoded, local.publicKey.encoded)) {
            "Signed certificate does not correspond to the phone's private key"
        }
        val expectedSubject = X500Principal("CN=fedup-" + state.getString("device"))
        require(signed.subjectX500Principal == expectedSubject) {
            "Certificate is issued for another device"
        }

        check(file(CERT).createNewFile()) { "Refusing overwrite" }
        try {
            file(CERT).writeText(pem.trim() + "\n", Charsets.UTF_8)
            // This request includes a bearer token. Remove it after successful issuance.
            file(REQUEST).delete()
        } catch (error: Exception) {
            file(CERT).delete()
            throw error
        }
        return device() ?: error("Device metadata vanished")
    }

    fun clientCertificate(): X509Certificate? =
        if (file(CERT).isFile) certificate(file(CERT).readText(Charsets.UTF_8)) else null

    fun pinnedCa(): X509Certificate? =
        metadata()?.let { certificate(it.getString("ca_pem")) }

    fun privateKeyAlias(): String =
        keyAlias(metadata()?.getString("id") ?: error("Device is not registered"))
}
