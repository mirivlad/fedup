package top.mirv.fedup.android

import java.security.KeyPair
import java.security.Signature
import java.util.Base64

/** PKCS#10 CSR signed by AndroidKeyStore P-256; the private key never leaves Keystore. */
internal object CsrEncoder {
    private fun derLength(size: Int): ByteArray {
        require(size in 0..65535)
        return when {
            size < 128 -> byteArrayOf(size.toByte())
            size <= 255 -> byteArrayOf(0x81.toByte(), size.toByte())
            else -> byteArrayOf(0x82.toByte(), (size ushr 8).toByte(), size.toByte())
        }
    }
    private fun der(tag: Int, body: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + derLength(body.size) + body

    private fun seq(vararg parts: ByteArray): ByteArray =
        der(0x30, parts.fold(ByteArray(0)) { acc, data -> acc + data })

    fun create(keyPair: KeyPair, device: String): String {
        require(device.matches(Regex("[A-Za-z0-9._-]{1,48}")))
        val name = seq(der(0x31, seq(
            der(0x06, byteArrayOf(0x55, 0x04, 0x03)),
            der(0x0c, ("fedup-" + device).toByteArray(Charsets.UTF_8))
        )))
        val requestInfo = seq(
            der(0x02, byteArrayOf(0)), name, keyPair.public.encoded,
            der(0xa0, ByteArray(0))
        )
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(keyPair.private)
        signer.update(requestInfo)
        val signature = signer.sign()
        val ecdsaSha256 = seq(der(0x06, byteArrayOf(
            0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x04, 0x03, 0x02
        )))
        val binary = seq(requestInfo, ecdsaSha256, der(0x03, byteArrayOf(0) + signature))
        val text = Base64.getMimeEncoder(64, byteArrayOf('\n'.code.toByte()))
            .encodeToString(binary)
        return "-----BEGIN CERTIFICATE REQUEST-----\n$text\n-----END CERTIFICATE REQUEST-----\n"
    }
}
