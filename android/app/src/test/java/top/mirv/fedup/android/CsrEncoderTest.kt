package top.mirv.fedup.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class CsrEncoderTest {
    private fun bounds(data: ByteArray, at: Int): Pair<Int, Int> {
        val prefix = data[at + 1].toInt() and 255
        val headerSize: Int
        val size: Int
        when (prefix) {
            in 0..127 -> { headerSize = 2; size = prefix }
            0x81 -> { headerSize = 3; size = data[at + 2].toInt() and 255 }
            0x82 -> {
                headerSize = 4
                size = ((data[at + 2].toInt() and 255) shl 8) or
                    (data[at + 3].toInt() and 255)
            }
            else -> error("Unsupported DER length")
        }
        return Pair(at + headerSize, at + headerSize + size)
    }

    @Test fun signedPkcs10ProofOfPossessionIsValid() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val keys = generator.generateKeyPair()
        val pem = CsrEncoder.create(keys, "android-ci")
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        val der = Base64.getMimeDecoder().decode(
            pem.substringAfter("-----BEGIN CERTIFICATE REQUEST-----")
                .substringBefore("-----END CERTIFICATE REQUEST-----")
        )
        val (body, end) = bounds(der, 0)
        assertEquals(der.size, end)
        val (_, infoEnd) = bounds(der, body)
        val (_, algorithmEnd) = bounds(der, infoEnd)
        val (sigData, sigEnd) = bounds(der, algorithmEnd)
        assertEquals(der.size, sigEnd)
        assertEquals(0, der[sigData].toInt())
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(keys.public)
        verifier.update(der.copyOfRange(body, infoEnd))
        assertTrue(verifier.verify(der.copyOfRange(sigData + 1, sigEnd)))
        assertTrue(String(der, Charsets.ISO_8859_1).contains("fedup-android-ci"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun injectedDeviceNameIsRejected() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        CsrEncoder.create(generator.generateKeyPair(), "other; injected")
    }
}
