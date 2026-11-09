package top.mirv.fedup.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import javax.crypto.KeyGenerator
import javax.crypto.AEADBadTagException

class EncryptedValueTest {
    @Test fun gcmCiphertextsUseIndependentNonces() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val plaintext = "temporary-credential-123".toByteArray()
        val first = EncryptedValue.encrypt(key, plaintext)
        val second = EncryptedValue.encrypt(key, plaintext)
        assertFalse(first.contentEquals(second))
        assertArrayEquals(plaintext, EncryptedValue.decrypt(key, first))
        assertArrayEquals(plaintext, EncryptedValue.decrypt(key, second))
    }

    @Test(expected = AEADBadTagException::class)
    fun tamperingNeverFallsBackToPlaintext() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val ciphertext = EncryptedValue.encrypt(key, "sufficient-password".toByteArray())
        ciphertext[ciphertext.size - 1] = (ciphertext.last().toInt() xor 1).toByte()
        EncryptedValue.decrypt(key, ciphertext)
    }
}
