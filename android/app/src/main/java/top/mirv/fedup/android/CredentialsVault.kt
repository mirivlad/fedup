package top.mirv.fedup.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Standard AES-GCM with random nonce and authenticated ciphertext. */
internal object EncryptedValue {
    fun encrypt(key: SecretKey, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.size == 12) { "Unsupported GCM nonce size" }
        return iv + cipher.doFinal(plaintext)
    }

    fun decrypt(key: SecretKey, encoded: ByteArray): ByteArray {
        require(encoded.size in 29..2048) { "Invalid encrypted credential size" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encoded.copyOfRange(0, 12)))
        return cipher.doFinal(encoded.copyOfRange(12, encoded.size))
    }
}

/**
 * No plaintext credential file or fallback. AES key never leaves AndroidKeyStore.
 * Only the AES-GCM ciphertext is kept in app-private preferences (backup off).
 * This will be replaced with short-lived device credentials when online
 * first-use enrollment becomes available.
 */
internal class CredentialsVault(private val context: Context) {
    private companion object {
        const val ALIAS = "fedup-account-aes-gcm-v1"
        const val PREFS = "fedup_encrypted_account"
        const val FIELD = "ciphertext"
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = store.getKey(ALIAS, null)
        if (existing != null) {
            return existing as? SecretKey ?: error("Invalid Android account key type")
        }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return generator.generateKey()
    }

    fun save(password: String) {
        val raw = password.toByteArray(Charsets.UTF_8)
        try {
            require(raw.size in 1..128) { "Invalid credential length" }
            val data = EncryptedValue.encrypt(key(), raw)
            val text = Base64.encodeToString(data, Base64.NO_WRAP)
            check(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putString(FIELD, text).commit()) { "Cannot save encrypted credentials" }
        } finally {
            raw.fill(0)
        }
    }

    fun read(): String {
        val text = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(FIELD, null) ?: error("No saved account credentials")
        val raw = Base64.decode(text, Base64.NO_WRAP)
        val decrypted = EncryptedValue.decrypt(key(), raw)
        return try {
            decrypted.toString(Charsets.UTF_8)
        } finally {
            decrypted.fill(0)
        }
    }

    fun clear() {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().remove(FIELD).commit()
    }
}
