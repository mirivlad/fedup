package top.mirv.fedup.android

import android.content.Context
import org.json.JSONObject
import java.security.SecureRandom

/**
 * The public three-field account UX now creates and enrolls a real device
 * identity without asking the user to export/import CSR or PEM files.
 *
 * State is scoped to a single HTTPS server + username. A failed network
 * request is safe to retry: the same Keystore key and CSR remain pending.
 * No public/private key material is backed up or transmitted.
 */
internal class AutomaticEnrollment(private val context: Context) {
    private val identity = EnrollmentManager(context)
    private val prefs = context.getSharedPreferences("fedup_automatic_device", Context.MODE_PRIVATE)

    private fun hex(size: Int): String {
        val raw = ByteArray(size)
        SecureRandom().nextBytes(raw)
        return raw.joinToString("") { "%02x".format(it) }
    }

    fun register(server: String, user: String, password: String): String {
        val canonical = AccountLogin.endpoint(server)
            .newBuilder().encodedPath("/").build().toString()
        require(user.matches(Regex("[a-z0-9._-]{1,48}")))
        val savedUser = prefs.getString("user", null)
        val savedServer = prefs.getString("server", null)
        if (savedUser != null || savedServer != null) {
            require(savedUser == user && savedServer == canonical) {
                "Устройство привязано к другому серверу или пользователю."
            }
        }
        val existing = identity.device()
        if (existing?.enrolled == true) {
            require(savedUser == user && savedServer == canonical) {
                "Обнаружена ручная регистрация другого устройства"
            }
            return "Устройство уже зарегистрировано: " + existing.device
        }
        if (existing == null) {
            val conf = AccountLogin.config(server, user, password)
            // This CA arrives on an authenticated, public-trust HTTPS
            // connection. EnrollmentManager also verifies its DER SHA-256.
            val invitation = JSONObject()
                .put("version", 1)
                .put("id", hex(16))
                .put("token", hex(32))
                .put("device", "android-" + hex(5))
                .put("expires_at", System.currentTimeMillis() / 1000 + 600)
                .put("server_name", conf.serverName)
                .put("ca_sha256", conf.caSha256)
                .put("ca_pem", conf.caPem)
            // Mark account ownership before generating the Keystore key:
            // if we crash, another account cannot silently take the key.
            require(prefs.edit().putString("user", user)
                .putString("server", canonical).commit()) {
                "Не удалось сохранить принадлежность устройства"
            }
            identity.begin(invitation.toString())
        }
        val device = identity.device() ?: error("Не создан ключ телефона")
        val pending = JSONObject(identity.pendingRequest())
        require(pending.getString("device") == device.device) {
            "Запрос на сертификат не совпадает с ключом телефона"
        }
        val result = AccountLogin.enroll(
            server, user, password, device.device, pending.getString("csr_pem")
        )
        require(result.caSha256 == device.caPin &&
            result.serverName == device.serverName) {
            "Сервер изменил доверенный CA или имя TLS"
        }
        val saved = identity.finish(result.certificatePem)
        check(saved.enrolled) { "Сертификат не установлен" }
        return "Устройство " + saved.device +
            " автоматически зарегистрировано; приватный ключ остался в Android Keystore."
    }
}
