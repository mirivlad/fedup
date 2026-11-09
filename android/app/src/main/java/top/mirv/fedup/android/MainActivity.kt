package top.mirv.fedup.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputFilter
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream

/**
 * Offline enrollment, not a working VPN. The CSR request contains a bearer
 * invitation token: export it only to the authenticated administrator.
 */
class MainActivity : Activity() {
    private companion object {
        const val PICK_INVITE = 11
        const val SAVE_REQUEST = 12
        const val PICK_CERT = 13
        const val MAX_FILE = 32768
    }

    private val enrollment by lazy { EnrollmentManager(this) }
    private lateinit var status: TextView
    private lateinit var invitation: EditText
    private lateinit var certificate: EditText

    private fun message(value: String) { status.text = value }

    private fun showDeviceState() {
        try {
            val found = enrollment.device()
            message(when {
                found == null -> "Ключ устройства ещё не создан."
                found.enrolled -> "Сертификат " + found.device +
                    " проверен. Android VPN пока не подключён."
                else -> "Ключ устройства " + found.device +
                    " создан в Android Keystore. Ожидается сертификат.\nCA SHA-256: " +
                    found.caPin
            })
        } catch (error: Exception) {
            message("Ошибка состояния устройства: " + error.message + ". VPN отключён.")
        }
    }

    private fun label(layout: LinearLayout, value: String) {
        layout.addView(TextView(this).apply {
            text = value
            textSize = 18f
            setPadding(0, 16, 0, 8)
        })
    }

    private fun entry(layout: LinearLayout, hintText: String): EditText =
        EditText(this).apply {
            hint = hintText
            minLines = 4
            maxLines = 8
            filters = arrayOf(InputFilter.LengthFilter(MAX_FILE))
            layout.addView(this, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }

    private fun action(layout: LinearLayout, text: String, block: () -> Unit) {
        layout.addView(Button(this).apply {
            this.text = text
            setOnClickListener {
                try { block() }
                catch (error: Exception) { message("Ошибка: " + error.message) }
            }
        }, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 32, 28, 32)
        }
        label(layout, "FedUp — регистрация Android")
        layout.addView(TextView(this).apply {
            text = "Приватный ключ создаётся на телефоне и не передаётся администратору. " +
                "Это диагностическая сборка: VPN не работает и Always-on отключён."
        })
        status = TextView(this).apply { textSize = 15f; setPadding(0, 16, 0, 16) }
        layout.addView(status)

        label(layout, "1. Приглашение администратора")
        invitation = entry(layout, "Вставьте или откройте invite.json")
        action(layout, "Открыть приглашение") { pick(PICK_INVITE) }
        action(layout, "Создать ключ Android Keystore и запрос CSR") {
            val raw = invitation.text.toString()
            require(raw.isNotBlank()) { "Введите приглашение" }
            Thread {
                try {
                    val identity = enrollment.begin(raw)
                    runOnUiThread {
                        invitation.text.clear()
                        message("Создан CSR для " + identity.device +
                            ". Сверьте SHA-256 CA с администратором: " + identity.caPin)
                    }
                } catch (error: Exception) {
                    runOnUiThread { message("Запрос отклонён: " + error.message) }
                }
            }.start()
        }
        action(layout, "Сохранить request.json для администратора") {
            enrollment.pendingRequest()
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/json"
                putExtra(Intent.EXTRA_TITLE, "fedup-request.json")
            }, SAVE_REQUEST)
        }

        label(layout, "2. Подписанный сертификат от администратора")
        certificate = entry(layout, "Вставьте или откройте client.pem")
        action(layout, "Открыть сертификат") { pick(PICK_CERT) }
        action(layout, "Проверить и импортировать сертификат") {
            val pem = certificate.text.toString()
            require(pem.isNotBlank()) { "Введите сертификат" }
            Thread {
                try {
                    val identity = enrollment.finish(pem)
                    runOnUiThread {
                        certificate.text.clear()
                        message("Сертификат " + identity.device +
                            " проверен, приватный ключ остался на телефоне. " +
                            "VPN-транспорт пока не подключён.")
                    }
                } catch (error: Exception) {
                    runOnUiThread { message("Сертификат отклонён: " + error.message) }
                }
            }.start()
        }
        label(layout, "Диагностика")
        action(layout, "Проверить Rust-ядро") {
            message(if (NativePacketPolicy.available())
                "Rust-ядро доступно. Это НЕ VPN-подключение."
            else "Rust-ядро недоступно: подключение запрещено.")
        }
        setContentView(ScrollView(this).apply { addView(layout) })
        showDeviceState()
    }

    private fun pick(code: Int) {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }, code)
    }

    private fun readLimited(uri: Uri): String {
        val buffer = ByteArrayOutputStream()
        contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Невозможно открыть документ" }
            val chunk = ByteArray(4096)
            while (true) {
                val n = input.read(chunk)
                if (n < 0) break
                require(buffer.size() + n <= MAX_FILE) { "Слишком большой файл" }
                buffer.write(chunk, 0, n)
            }
        }
        return buffer.toString("UTF-8")
    }

    @Deprecated("Android platform document picker, no third-party dependencies")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        try {
            val uri = requireNotNull(data.data)
            when (requestCode) {
                PICK_INVITE -> invitation.setText(readLimited(uri))
                PICK_CERT -> certificate.setText(readLimited(uri))
                SAVE_REQUEST -> {
                    val request = enrollment.pendingRequest().toByteArray(Charsets.UTF_8)
                    require(request.size <= MAX_FILE)
                    contentResolver.openOutputStream(uri, "w").use { stream ->
                        requireNotNull(stream)
                        stream.write(request)
                        stream.flush()
                    }
                    message("Запрос сохранён. В нём есть секретный одноразовый токен. " +
                        "Передайте файл только администратору по доверенному каналу.")
                }
            }
        } catch (error: Exception) {
            message("Работа с документом не выполнена: " + error.message)
        }
    }
}
