package top.mirv.fedup.android

import android.app.Activity
import android.app.AlertDialog
import android.net.VpnService
import android.os.Build
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Offline enrollment, not a working VPN. The CSR request contains a bearer
 * invitation token: export it only to the authenticated administrator.
 */
class MainActivity : Activity() {
    private companion object {
        const val PICK_INVITE = 11
        const val SAVE_REQUEST = 12
        const val PICK_CERT = 13
        const val VPN_PERMISSION = 14
        const val MAX_FILE = 32768
    }

    private val enrollment by lazy { EnrollmentManager(this) }
    private var pendingLabEndpoint: String? = null
    private var pendingVpsV4 = false
    private lateinit var status: TextView
    private lateinit var invitation: EditText
    private lateinit var certificate: EditText

    private fun message(value: String) { status.text = value }

    private fun showDeviceState() {
        try {
            val found = enrollment.device()
            message(when {
                found == null -> "Добавьте сервер, логин и пароль для входа."
                found.enrolled -> "Сертификат " + found.device +
                    " проверен. Доступен экспериментальный выход IPv4 через VPS; IPv6 блокируется."
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
        label(layout, "FedUp")
        layout.addView(TextView(this).apply {
            text = "Введите сервер, логин и пароль — приложение само зарегистрирует ключ " +
                "телефона и проверит сертификат. Лабораторный VPN поддерживает " +
                "только тестовые адреса; полный интернет-туннель ещё не готов."
        })
        status = TextView(this).apply { textSize = 15f; setPadding(0, 16, 0, 16) }
        layout.addView(status)

        val prefs = getSharedPreferences("fedup_account", MODE_PRIVATE)
        val server = EditText(this).apply {
            hint = "Сервер, например vpn.example.net"
            setSingleLine(true)
            setText(prefs.getString("server", ""))
        }
        layout.addView(server, ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT)
        val login = EditText(this).apply {
            hint = "Логин"
            setSingleLine(true)
            setText(prefs.getString("username", ""))
        }
        layout.addView(login, ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT)
        val password = EditText(this).apply {
            hint = "Пароль"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(password, ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT)
        action(layout, "Войти и зарегистрировать телефон") {
            val host = server.text.toString().trim()
            val username = login.text.toString().trim()
            val secret = password.text.toString()
            require(secret.isNotBlank()) { "Введите пароль" }
            password.text.clear()
            message("Проверка учётной записи по HTTPS...")
            Thread {
                try {
                    AccountLogin.check(host, username, secret)
                    val result = AutomaticEnrollment(this).register(host, username, secret)
                    // Save credentials only after complete account and device
                    // registration. A failed enrollment is not a VPN success.
                    CredentialsVault(this).save(secret)
                    prefs.edit().putString("server", host)
                        .putString("username", username).apply()
                    runOnUiThread {
                        message(result + "\nМожно проверить IPv4 через VPS кнопкой ниже. " +
                            "IPv6 пока заблокирован; полноценные тесты защиты ещё не пройдены.")
                    }
                } catch (error: Exception) {
                    runOnUiThread {
                        message("Вход не выполнен: " + error.message)
                    }
                }
            }.start()
        }

        action(layout, "Подключиться к VPS (IPv4 + DNS, эксперимент)") {
            require(enrollment.device()?.enrolled == true) {
                "Сначала войдите и зарегистрируйте устройство"
            }
            require(NativePacketPolicy.available()) {
                "Rust-проверка пакетов недоступна"
            }
            val savedHost = prefs.getString("server", null)
                ?: error("Укажите сервер и сначала войдите")
            message("Определение IPv4 адреса VPS...")
            Thread {
                try {
                    // Resolve BEFORE establishing the TUN; protect() then
                    // ensures the real TLS socket never routes through itself.
                    val hostname = AccountLogin.endpoint(savedHost).host
                    val ipv4 = InetAddress.getAllByName(hostname)
                        .filterIsInstance<Inet4Address>().firstOrNull()
                        ?: error("У сервера нет доступного IPv4 DNS A-записи")
                    val address = ipv4.hostAddress + ":7443"
                    runOnUiThread {
                        AlertDialog.Builder(this)
                            .setTitle("Экспериментальный IPv4 VPN")
                            .setMessage(
                                "Подключение к " + address + ". Android заменит текущий VPN. " +
                                    "IPv4 и системный DNS будут направлены через FedUp. " +
                                    "IPv6 намеренно блокируется. Пока не испытана защита при " +
                                    "сбоях, НЕ используйте для конфиденциального трафика. " +
                                    "Продолжить?"
                            )
                            .setNegativeButton("Отмена", null)
                            .setPositiveButton("Подключить") { _, _ ->
                                pendingLabEndpoint = address
                                pendingVpsV4 = true
                                val permission = VpnService.prepare(this)
                                if (permission == null) {
                                    startTunnel(address, true)
                                } else {
                                    startActivityForResult(permission, VPN_PERMISSION)
                                }
                            }
                            .show()
                    }
                } catch (error: Exception) {
                    runOnUiThread { message("Нет подключения к серверу: " + error.message) }
                }
            }.start()
        }
        action(layout, "Отключиться") {
            startService(Intent(this, FedUpVpnService::class.java)
                .setAction(FedUpVpnService.STOP))
            message("Подано отключение VPN.")
        }

        val advanced = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        action(layout, "Расширенная диагностика и ручная регистрация") {
            advanced.visibility = if (advanced.visibility == View.GONE)
                View.VISIBLE else View.GONE
        }
        layout.addView(advanced)
        label(advanced, "1. Приглашение администратора")
        invitation = entry(advanced, "Вставьте или откройте invite.json")
        action(advanced, "Открыть приглашение") { pick(PICK_INVITE) }
        action(advanced, "Создать ключ Android Keystore и запрос CSR") {
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
        action(advanced, "Сохранить request.json для администратора") {
            enrollment.pendingRequest()
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/json"
                putExtra(Intent.EXTRA_TITLE, "fedup-request.json")
            }, SAVE_REQUEST)
        }

        label(advanced, "2. Подписанный сертификат от администратора")
        certificate = entry(advanced, "Вставьте или откройте client.pem")
        action(advanced, "Открыть сертификат") { pick(PICK_CERT) }
        action(advanced, "Проверить и импортировать сертификат") {
            val pem = certificate.text.toString()
            require(pem.isNotBlank()) { "Введите сертификат" }
            Thread {
                try {
                    val identity = enrollment.finish(pem)
                    runOnUiThread {
                        certificate.text.clear()
                        message("Сертификат " + identity.device +
                            " проверен, приватный ключ остался на телефоне. " +
                            "Лабораторный VPN можно проверить после подключения к тестовому серверу.")
                    }
                } catch (error: Exception) {
                    runOnUiThread { message("Сертификат отклонён: " + error.message) }
                }
            }.start()
        }
        label(advanced, "3. Проверка взаимной TLS-аутентификации")
        advanced.addView(TextView(this).apply {
            text = "Введите адрес FedUp-сервера и порт, например 192.168.1.10:7443. " +
                "Имя TLS и доверенный CA берутся только из приглашения. " +
                "Этот тест не создаёт VPN и не меняет маршруты."
        })
        val endpoint = EditText(this).apply {
            hint = "server-address:7443"
            setSingleLine(true)
            filters = arrayOf(InputFilter.LengthFilter(253))
        }
        advanced.addView(endpoint, ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT)
        action(advanced, "Проверить TLS 1.3, HTTP/2 и допуск устройства") {
            val address = endpoint.text.toString().trim()
            require(address.isNotBlank()) { "Введите адрес сервера" }
            Thread {
                try {
                    val result = TlsProbe.check(enrollment, address)
                    runOnUiThread { message(result) }
                } catch (error: Exception) {
                    runOnUiThread { message("Сервер не подтвердил устройство: " + error.message) }
                }
            }.start()
        }
        action(advanced, "Лаб: подключить только тестовые IP (не защищает Интернет)") {
            val address = endpoint.text.toString().trim()
            require(enrollment.device()?.enrolled == true) {
                "Сначала получите сертификат устройства"
            }
            require(NativePacketPolicy.available()) { "Rust-модуль недоступен" }
            TlsProbe.Endpoint.parse(address)
            AlertDialog.Builder(this)
                .setTitle("Только лабораторный VPN")
                .setMessage(
                    "Android заменит действующий VPN на FedUp LAB. " +
                        "В туннель попадут только 10.77.0.1, 10.88.0.10 и два " +
                        "IPv6-адреса. Весь остальной Интернет и DNS останутся " +
                        "без защиты FedUp. Используйте только на тестовом устройстве."
                )
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Продолжить") { _, _ ->
                    pendingLabEndpoint = address
                    pendingVpsV4 = false
                    val permission = VpnService.prepare(this)
                    if (permission == null) startTunnel(address, false)
                    else startActivityForResult(permission, VPN_PERMISSION)
                }
                .show()
        }
        action(advanced, "Отключить лабораторный VPN") {
            startService(Intent(this, FedUpVpnService::class.java)
                .setAction(FedUpVpnService.STOP))
            message("Запрошено отключение лабораторного VPN.")
        }
        label(advanced, "Диагностика")
        action(advanced, "Проверить Rust-ядро") {
            message(if (NativePacketPolicy.available())
                "Rust-ядро доступно. Это НЕ VPN-подключение."
            else "Rust-ядро недоступно: подключение запрещено.")
        }
        setContentView(ScrollView(this).apply { addView(layout) })
        showDeviceState()
    }

    private fun startTunnel(address: String, internetV4: Boolean) {
        val command = Intent(this, FedUpVpnService::class.java)
            .setAction(if (internetV4) FedUpVpnService.START_VPS_V4
                else FedUpVpnService.START)
            .putExtra(FedUpVpnService.ENDPOINT, address)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(command)
        } else {
            startService(command)
        }
        message(if (internetV4)
            "Подключение к VPS запускается. IPv4/DNS в туннеле, IPv6 заблокирован. " +
                "Проверяйте публичный IP и статус в уведомлении Android."
            else "Запускается лабораторный туннель. Интернет не защищён.")
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
        if (requestCode == VPN_PERMISSION) {
            val address = pendingLabEndpoint
            pendingLabEndpoint = null
            val vps = pendingVpsV4
            pendingVpsV4 = false
            if (resultCode == RESULT_OK && address != null) {
                startTunnel(address, vps)
            } else {
                message("Разрешение VPN не предоставлено: подключение отменено.")
            }
            return
        }
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
