package top.mirv.fedup.android

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * First-stage account authentication. HTTPS certificate and hostname checks
 * are performed by the OS / OkHttp. No TOFU, cleartext or disabled TLS checks.
 *
 * HTTP 204 proves only that credentials are valid. Device registration and
 * VPN authorization are DIFFERENT steps and are not claimed here.
 */
internal object AccountLogin {
    private val jsonType = "application/json; charset=utf-8".toMediaType()
    private val client = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .callTimeout(15, TimeUnit.SECONDS)
        .build()

    fun endpoint(text: String): HttpUrl {
        val input = text.trim()
        require(input.length in 3..253 && !input.contains("@")) {
            "Введите домен HTTPS-сервера"
        }
        val url = (if (input.contains("://")) input else "https://" + input)
            .toHttpUrlOrNull() ?: error("Неверный адрес сервера")
        require(url.scheme == "https" && url.username.isEmpty()
            && url.password.isEmpty() && url.encodedPath == "/"
            && url.query == null && url.fragment == null) {
            "Допускается только HTTPS-домен и необязательный порт"
        }
        return url.newBuilder()
            .addPathSegments("api/fedup/v1/login")
            .build()
    }

    data class Config(
        val serverName: String,
        val caPem: String,
        val caSha256: String,
    )

    data class Certificate(
        val certificatePem: String,
        val caSha256: String,
        val serverName: String,
    )

    private fun limitedBody(response: okhttp3.Response): String {
        val source = response.body?.byteStream() ?: error("Missing server response")
        val buffer = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(4096)
        while (true) {
            val n = source.read(chunk)
            if (n < 0) break
            require(buffer.size() + n <= 32768) { "Server response exceeds limit" }
            buffer.write(chunk, 0, n)
        }
        return buffer.toString("UTF-8")
    }

    fun config(server: String): Config {
        val request = Request.Builder()
            .url(endpoint(server).newBuilder().encodedPath("/api/fedup/v1/config").build())
            .header("Cache-Control", "no-store")
            .get().build()
        client.newCall(request).execute().use { response ->
            require(response.code == 200) {
                "Server does not provide automatic enrollment (HTTP " + response.code + ")"
            }
            val json = JSONObject(limitedBody(response))
            return Config(
                json.getString("server_name"),
                json.getString("ca_pem"),
                json.getString("ca_sha256"),
            )
        }
    }

    fun enroll(
        server: String,
        username: String,
        password: String,
        device: String,
        csrPem: String
    ): Certificate {
        require(username.matches(Regex("[a-z0-9._-]{1,48}")))
        require(device.matches(Regex("[A-Za-z0-9._-]{1,48}")))
        require(password.toByteArray(Charsets.UTF_8).size in 1..128)
        require(csrPem.length in 1..8192)
        val body = JSONObject()
            .put("username", username)
            .put("password", password)
            .put("device", device)
            .put("csr_pem", csrPem)
            .toString().toRequestBody(jsonType)
        val request = Request.Builder()
            .url(endpoint(server).newBuilder().encodedPath("/api/fedup/v1/devices").build())
            .header("Cache-Control", "no-store")
            .post(body).build()
        client.newCall(request).execute().use { response ->
            if (response.code == 401) error("Неверный логин или пароль")
            if (response.code == 429) error("Слишком много попыток, повторите позднее")
            if (response.code == 409) error("Имя устройства занято или учётная запись изменена")
            require(response.code == 201) {
                "Регистрация устройства отклонена (HTTP " + response.code + ")"
            }
            val json = JSONObject(limitedBody(response))
            return Certificate(
                json.getString("certificate_pem"),
                json.getString("ca_sha256"),
                json.getString("server_name"),
            )
        }
    }

    fun check(server: String, username: String, password: String) {
        require(username.matches(Regex("[a-z0-9._-]{1,48}"))) {
            "Логин должен содержать строчные латинские буквы и цифры"
        }
        require(password.toByteArray(Charsets.UTF_8).size in 1..128) {
            "Введите пароль"
        }
        val payload = JSONObject()
            .put("username", username)
            .put("password", password)
            .toString()
            .toRequestBody(jsonType)
        val request = Request.Builder()
            .url(endpoint(server))
            .header("Cache-Control", "no-store")
            .post(payload)
            .build()
        client.newCall(request).execute().use { response ->
            if (response.code == 204) return
            if (response.code == 401) error("Неверный логин или пароль")
            if (response.code == 429) error("Слишком много попыток. Повторите позже.")
            error("Сервер не подтвердил авторизацию (HTTP " + response.code + ")")
        }
    }
}
