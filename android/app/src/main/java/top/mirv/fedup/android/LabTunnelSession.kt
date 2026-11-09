package top.mirv.fedup.android

import android.net.VpnService
import android.os.ParcelFileDescriptor
import okhttp3.Call
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Narrowly scoped Android TUN ↔ genuine HTTP/2 experiment.
 *
 * NOT a full VPN: only 10.77.0.1, 10.88.0.10, fd42:fed0::1,
 * and fd42:fed1::10 enter TUN. DNS and ordinary Internet remain outside.
 * This is for a private lab, never for privacy/security-sensitive browsing.
 */
internal class LabTunnelSession(
    private val service: VpnService,
    private val identity: EnrollmentManager,
    private val endpoint: String,
    private val internetV4: Boolean,
    private val onReady: () -> Unit
) {
    @Volatile private var stopped = false
    @Volatile private var call: Call? = null
    @Volatile private var tun: ParcelFileDescriptor? = null

    fun stop() {
        stopped = true
        call?.cancel()
        try { tun?.close() } catch (_: IOException) { }
    }

    fun run() {
        check(android.net.VpnService.prepare(service) == null) {
            "Android system VPN consent has not been granted"
        }
        check(NativePacketPolicy.available()) { "Native Rust IP policy unavailable" }
        check(identity.device()?.enrolled == true) { "No enrolled client certificate" }

        // The upstream socket is protected BEFORE connecting. The server
        // authenticates this client in a separate HTTP/2 204 probe.
        val (client, baseUrl) = TlsProbe.createClient(identity, endpoint, service, live = true)
        try {
            TlsProbe.verifyAuthorization(client, baseUrl)
            check(!stopped && android.net.VpnService.prepare(service) == null) {
                "VPN permission revoked during authentication"
            }

            // A separate opt-in IPv4-only VPS session. The Android TUN
            // captures all IPv4 traffic, including DNS, while IPv6 packets
            // are routed into the TUN and deliberately discarded. No IPv6
            // packet can be forwarded until real IPv6 egress is implemented.
            val builder = service.Builder()
                .setSession(if (internetV4) "FedUp VPS IPv4 (experimental)"
                    else "FedUp LAB — no Internet protection")
                .setMtu(PacketCodec.MTU)
                .setBlocking(true)
            if (internetV4) {
                builder.addAddress("10.77.0.2", 30)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1")
                    .addAddress("fd42:fed0::2", 128)
                    .addRoute("::", 0)
            } else {
                builder.addAddress("10.77.0.2", 30)
                    .addRoute("10.77.0.1", 32)
                    .addRoute("10.88.0.10", 32)
                    .addAddress("fd42:fed0::2", 64)
                    .addRoute("fd42:fed0::1", 128)
                    .addRoute("fd42:fed1::10", 128)
            }
            val fd = builder.establish()
                ?: error("Android refused to establish the VPN interface")
            tun = fd

            val read = FileInputStream(fd.fileDescriptor)
            val write = FileOutputStream(fd.fileDescriptor)
            val requestBody = object : RequestBody() {
                private val binaryType: MediaType =
                    "application/vnd.fedup.ip-packets".toMediaType()

                override fun contentType(): MediaType = binaryType
                override fun isDuplex(): Boolean = true

                override fun writeTo(sink: BufferedSink) {
                    val buf = ByteArray(PacketCodec.MTU)
                    while (!stopped) {
                        val count = try { read.read(buf) }
                        catch (error: IOException) {
                            if (stopped) return
                            throw error
                        }
                        if (count < 0) return
                        if (count < 20 || count > PacketCodec.MTU) continue
                        val valid = if (internetV4)
                            NativePacketPolicy.admitsInternetV4(buf.copyOf(count), true)
                        else NativePacketPolicy.admits(buf.copyOf(count), true)
                        if (!valid) continue
                        PacketCodec.send(sink, buf, count)
                    }
                }
            }
            val request = Request.Builder()
                .url(baseUrl + "/fedup-lab/v1/ip-tunnel")
                .post(requestBody)
                .build()
            val runningCall = client.newCall(request)
            call = runningCall
            runningCall.execute().use { response ->
                check(response.protocol == Protocol.HTTP_2 && response.code == 200) {
                    "FedUp packet stream refused or downgraded, HTTP " + response.code
                }
                val input = response.body?.byteStream() ?: error("No HTTP/2 response body")
                // A system TUN alone is not a connected VPN: report success
                // only after the gateway confirms the actual HTTP/2 stream.
                onReady()
                while (!stopped) {
                    val packet = PacketCodec.receive(input) ?: error("Tunnel stream ended")
                    check(if (internetV4)
                        NativePacketPolicy.admitsInternetV4(packet, false)
                    else NativePacketPolicy.admits(packet, false)) {
                        "Invalid or spoofed packet received from server"
                    }
                    write.write(packet)
                }
            }
        } finally {
            stop()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }
}
