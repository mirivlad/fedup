package top.mirv.fedup.android

import android.net.VpnService
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

/** Protect the *actual TCP socket* from re-entering the VPN TUN.
 * Protection happens before connect(). Failing to protect is fatal. */
internal class ProtectedSocketFactory(private val vpn: VpnService) : SocketFactory() {
    override fun createSocket(): Socket {
        val socket = Socket()
        if (!vpn.protect(socket)) {
            socket.close()
            throw IOException("Android refused to protect the VPN transport socket")
        }
        return socket
    }

    override fun createSocket(host: String?, port: Int): Socket =
        createSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        createSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(
        host: String?, port: Int, localHost: InetAddress?, localPort: Int
    ): Socket = createSocket().apply {
        bind(InetSocketAddress(localHost, localPort))
        connect(InetSocketAddress(host, port))
    }

    override fun createSocket(
        address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int
    ): Socket = createSocket().apply {
        bind(InetSocketAddress(localAddress, localPort))
        connect(InetSocketAddress(address, port))
    }
}
