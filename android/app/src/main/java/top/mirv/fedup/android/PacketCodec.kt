package top.mirv.fedup.android

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import okio.BufferedSink

/**
 * Wire-compatible with fedup-protocol v1 Datagram frames, stream 1.
 * Never allocate payload based on an unvalidated remote length.
 */
internal object PacketCodec {
    const val MTU = 1280
    const val HEADER = 12

    fun header(length: Int): ByteArray {
        require(length in 20..MTU)
        return byteArrayOf(
            1, 7, 0, 0,   // version, Datagram kind, reserved flags
            0, 0, 0, 1,   // stream ID
            (length ushr 24).toByte(),
            (length ushr 16).toByte(),
            (length ushr 8).toByte(),
            length.toByte()
        )
    }

    fun send(sink: BufferedSink, packet: ByteArray, count: Int) {
        require(count in 20..MTU && count <= packet.size)
        sink.write(header(count))
        sink.write(packet, 0, count)
        sink.flush()
    }

    private fun readExactly(stream: InputStream, buffer: ByteArray, allowEof: Boolean): Boolean {
        var copied = 0
        while (copied < buffer.size) {
            val count = stream.read(buffer, copied, buffer.size - copied)
            if (count < 0) {
                if (allowEof && copied == 0) return false
                throw EOFException("Truncated FedUp packet frame")
            }
            if (count == 0) continue
            copied += count
        }
        return true
    }

    fun receive(stream: InputStream): ByteArray? {
        val head = ByteArray(HEADER)
        if (!readExactly(stream, head, true)) return null
        if (head[0] != 1.toByte() || head[1] != 7.toByte() ||
            head[2] != 0.toByte() || head[3] != 0.toByte() ||
            head[4] != 0.toByte() || head[5] != 0.toByte() ||
            head[6] != 0.toByte() || head[7] != 1.toByte()) {
            throw IOException("Unsupported packet header or unexpected stream")
        }
        val size = ((head[8].toInt() and 255) shl 24) or
            ((head[9].toInt() and 255) shl 16) or
            ((head[10].toInt() and 255) shl 8) or
            (head[11].toInt() and 255)
        if (size !in 20..MTU) throw IOException("Invalid or oversized IP datagram length")
        return ByteArray(size).also { readExactly(stream, it, false) }
    }
}
