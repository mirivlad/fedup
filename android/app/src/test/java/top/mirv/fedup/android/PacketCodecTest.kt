package top.mirv.fedup.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import okio.Buffer

class PacketCodecTest {
    @Test fun datagramRoundtrip() {
        val payload = ByteArray(1280) { (it % 223).toByte() }
        val stream = Buffer()
        PacketCodec.send(stream, payload, 1280)
        val wire = stream.readByteArray()
        assertArrayEquals(PacketCodec.header(1280), wire.copyOfRange(0, 12))
        assertArrayEquals(payload, PacketCodec.receive(ByteArrayInputStream(wire)))
        assertNull(PacketCodec.receive(ByteArrayInputStream(ByteArray(0))))
    }

    @Test(expected = IOException::class)
    fun invalidStreamIsRejected() {
        val fake = PacketCodec.header(20)
        fake[7] = 2
        PacketCodec.receive(ByteArrayInputStream(fake + ByteArray(20)))
    }

    @Test(expected = IOException::class)
    fun hugePayloadRejectedBeforeAllocation() {
        val fake = PacketCodec.header(20)
        fake[11] = 0x01
        fake[10] = 0x10
        PacketCodec.receive(ByteArrayInputStream(fake))
    }

    @Test(expected = EOFException::class)
    fun truncatedResponseFailsClosed() {
        PacketCodec.receive(ByteArrayInputStream(PacketCodec.header(20) + ByteArray(4)))
    }

    @Test fun serializedHeaderMatchesRustV1() {
        assertArrayEquals(
            byteArrayOf(1, 7, 0, 0, 0, 0, 0, 1, 0, 0, 0, 20),
            PacketCodec.header(20)
        )
        assertEquals(12, PacketCodec.HEADER)
    }
}
