#!/usr/bin/env python3
"""Offline regression tests for the detailed TLS ClientHello comparer.

Synthetic handshakes have deliberately different random/session/key-share
bytes, but the same observable static fingerprint. No VPN traffic is sent.
"""
import importlib.util
import struct
import unittest
from pathlib import Path


root = Path(__file__).parent
spec = importlib.util.spec_from_file_location("tls_matched_measure", root / "tls-matched-measure.py")
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)
profile = compare.profile


def u16(value):
    return struct.pack("!H", value)


def ext(number, body):
    return u16(number) + u16(len(body)) + body


def vec16(values):
    return u16(len(values)) + values


def clienthello(seed=1, ciphers=(4866, 4867, 4865, 255), keyshare_group=29):
    server_name = b"localhost"
    extensions = [
        ext(0, vec16(b"\x00" + u16(len(server_name)) + server_name)),
        ext(11, b"\x01\x00"),
        ext(10, vec16(u16(29) + u16(23))),
        ext(16, vec16(b"\x02h2\x08http/1.1")),
        ext(13, vec16(u16(1027) + u16(2052))),
        ext(43, b"\x02\x03\x04"),
        ext(51, vec16(u16(keyshare_group) + u16(32) + bytes([seed]) * 32)),
        ext(21, bytes(16)),
    ]
    body = (
        b"\x03\x03" + bytes([seed]) * 32
        + b"\x20" + bytes([seed ^ 0xAB]) * 32
        + vec16(b"".join(u16(x) for x in ciphers))
        + b"\x01\x00"
        + vec16(b"".join(extensions))
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + u16(len(handshake)) + handshake


class MatchedTLSMeasurementTests(unittest.TestCase):
    def test_identical_static_fields_with_distinct_random_ephemerals(self):
        left = profile.parse_client_hello(clienthello(seed=1))
        right = profile.parse_client_hello(clienthello(seed=77))
        self.assertIsNotNone(left)
        self.assertEqual(compare.signature(left), compare.signature(right))
        self.assertEqual(left["key_share_entries"], [[29, 32]])
        self.assertEqual(left["supported_groups"], [29, 23])
        self.assertEqual(left["supported_versions"], [772])
        self.assertEqual(left["offered_alpn"], ["h2", "http/1.1"])

    def test_cipher_value_change_is_not_hidden_by_identical_count(self):
        a = profile.parse_client_hello(clienthello(ciphers=(4866, 4867, 4865, 255)))
        b = profile.parse_client_hello(clienthello(ciphers=(4866, 4867, 4864, 255)))
        self.assertEqual(a["handshake_bytes"], b["handshake_bytes"])
        self.assertEqual(a["cipher_suite_count"], b["cipher_suite_count"])
        self.assertNotEqual(compare.signature(a), compare.signature(b))

    def test_keyshare_group_change_detected_even_with_equal_size(self):
        a = profile.parse_client_hello(clienthello(keyshare_group=29))
        b = profile.parse_client_hello(clienthello(keyshare_group=23))
        self.assertEqual(a["handshake_bytes"], b["handshake_bytes"])
        self.assertNotEqual(compare.signature(a), compare.signature(b))

    def test_truncated_or_corrupt_extension_is_rejected(self):
        normal = clienthello()
        self.assertIsNone(profile.parse_client_hello(normal[:-1]))
        # Remove the final padding byte but retain a coherent record length
        # and handshake length, so the extension block is internally corrupt.
        malformed = bytearray(normal)
        malformed[-1] = 0xff
        self.assertIsNotNone(profile.parse_client_hello(malformed))
        # Corrupt the last extension's claimed length from 16 to 255.
        where = bytes(malformed).rfind(u16(21) + u16(16))
        self.assertGreater(where, 0)
        malformed[where + 2:where + 4] = u16(255)
        self.assertIsNone(profile.parse_client_hello(malformed))


if __name__ == "__main__":
    unittest.main()
