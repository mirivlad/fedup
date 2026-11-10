#!/usr/bin/env python3
"""No-network regression for synthetic encrypted TLS record inspection."""
import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "tls_flow_observer", Path(__file__).with_name("tls-flow-observer.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def record(kind, payload):
    return bytes((kind, 3, 3)) + struct.pack("!H", len(payload)) + payload


class TLSRecordObserverTests(unittest.TestCase):
    def test_counts_only_encrypted_records_without_decrypting(self):
        traffic = (
            record(22, b"hello") + record(23, b"a" * 41)
            + record(23, b"b" * 719) + record(21, b"\x01\x00")
        )
        result = module.tls_records(traffic)
        self.assertEqual(result["records_parsed"], 4)
        self.assertEqual(result["encrypted_records"], 2)
        self.assertEqual(result["first_encrypted_sizes"], [41, 719])
        self.assertEqual(result["parsed_prefix_bytes"], len(traffic))
        self.assertFalse(result["may_be_incomplete"])

    def test_refuses_to_invent_truncated_tls_record_sizes(self):
        traffic = record(23, b"x" * 64)
        for truncated in (traffic[:2], traffic[:-5]):
            result = module.tls_records(truncated)
            self.assertEqual(result["encrypted_records"], 0)
            self.assertTrue(result["may_be_incomplete"])

    def test_rejects_oversize_record_header(self):
        bad = b"\x17\x03\x03\xff\xff" + b"garbage"
        result = module.tls_records(bad)
        self.assertEqual(result["records_parsed"], 0)
        self.assertTrue(result["may_be_incomplete"])


if __name__ == "__main__":
    unittest.main()
