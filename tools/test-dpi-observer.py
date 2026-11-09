#!/usr/bin/env python3
"""Stdlib-only safety and regression tests for the passive DPI observer."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

script = Path(__file__).with_name("dpi-observer.py")
spec = importlib.util.spec_from_file_location("fedup_dpi_observer", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    return {
        "experiment": module.PROVENANCE,
        "fedup": {
            "port": 7443,
            "client_hello_count": 1,
            "client_hello_visible": [{
                "sni": "localhost", "handshake_bytes": 232,
                "offered_alpn": ["h2"], "cipher_suite_count": 9,
                "extension_ids": [0, 10, 13, 16],
            }],
        },
        "https_reference": {
            "port": 9443,
            "client_hello_count": 1,
            "client_hello_visible": [{
                "sni": "localhost", "handshake_bytes": 1561,
                "offered_alpn": ["http/1.1"], "cipher_suite_count": 30,
                "extension_ids": [0, 10, 11, 13, 16],
            }],
        },
    }


class ObserverTests(unittest.TestCase):
    def test_detects_observable_differences_without_calling_them_vpn(self):
        result = module.assess(fixture())
        self.assertTrue(result["different_from_this_control"])
        self.assertFalse(result["vpn_confirmed"])
        self.assertIsNone(result["censorship_detection_rate"])
        features = {a["feature"] for a in result["passive_visible_differences"]}
        self.assertIn("tls_offered_alpn", features)
        self.assertIn("tls_extension_ids_in_order", features)
        self.assertIn("tcp_destination_port", features)
        self.assertIn("tls_cipher_suite_count", features)

    def test_same_hello_does_not_prove_the_tunnel_is_undetectable(self):
        control = fixture()
        control["https_reference"] = dict(control["fedup"])
        result = module.assess(control)
        self.assertFalse(result["different_from_this_control"])
        self.assertFalse(result["vpn_confirmed"])
        self.assertIn("not proof", " ".join(result["notes"]).lower())

    def test_refuses_untrusted_or_ambiguous_input(self):
        for mutate in (
            lambda f: f.update(experiment="unknown"),
            lambda f: f["fedup"].update(client_hello_count=2),
            lambda f: f["fedup"]["client_hello_visible"][0].update(sni="private.example"),
            lambda f: f["fedup"]["client_hello_visible"][0].update(handshake_bytes=True),
            lambda f: f["fedup"].update(port=0),
        ):
            data = fixture()
            mutate(data)
            with self.assertRaises(ValueError):
                module.assess(data)

    def test_rejects_oversized_and_missing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            valid = root / "control.json"
            valid.write_text(json.dumps(fixture()), encoding="utf-8")
            self.assertEqual(module.load_report(valid)["experiment"], module.PROVENANCE)
            with self.assertRaises(ValueError):
                module.load_report(root / "missing.json")
            valid.write_bytes(b"x" * (module.MAX_REPORT_BYTES + 1))
            with self.assertRaises(ValueError):
                module.load_report(valid)


if __name__ == "__main__":
    unittest.main()
