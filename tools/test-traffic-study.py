#!/usr/bin/env python3
"""No-network regression tests for the multi-capture FedUp report aggregator."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


script = Path(__file__).with_name("traffic-study.py")
spec = importlib.util.spec_from_file_location("fedup_traffic_study", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(directory, name, offered_alpn):
    report = {
        "experiment": "synthetic test namespaces; NOT an actual DPI classifier",
        "fedup": {
            "client_hello_count": 1,
            "client_hello_visible": [{
                "sni": "localhost",
                "offered_alpn": offered_alpn,
                "handshake_bytes": 250 if not offered_alpn else 260,
                "cipher_suite_count": 9,
                "extension_ids": [0, 10, 13, 16] if offered_alpn else [0, 10, 13],
            }],
            "tcp_frame_count": 100,
            "tcp_payload_bytes": 4096,
            "median_frame_bytes": 100.0,
            "median_packet_spacing_ms": 0.25,
            "capture_window_ms": 500.0,
        },
    }
    output = directory / name
    output.write_text(json.dumps(report), encoding="utf-8")
    return output


class StudyTests(unittest.TestCase):
    def test_three_matched_samples_are_descriptive_not_classifier_rates(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            raw = [fixture(directory, f"raw-{n}.json", []) for n in range(3)]
            h2 = [fixture(directory, f"h2-{n}.json", ["h2"]) for n in range(3)]
            summary = module.study(raw, h2)
            self.assertEqual(summary["raw_tls"]["independent_captures"], 3)
            self.assertEqual(summary["real_http2"]["independent_captures"], 3)
            self.assertEqual(summary["raw_tls"]["offered_alpn"], [])
            self.assertEqual(summary["real_http2"]["offered_alpn"], ["h2"])
            self.assertEqual(summary["raw_tls"]["metrics"]["handshake_bytes"]["median"], 250)
            self.assertNotIn("detection_rate", json.dumps(summary))
            self.assertNotIn("false_positive_rate", json.dumps(summary))

    def test_missing_samples_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            raw = [fixture(path, f"raw-{n}.json", []) for n in range(2)]
            h2 = [fixture(path, f"h2-{n}.json", ["h2"]) for n in range(2)]
            with self.assertRaisesRegex(ValueError, "at least three"):
                module.study(raw, h2)

    def test_misidentified_alpn_and_untrusted_provenance_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            bad = fixture(path, "bad.json", ["h2"])
            with self.assertRaisesRegex(ValueError, "wrong offered ALPN"):
                module.load_report(bad, [])
            raw = json.loads(bad.read_text())
            raw["experiment"] = "real DPI test"
            bad.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ValueError, "unrecognized report provenance"):
                module.load_report(bad, ["h2"])

    def test_variable_observations_do_not_invent_missing_measurements(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            raw = [fixture(directory, f"raw-{n}.json", []) for n in range(3)]
            h2 = [fixture(directory, f"h2-{n}.json", ["h2"]) for n in range(3)]
            content = json.loads(raw[0].read_text())
            content["fedup"]["median_packet_spacing_ms"] = None
            raw[0].write_text(json.dumps(content))
            summary = module.study(raw, h2)
            self.assertEqual(
                summary["raw_tls"]["metrics"]["median_packet_spacing_ms"]["observations"], 2
            )
            self.assertEqual(
                summary["raw_tls"]["metrics"]["tcp_frame_count"]["observations"], 3
            )


if __name__ == "__main__":
    unittest.main()
