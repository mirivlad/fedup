#!/usr/bin/env python3
"""Deterministic regression for active HTTPS probe response parity."""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "active_probe", Path(__file__).with_name("active-probe.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fake_response(date, path):
    headers = (
        b"HTTP/2 404 \r\n"
        b"content-type: text/plain; charset=utf-8\r\n"
        b"content-length: 10\r\n"
        b"cache-control: no-store\r\n"
        + b"date: " + date.encode() + b"\r\n"
        + b"\r\n"
    )
    return subprocess.CompletedProcess(
        ["curl", path], 0, stdout=headers, stderr=headers
    )


class ActiveProbeTests(unittest.TestCase):
    def test_head_has_no_body_even_when_curl_prints_headers_to_stdout(self):
        with patch.object(module.subprocess, "run", return_value=fake_response(
            "Tue, 10 Nov 2026 14:14:53 GMT", "/fedup-lab/v1/auth-check"
        )):
            protected = module.request("HEAD", "/fedup-lab/v1/auth-check")
        with patch.object(module.subprocess, "run", return_value=fake_response(
            "Tue, 10 Nov 2026 14:14:54 GMT", "/ordinary-missing"
        )):
            missing = module.request("HEAD", "/ordinary-missing")
        self.assertEqual(module.public_signature(protected), module.public_signature(missing))
        self.assertEqual(protected[2], b"")

    def test_get_body_is_not_suppressed(self):
        headers = b"HTTP/2 404 \r\ncontent-length: 10\r\n\r\n"
        result = subprocess.CompletedProcess(
            ["curl"], 0, stdout=b"Not Found\n", stderr=headers
        )
        with patch.object(module.subprocess, "run", return_value=result):
            got = module.request("GET", "/missing")
        self.assertEqual(got[2], b"Not Found\n")


if __name__ == "__main__":
    unittest.main()
