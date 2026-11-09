#!/usr/bin/env python3
"""Aggregate repeated *synthetic* FedUp TLS observations.

Compares raw TLS and standards-compliant HTTP/2 under the same controlled
network-namespace workload. No trained DPI model, no TPR/FPR and no claims
about censorship resistance. No external requests, third-party dependencies,
raw payload inspection or upload of captures.
"""
import argparse
import json
import os
import statistics
from pathlib import Path

MAX_REPORT_BYTES = 256 * 1024
METRICS = {
    "handshake_bytes": ("client_hello_visible", "handshake_bytes"),
    "cipher_suite_count": ("client_hello_visible", "cipher_suite_count"),
    "tcp_frame_count": (None, "tcp_frame_count"),
    "tcp_payload_bytes": (None, "tcp_payload_bytes"),
    "median_frame_bytes": (None, "median_frame_bytes"),
    "capture_window_ms": (None, "capture_window_ms"),
    "median_packet_spacing_ms": (None, "median_packet_spacing_ms"),
}


def load_report(path: Path, expected_alpn: list[str]) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"missing or oversized synthetic report: {path}")
    with path.open("r", encoding="utf-8") as source:
        report = json.load(source)
    if report.get("experiment") != "synthetic test namespaces; NOT an actual DPI classifier":
        raise ValueError(f"unrecognized report provenance: {path.name}")
    fedup = report.get("fedup")
    if not isinstance(fedup, dict) or fedup.get("client_hello_count") != 1:
        raise ValueError(f"expected one complete FedUp ClientHello in {path.name}")
    hellos = fedup.get("client_hello_visible")
    if not isinstance(hellos, list) or len(hellos) != 1:
        raise ValueError(f"invalid ClientHello list: {path.name}")
    hello = hellos[0]
    if hello.get("offered_alpn") != expected_alpn:
        raise ValueError(f"wrong offered ALPN in {path.name}: {hello.get('offered_alpn')}")
    if not isinstance(hello.get("extension_ids"), list) or not hello["extension_ids"]:
        raise ValueError(f"missing TLS extension fingerprint in {path.name}")
    if hello.get("sni") != "localhost":
        raise ValueError(f"unexpected synthetic SNI in {path.name}")
    if not 0 < hello.get("handshake_bytes", 0) < 65536:
        raise ValueError(f"implausible ClientHello size in {path.name}")
    if not 0 < hello.get("cipher_suite_count", 0) < 256:
        raise ValueError(f"invalid TLS cipher suite count in {path.name}")
    if fedup.get("tcp_frame_count", 0) <= 0:
        raise ValueError(f"missing observed TCP frames in {path.name}")
    # No reference traffic is used in a comparison of unmatched workloads.
    return fedup


def numeric_series(observations, field):
    parent, key = METRICS[field]
    values = []
    for item in observations:
        source = item["client_hello_visible"][0] if parent else item
        value = source.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"non-numeric measurement: {field}")
        if value < 0:
            raise ValueError(f"negative measurement: {field}")
        values.append(value)
    return values


def stats(values):
    if not values:
        return {"observations": 0, "min": None, "median": None, "max": None}
    return {
        "observations": len(values),
        "min": min(values),
        "median": round(statistics.median(values), 3),
        "max": max(values),
    }


def summarize_group(items):
    fingerprints = {
        (
            tuple(item["client_hello_visible"][0]["offered_alpn"]),
            item["client_hello_visible"][0]["cipher_suite_count"],
            tuple(item["client_hello_visible"][0]["extension_ids"]),
        )
        for item in items
    }
    return {
        "independent_captures": len(items),
        "distinct_observed_hello_shapes": len(fingerprints),
        "offered_alpn": items[0]["client_hello_visible"][0]["offered_alpn"],
        "metrics": {name: stats(numeric_series(items, name)) for name in METRICS},
    }


def study(raw_reports, h2_reports):
    if len(raw_reports) != len(h2_reports) or len(raw_reports) < 3:
        raise ValueError("need at least three paired, independently captured samples per mode")
    raw = [load_report(p, []) for p in raw_reports]
    h2 = [load_report(p, ["h2"]) for p in h2_reports]
    return {
        "study_type": "matched synthetic workload across two FedUp TLS transport implementations",
        "assumptions": [
            "same tun-smoke.sh workload, same test topology, distinct independent runs",
            "synthetic veth capture, not a browser or physical Internet trace",
            "HTTPS reference from each raw capture is NOT a matched workload and is excluded",
        ],
        "raw_tls": summarize_group(raw),
        "real_http2": summarize_group(h2),
        "limitations": [
            "A few synthetic observations do not estimate DPI detection probability.",
            "No positive/negative labeled censor dataset or held-out real HTTPS browser traces.",
            "No classifier, TPR, FPR, false-positive guarantees, statistical significance or stealth claim.",
            "Capture timing includes test orchestration and is not a pure transport benchmark.",
            "TLS ClientHello and network metadata remain observable without payload decryption.",
            "TCP-over-TCP head-of-line blocking is not eliminated by HTTP/2.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", nargs="+", type=Path, required=True)
    parser.add_argument("--h2", nargs="+", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = study(args.raw, args.h2)
    data = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        fd = os.open(str(args.output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
    else:
        print(data, end="")


if __name__ == "__main__":
    main()
