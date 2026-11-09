#!/usr/bin/env python3
"""Explain what a hypothetical *passive* observer sees in synthetic FedUp PCAP reports.

No Internet access, raw packet payloads, private keys, domain histories or
real-user captures. These rules distinguish a local laboratory control from
FedUp; they do NOT identify an RKN classifier or estimate real-world blocking.
"""
import argparse
import json
import os
from pathlib import Path

PROVENANCE = "synthetic test namespaces; NOT an actual DPI classifier"
MAX_REPORT_BYTES = 256 * 1024


def get_hello(group, label):
    if not isinstance(group, dict) or group.get("client_hello_count") != 1:
        raise ValueError(f"{label}: expected exactly one complete ClientHello")
    hellos = group.get("client_hello_visible")
    if not isinstance(hellos, list) or len(hellos) != 1:
        raise ValueError(f"{label}: missing single visible ClientHello")
    hello = hellos[0]
    if not isinstance(hello, dict):
        raise ValueError(f"{label}: malformed ClientHello")
    if not isinstance(hello.get("offered_alpn"), list):
        raise ValueError(f"{label}: missing ALPN observation")
    if not isinstance(hello.get("extension_ids"), list):
        raise ValueError(f"{label}: missing TLS extension IDs")
    for field in ("handshake_bytes", "cipher_suite_count"):
        val = hello.get(field)
        if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
            raise ValueError(f"{label}: invalid {field}")
    if not isinstance(group.get("port"), int) or not 1 <= group["port"] <= 65535:
        raise ValueError(f"{label}: invalid port")
    return hello


def assess(observation):
    """Compare only observable handshake/outer-flow metadata in one fixture."""
    if observation.get("experiment") != PROVENANCE:
        raise ValueError("unknown provenance; refuse non-synthetic report")
    fedup = observation.get("fedup")
    reference = observation.get("https_reference")
    h2_reference = observation.get("https2_reference")
    curl_h2_reference = observation.get("https2_curl_reference")
    tunnel = get_hello(fedup, "fedup")
    control = get_hello(reference, "https_reference")
    h2_control = get_hello(h2_reference, "https2_reference")
    curl_h2_control = get_hello(curl_h2_reference, "https2_curl_reference")
    if "h2" not in h2_control["offered_alpn"] or "h2" not in curl_h2_control["offered_alpn"]:
        raise ValueError("HTTPS/2 control must offer ALPN h2")
    if (tunnel.get("sni") != "localhost"
            or control.get("sni") not in ("localhost", None)
            or h2_control.get("sni") not in ("localhost", None)
            or curl_h2_control.get("sni") != "localhost"):
        raise ValueError("unexpected endpoint; refusing personal or real-world capture")

    comparisons = [
        ("tcp_destination_port", fedup["port"], reference["port"]),
        ("tls_handshake_bytes", tunnel["handshake_bytes"], control["handshake_bytes"]),
        ("tls_offered_alpn", tunnel["offered_alpn"], control["offered_alpn"]),
        ("tls_cipher_suite_count", tunnel["cipher_suite_count"], control["cipher_suite_count"]),
        ("tls_extension_ids_in_order", tunnel["extension_ids"], control["extension_ids"]),
    ]
    differences = [
        {"feature": name, "fedup": value, "control": baseline}
        for name, value, baseline in comparisons
        if value != baseline
    ]
    # Exclude destination ports from the HTTP/2 protocol fingerprint comparison:
    # ports 7443/9553 differ by laboratory design and trivially leak labels.
    protocol_features = [
        ("tls_handshake_bytes", "handshake_bytes"),
        ("tls_offered_alpn", "offered_alpn"),
        ("tls_cipher_suite_count", "cipher_suite_count"),
        ("tls_extension_ids_in_order", "extension_ids"),
    ]
    h2_differences = [
        {"feature": label, "fedup": tunnel[key], "control": h2_control[key]}
        for label, key in protocol_features
        if tunnel[key] != h2_control[key]
    ]
    curl_h2_differences = [
        {"feature": label, "fedup": tunnel[key], "control": curl_h2_control[key]}
        for label, key in protocol_features
        if tunnel[key] != curl_h2_control[key]
    ]
    return {
        "control": "curl/OpenSSL HTTPS/1.1, nghttp/OpenSSL HTTPS/2, curl/OpenSSL HTTPS/2; no browser",
        "http2_control": "nghttp/OpenSSL TLS+ALPN h2; not Android, Firefox or Chromium",
        "https2_visible_differences_excluding_port": h2_differences,
        "different_tls_shape_from_https2": bool(h2_differences),
        "curl_https2_matched_sni": curl_h2_control["sni"] == tunnel["sni"],
        "https2_curl_visible_differences_excluding_port": curl_h2_differences,
        "different_tls_shape_from_curl_https2": bool(curl_h2_differences),
        "subject": "synthetic FedUp test connection, NOT physical Android",
        "passive_visible_differences": differences,
        "different_from_this_control": bool(differences),
        "vpn_confirmed": False,
        "censorship_detection_rate": None,
        "notes": [
            "Port difference is lab topology, not an independent protocol signature.",
            "ALPN difference can simply distinguish HTTP/1.1 from HTTP/2.",
            "HTTP/2 reference is a real web transport, but uses nghttp/OpenSSL TLS, not browsers.",
            "Port is excluded from HTTPS/2 fingerprint comparison to prevent a trivial lab-only classifier.",
            "The two requests do not yet have identical timing/size/workload.",
            "Visible TLS/flow differences are not proof the payload is a VPN.",
            "TLS 1.3 encrypts HTTP/2 payload and post-ServerHello handshake messages.",
            "A stateful adversary can also attempt active TLS/HTTP probes; this is not one.",
            "The Windows and Android TLS fingerprints have NOT been measured here.",
            "Do not infer RKN detection accuracy or safety from this synthetic control.",
        ],
    }


def load_report(path):
    if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"missing or oversized report: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("reports", nargs="+", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = {
        "experiment": "hypothetical passive observer of synthetic HTTPS/TLS controls",
        "samples": [
            {"fixture": f"sample-{i + 1}", **assess(load_report(path))}
            for i, path in enumerate(args.reports)
        ],
        "limits": "Not a classifier accuracy estimate, not real censorship measurements",
    }
    serialized = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        fd = os.open(str(args.output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as destination:
            destination.write(serialized)
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
