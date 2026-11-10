#!/usr/bin/env python3
"""Compare REAL ClientHello fingerprints under matched transport conditions.

Workload is not equal: this deliberately measures only the first unencrypted
TLS ClientHello, not traffic timing, duration, protocol secrecy or DPI evasion.
The control and device must connect to the SAME localhost:7443 lab service,
with TLS 1.3 and HTTP/2 + HTTP/1.1 ALPN offered. No keys are decrypted.
"""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path
import statistics

module_path = Path(__file__).with_name("traffic-profile.py")
spec = importlib.util.spec_from_file_location("fedup_traffic_profile", module_path)
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


def hellos(path):
    flows = defaultdict(list)
    first_seen = {}
    for timestamp, linktype, frame in profile.read_pcap(path):
        packet = profile.ipv4_tcp(linktype, frame)
        if not packet or packet["dst_port"] != 7443 or not packet["payload"]:
            continue
        address = packet["flow"]
        flows[address].append((packet["seq"], packet["payload"]))
        first_seen[address] = min(timestamp, first_seen.get(address, timestamp))
    parsed = []
    for address, segments in flows.items():
        message = profile.parse_client_hello(profile.join_segments(segments))
        if message and message["sni"] == "localhost" and message["offered_alpn"] == ["h2", "http/1.1"]:
            parsed.append((first_seen[address], message))
    return [item for _, item in sorted(parsed, key=lambda row: row[0])]


KEYS = (
    "handshake_bytes",
    "record_bytes",
    "legacy_version",
    "session_id_length",
    "cipher_suite_count",
    "cipher_suite_ids",
    "compression_methods",
    "extension_ids",
    "extension_lengths",
    "supported_groups",
    "ec_point_formats",
    "signature_algorithm_ids",
    "supported_versions",
    "key_share_entries",
    "psk_key_exchange_modes",
    "offered_alpn",
    "sni",
)


def signature(hello):
    # JSON is stable and hashable even for nested extension/key-share lists.
    return json.dumps(
        {key: hello[key] for key in KEYS}, sort_keys=True, separators=(",", ":")
    )


def analyze(normal, vpn, min_control=8):
    controls = hellos(normal)
    devices = hellos(vpn)
    if len(controls) < min_control or len(devices) < 1:
        raise RuntimeError(f"incomplete matched TLS samples: control={len(controls)}, VPN={len(devices)}")
    # Synthetic smoke does 8 controlled curl trials first. Later probe opens
    # additional SNI-matched handshakes and must NOT contaminate the reference.
    controls = controls[:min_control]
    if len({signature(x) for x in controls}) != 1:
        raise RuntimeError("curl control TLS signatures differ; first 8 are not reproducible")
    baseline = controls[0]
    candidate = devices[0]  # first signed VPN connection, not later probe/second session
    equality = {key: candidate[key] == baseline[key] for key in KEYS}
    fields = {
        "baseline_control_count": len(controls),
        "vpn_first_handshake_observed": 1,
        "vpn_total_matching_sni_and_alpn_hellos": len(devices),
        "control": baseline,
        "vpn": candidate,
        "field_equalities": equality,
        "all_observed_fields_equal": all(equality.values()),
        "clienthello_absolute_byte_gap": abs(candidate["handshake_bytes"] - baseline["handshake_bytes"]),
        "cipher_suite_count_gap": abs(candidate["cipher_suite_count"] - baseline["cipher_suite_count"]),
        "extensions_exact_order_match": candidate["extension_ids"] == baseline["extension_ids"],
        "cipher_suites_exact_order_match": candidate["cipher_suite_ids"] == baseline["cipher_suite_ids"],
        "supported_groups_exact_order_match": candidate["supported_groups"] == baseline["supported_groups"],
        "signature_algorithms_exact_order_match": (
            candidate["signature_algorithm_ids"] == baseline["signature_algorithm_ids"]
        ),
        "extension_payload_lengths_exact_match": (
            candidate["extension_lengths"] == baseline["extension_lengths"]
        ),
        "extensions_jaccard": round(
            len(set(candidate["extension_ids"]) & set(baseline["extension_ids"]))
            / len(set(candidate["extension_ids"]) | set(baseline["extension_ids"])), 4
        ),
        "interpretation": (
            "TLS ClientHello observables only, one VPN connection. "
            "No measured DPI TPR/FPR, no equal-load flow behavior and no Android inference."
        ),
    }
    return fields


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("baseline", type=Path)
    p.add_argument("vpn", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = analyze(args.baseline, args.vpn)
    raw = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as file:
            file.write(raw)
        print(f"Matched TLS ClientHello measurement: {args.output}")
    else:
        print(raw, end="")


if __name__ == "__main__":
    main()
