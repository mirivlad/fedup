#!/usr/bin/env python3
"""Observed encrypted TLS record/flow shapes in disposable FedUp lab PCAPs.

Reads only synthetic TCP port 7443; no TLS secrets or decryption. This
compares an ordinary short HTTPS/2 request to a long-lived VPN stream,
so the workloads are NOT matched and classification accuracy is UNKNOWN.
It measures the next obvious traffic-shape differences without assuming
they imply successful DPI identification.
"""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path
import statistics


spec = importlib.util.spec_from_file_location(
    "tls_traffic_profile", Path(__file__).with_name("traffic-profile.py")
)
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)

PORT = 7443
MAX_RECORD = (1 << 14) + 2048


def tls_records(data):
    """Count TLS record header types and encrypted record sizes, with bounds."""
    cursor = 0
    lengths = []
    types = []
    while cursor + 5 <= len(data):
        kind = data[cursor]
        if kind not in (20, 21, 22, 23) or data[cursor + 1] != 3:
            break
        size = profile.u16(data, cursor + 3)
        if size > MAX_RECORD or cursor + 5 + size > len(data):
            break
        if kind == 23:
            lengths.append(size)
        types.append(kind)
        cursor += size + 5
    return {
        "records_parsed": len(types),
        "encrypted_records": len(lengths),
        "first_encrypted_sizes": lengths[:10],
        "encrypted_record_size_median": statistics.median(lengths) if lengths else None,
        "parsed_prefix_bytes": cursor,
        "stream_prefix_bytes": len(data),
        "may_be_incomplete": cursor < len(data),
    }


def collect(pcap):
    streams = defaultdict(lambda: {
        "client": [], "server": [], "first": None, "last": None,
        "captured_frames": 0,
    })
    for ts, linktype, frame in profile.read_pcap(pcap):
        packet = profile.ipv4_tcp(linktype, frame)
        if packet is None or (packet["src_port"] != PORT and packet["dst_port"] != PORT):
            continue
        src_ip, src_port, dst_ip, dst_port = packet["flow"]
        if packet["dst_port"] == PORT:
            key = (src_ip, src_port, dst_ip, dst_port)
            direction = "client"
        else:
            key = (dst_ip, dst_port, src_ip, src_port)
            direction = "server"
        stream = streams[key]
        stream["first"] = ts if stream["first"] is None else min(stream["first"], ts)
        stream["last"] = ts if stream["last"] is None else max(stream["last"], ts)
        stream["captured_frames"] += 1
        if packet["payload"]:
            stream[direction].append((packet["seq"], packet["payload"]))

    matches = []
    for address, stream in streams.items():
        client = profile.join_segments(stream["client"])
        hello = profile.parse_client_hello(client)
        if not hello or hello["sni"] != "localhost" or hello["offered_alpn"] != ["h2", "http/1.1"]:
            continue
        server = profile.join_segments(stream["server"])
        matches.append({
            "address": address,
            "first": stream["first"],
            "duration_ms": round((stream["last"] - stream["first"]) * 1000, 2),
            "captured_frames": stream["captured_frames"],
            "client_tcp_prefix_bytes": len(client),
            "server_tcp_prefix_bytes": len(server),
            "client_tls": tls_records(client),
            "server_tls": tls_records(server),
        })
    return sorted(matches, key=lambda x: x["first"])


def compare(baseline, vpn):
    controls = collect(baseline)
    devices = collect(vpn)
    if len(controls) < 8 or not devices:
        raise ValueError("missing required 8 control flows or signed FedUp flow")
    controls = controls[:8]
    device = devices[0]
    return {
        "scope": "disposable Linux namespaces, synthetic VPS TLS port 7443",
        "reference": "8 curl/OpenSSL HTTPS/2 GET requests with matched TLS 1.3 SNI and ALPN",
        "vpn": "first signed Linux FedUp HTTP/2 packet tunnel in its capture",
        "reference_sessions": len(controls),
        "reference_median_duration_ms": statistics.median(x["duration_ms"] for x in controls),
        "reference_median_encrypted_client_records": statistics.median(
            x["client_tls"]["encrypted_records"] for x in controls
        ),
        "reference_first_client_records": controls[0]["client_tls"]["first_encrypted_sizes"],
        "vpn_duration_ms": device["duration_ms"],
        "vpn_encrypted_client_records": device["client_tls"]["encrypted_records"],
        "vpn_first_client_records": device["client_tls"]["first_encrypted_sizes"],
        "vpn_client_tls_data": device["client_tls"],
        "vpn_server_tls_data": device["server_tls"],
        "limitations": [
            "HTTPS GET and an IP tunnel are distinct workloads; comparisons are descriptive only.",
            "Not a measured DPI true-positive or false-positive rate.",
            "Only first 64KiB per direction reassembled; Linux veth offloads may distort packets.",
            "No physical Android, no production VPS and no censor classification results.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("vpn", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = compare(args.baseline, args.vpn)
    blob = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as dest:
            dest.write(blob)
        print("TLS flow profile saved:", args.output)
    else:
        print(blob, end="")


if __name__ == "__main__":
    main()
