#!/usr/bin/env python3
"""Passive TLS/TCP fingerprint report from synthetic local PCAPs.

No network access, no upload, no decryption, no claims about actual DPI accuracy.
Requires tshark/Wireshark. Do NOT share captures of personal browsing.
"""
import argparse
import json
import os
import statistics
import subprocess
from pathlib import Path


def tshark(path: Path, display_filter: str, fields: list[str]) -> list[list[str]]:
    cmd = ["tshark", "-Q", "-r", str(path), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        cmd.extend(["-e", field])
    cmd.extend(["-E", "separator=/t", "-E", "occurrence=f"])
    process = subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)
    if process.returncode:
        raise RuntimeError(f"tshark failed: {process.stderr.strip()[:1000]}")
    return [line.split("\t") for line in process.stdout.splitlines() if line.strip()]


def median(values: list[float]):
    return round(statistics.median(values), 2) if values else None


def report(path: Path, port: int) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"empty or missing PCAP: {path}")
    port_filter = f"tcp.port == {port}"
    handshake_fields = [
        "frame.time_epoch",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.length",
        "frame.len",
    ]
    hellos = tshark(
        path, f"({port_filter}) && tls.handshake.type == 1",
        handshake_fields,
    )
    tcp_rows = tshark(
        path, port_filter, ["frame.time_epoch", "frame.len", "tcp.len", "tcp.flags.syn"],
    )
    lengths = []
    times = []
    payload_bytes = 0
    syn_packets = 0
    for row in tcp_rows:
        try:
            times.append(float(row[0]))
            lengths.append(int(row[1]))
            payload_bytes += int(row[2] or "0")
            if len(row) > 3 and row[3] == "1":
                syn_packets += 1
        except (ValueError, IndexError):
            continue
    times.sort()
    gaps = [(b - a) * 1000 for a, b in zip(times, times[1:]) if b >= a]
    return {
        "source": path.name,
        "port": port,
        "client_hello_count": len(hellos),
        "client_hello_visible": [
            {
                "sni": row[1] if len(row) > 1 and row[1] else None,
                "offered_alpn": row[2] if len(row) > 2 and row[2] else [],
                "handshake_len": row[3] if len(row) > 3 and row[3] else None,
                "observed_frame_len": row[4] if len(row) > 4 and row[4] else None,
            }
            for row in hellos[:5]
        ],
        "tcp_frame_count": len(lengths),
        "syn_count": syn_packets,
        "tcp_payload_bytes": payload_bytes,
        "median_frame_len": median(lengths),
        "median_interarrival_ms": median(gaps),
        "frame_len_min": min(lengths) if lengths else None,
        "frame_len_max": max(lengths) if lengths else None,
        "capture_window_ms": round((times[-1] - times[0]) * 1000, 1) if len(times) >= 2 else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="synthetic PCAP captured on a controlled lab network")
    parser.add_argument("--fedup-port", type=int, default=7443)
    parser.add_argument("--https-port", type=int, default=9443)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    result = {
        "experiment": "synthetic private namespace comparison, NOT real-world DPI evaluation",
        "fedup": report(args.pcap, args.fedup_port),
        "https_reference": report(args.pcap, args.https_port),
        "warnings": [
            "Standard TLS does not imply HTTPS framing.",
            "ClientHello metadata, destination IP and flow timing may be observable.",
            "This report does not prove identifiability, censorship bypass, anonymity, or stealth.",
            "A single sample cannot establish a meaningful classifier false positive/negative rate.",
            "Captured addresses are synthetic; never commit or distribute private network PCAPs.",
        ],
    }
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        if args.output.exists():
            raise FileExistsError(f"Refusing to overwrite {args.output}")
        fd = os.open(str(args.output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
