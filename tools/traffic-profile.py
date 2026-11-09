#!/usr/bin/env python3
"""Passive TLS ClientHello and flow analysis from a *synthetic* classic PCAP.

Only the Python standard library is needed. Never upload personal browsing
captures. This is NOT a TLS decryption tool, DPI classifier or evasion checker.
"""
import argparse
import json
import os
import statistics
import struct
from collections import defaultdict
from pathlib import Path

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_FRAME = 256 * 1024


def u16(buf, pos):
    if pos + 2 > len(buf):
        raise ValueError("truncated field")
    return int.from_bytes(buf[pos : pos + 2], "big")


def read_pcap(path):
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds 64 MiB limit")
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) != 24:
            raise ValueError("missing classic PCAP header")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, tick = "<", 1e6
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, tick = ">", 1e6
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, tick = "<", 1e9
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, tick = ">", 1e9
        else:
            raise ValueError("unsupported format: use classic PCAP, not PCAPNG")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype not in (1, 101, 113, 276):
            raise ValueError(f"unsupported PCAP link type {linktype}")
        while True:
            rec = source.read(16)
            if not rec:
                return
            if len(rec) != 16:
                raise ValueError("truncated PCAP record header")
            seconds, subseconds, caplen, _origlen = struct.unpack(endian + "IIII", rec)
            if caplen > MAX_FRAME:
                raise ValueError("unreasonably large captured frame")
            data = source.read(caplen)
            if len(data) != caplen:
                raise ValueError("truncated PCAP frame")
            yield seconds + subseconds / tick, linktype, data


def ipv4_tcp(linktype, frame):
    """Extract only outer IPv4/TCP. All capture addresses are synthetic."""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype = u16(frame, 12)
        pos = 14
        # One VLAN header is sufficient for our lab; ignore other link types.
        if ethertype == 0x8100:
            if len(frame) < 18:
                return None
            ethertype, pos = u16(frame, 16), 18
        if ethertype != 0x0800:
            return None
    elif linktype == 113:  # Linux cooked v1 (SLL)
        if len(frame) < 16 or u16(frame, 14) != 0x0800:
            return None
        pos = 16
    elif linktype == 276:  # Linux cooked v2 (SLL2)
        if len(frame) < 20 or u16(frame, 0) != 0x0800:
            return None
        pos = 20
    else:  # Raw IPv4
        pos = 0
    if len(frame) < pos + 20 or frame[pos] >> 4 != 4 or frame[pos + 9] != 6:
        return None
    ihl = (frame[pos] & 15) * 4
    if ihl < 20 or len(frame) < pos + ihl + 20:
        return None
    total = u16(frame, pos + 2)
    if total < ihl + 20:
        return None
    end = min(len(frame), pos + total)
    tcp = pos + ihl
    offset = (frame[tcp + 12] >> 4) * 4
    if offset < 20 or end < tcp + offset:
        return None
    source = ".".join(str(byte) for byte in frame[pos + 12 : pos + 16])
    dest = ".".join(str(byte) for byte in frame[pos + 16 : pos + 20])
    src_port, dst_port = u16(frame, tcp), u16(frame, tcp + 2)
    seq = int.from_bytes(frame[tcp + 4 : tcp + 8], "big")
    flags = frame[tcp + 13]
    return {
        "flow": (source, src_port, dest, dst_port),
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "flags": flags,
        "payload": frame[tcp + offset : end],
    }


def join_segments(segments):
    """Reassemble contiguous TCP payload in sequence order; skip retransmissions."""
    segments = sorted(segments, key=lambda part: part[0])
    if not segments:
        return b""
    result = bytearray()
    next_seq = segments[0][0]
    for seq, part in segments:
        if seq > next_seq:
            break  # capture gap; do not invent missing bytes
        overlap = next_seq - seq
        if overlap >= len(part):
            continue
        data = part[overlap:]
        result.extend(data)
        next_seq += len(data)
        if len(result) > 64 * 1024:
            break
    return bytes(result)


def parse_client_hello(data):
    """Parse public TLS ClientHello; never parse encrypted application data."""
    if len(data) < 9 or data[0] != 22 or data[1] != 3:
        return None
    record_len = u16(data, 3)
    if len(data) < record_len + 5:
        return None
    content = data[5 : 5 + record_len]
    if not content or content[0] != 1:
        return None
    handshake_len = int.from_bytes(content[1:4], "big")
    if len(content) < handshake_len + 4:
        return None
    body = content[4 : 4 + handshake_len]
    if len(body) < 35:
        return None
    # TLS ClientHello: legacy_version(2), random(32), sessionID, ciphers,
    # compressionMethods, extensions. Reject malformed fields.
    pos = 34
    session_len = body[pos]
    pos += 1 + session_len
    cipher_len = u16(body, pos)
    pos += 2
    if cipher_len % 2 or pos + cipher_len > len(body):
        return None
    ciphers = [u16(body, i) for i in range(pos, pos + cipher_len, 2)]
    pos += cipher_len
    if pos >= len(body):
        return None
    compression_len = body[pos]
    pos += 1 + compression_len
    extensions = []
    alpn = []
    sni = None
    if pos < len(body):
        length = u16(body, pos)
        pos += 2
        stop = pos + length
        if stop > len(body):
            return None
        while pos + 4 <= stop:
            ext_type = u16(body, pos)
            ext_len = u16(body, pos + 2)
            pos += 4
            if pos + ext_len > stop:
                return None
            ext = body[pos : pos + ext_len]
            pos += ext_len
            extensions.append(ext_type)
            if ext_type == 0 and len(ext) >= 5:  # server_name
                nlen = u16(ext, 0)
                if nlen + 2 <= len(ext) and ext[2] == 0:
                    strlen = u16(ext, 3)
                    if 5 + strlen <= len(ext):
                        sni = ext[5 : 5 + strlen].decode("ascii", "replace")
            elif ext_type == 16 and len(ext) >= 2:  # ALPN
                nlen = u16(ext, 0)
                i = 2
                end = min(len(ext), 2 + nlen)
                while i < end:
                    slen = ext[i]
                    i += 1
                    if i + slen > end:
                        return None
                    alpn.append(ext[i : i + slen].decode("ascii", "replace"))
                    i += slen
    return {
        "sni": sni,
        "offered_alpn": alpn,
        "handshake_bytes": handshake_len + 4,
        "record_bytes": record_len,
        "cipher_suite_count": len(ciphers),
        "extension_ids": extensions,
    }


def median(values):
    return round(statistics.median(values), 2) if values else None


def report(packets, port):
    times, lengths, payload_bytes, syn_packets = [], [], 0, 0
    flows = defaultdict(list)
    for timestamp, frame_size, segment in packets:
        if segment["src_port"] != port and segment["dst_port"] != port:
            continue
        times.append(timestamp)
        lengths.append(frame_size)
        payload_bytes += len(segment["payload"])
        if segment["flags"] & 2:
            syn_packets += 1
        if segment["dst_port"] == port and segment["payload"]:
            flows[segment["flow"]].append((segment["seq"], segment["payload"]))
    hellos = []
    for segments in flows.values():
        hello = parse_client_hello(join_segments(segments))
        if hello:
            hellos.append(hello)
    times.sort()
    gaps = [(b - a) * 1000 for a, b in zip(times, times[1:]) if b >= a]
    return {
        "port": port,
        "client_hello_count": len(hellos),
        "client_hello_visible": hellos[:5],
        "tcp_frame_count": len(lengths),
        "syn_count": syn_packets,
        "tcp_payload_bytes": payload_bytes,
        "median_frame_bytes": median(lengths),
        "median_packet_spacing_ms": median(gaps),
        "frame_bytes_min": min(lengths) if lengths else None,
        "frame_bytes_max": max(lengths) if lengths else None,
        "capture_window_ms": round(1000 * (times[-1] - times[0]), 1) if len(times) > 1 else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--fedup-port", type=int, default=7443)
    parser.add_argument("--https-port", type=int, default=9443)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    captured = []
    for timestamp, linktype, frame in read_pcap(args.pcap):
        item = ipv4_tcp(linktype, frame)
        if item:
            captured.append((timestamp, len(frame), item))
    result = {
        "experiment": "synthetic test namespaces; NOT an actual DPI classifier",
        "fedup": report(captured, args.fedup_port),
        "https_reference": report(captured, args.https_port),
        "warnings": [
            "ClientHello, IP destinations and flow shape can remain observable.",
            "FedUp carries raw application frames over TLS, not real HTTP/2 or HTTP/3.",
            "Reference is curl/OpenSSL HTTP/1.1, not representative browser traffic.",
            "A single controlled capture cannot prove censor detection accuracy.",
            "Never publish personal traffic PCAPs, private endpoints or credentials.",
        ],
    }
    if not result["fedup"]["client_hello_count"] or not result["https_reference"]["client_hello_count"]:
        raise RuntimeError("missing FedUp or reference ClientHello; capture is incomplete")
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        fd = os.open(str(args.output), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as dst:
            dst.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
