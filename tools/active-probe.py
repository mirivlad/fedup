#!/usr/bin/env python3
"""Offline active HTTPS/2 response-differential study for the disposable VPN lab.

Not an RKN DPI classifier. Runs only against the fixed isolated namespace
address and never contacts the public Internet. Compare protected route
failures against ordinary 404s, including both HTTP headers and body.
"""
import argparse
import subprocess
import sys
import time

GATEWAY = "https://172.31.44.1:7443"
CONTENT_TYPE = "application/vnd.fedup.ip-packets"


def request(method, path, headers=()):
    command = [
        "curl", "--http2", "--noproxy", "*", "--insecure", "--silent",
        "--show-error", "--max-time", "7", "--dump-header", "/dev/stderr",
        "--output", "/dev/stdout",
    ]
    if method == "HEAD":
        command.append("--head")
    elif method == "POST":
        command += ["--request", "POST", "--data-binary", ""]
    for value in headers:
        command += ["--header", value]
    command.append(GATEWAY + path)
    result = subprocess.run(command, capture_output=True, timeout=9, check=True)
    # Only HTTP/2. Do not treat proxy CONNECT responses as target metadata.
    raw = result.stderr.replace(b"\r\n", b"\n")
    chunks = [item for item in raw.split(b"\n\n") if item.startswith(b"HTTP/")]
    if len(chunks) != 1 or not chunks[0].startswith(b"HTTP/2 "):
        raise ValueError("expected one direct HTTP/2 origin response")
    lines = chunks[0].decode("utf-8", "replace").split("\n")
    status = int(lines[0].split()[1])
    fields = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    return status, fields, result.stdout


def public_signature(result):
    status, headers, body = result
    relevant = ("content-type", "content-length", "cache-control", "set-cookie")
    return status, tuple((name, tuple(headers.get(name, []))) for name in relevant), body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", action="store_true", required=True,
                        help="affirm this test runs inside disposable network namespaces")
    args = parser.parse_args()
    if not args.lab:
        parser.error("--lab is required")

    original = request("GET", "/")
    if original[0] != 200 or original[1].get("set-cookie"):
        raise AssertionError("anonymous public GET leaked a device-session challenge")
    head = request("HEAD", "/")
    if head[0] != 200 or head[1].get("set-cookie"):
        raise AssertionError("anonymous public HEAD leaked a device-session challenge")
    asset = request("GET", "/assets/site.js")
    if asset[0] != 200 or asset[1].get("set-cookie"):
        raise AssertionError("anonymous JS asset leaked a device-session challenge")
    attempted = request("GET", "/assets/site.js", (
        "x-device-init: " + "A" * 43,
        "x-device-time: " + str(int(time.time())),
        "x-device-certificate: AA",
        "x-device-proof: AA",
    ))
    if public_signature(attempted) != public_signature(asset):
        raise AssertionError("forged device initiation changed anonymous web response")

    cases = [
        ("GET", "/fedup-lab/v1/auth-check", "/definitely-unknown-route", ()),
        ("HEAD", "/fedup-lab/v1/auth-check", "/definitely-unknown-route", ()),
        ("POST", "/fedup-lab/v1/ip-tunnel", "/definitely-unknown-route",
         ("Content-Type: " + CONTENT_TYPE,)),
        ("GET", "/fedup-lab/v1/ip-tunnel", "/definitely-unknown-route", ()),
    ]
    for method, protected, unknown, headers in cases:
        observed = request(method, protected, headers)
        baseline = request(method, unknown, headers)
        if observed[0] != 404 or public_signature(observed) != public_signature(baseline):
            raise AssertionError(
                f"{method} {protected} differs from unrelated 404: "
                f"{public_signature(observed)!r} != {public_signature(baseline)!r}"
            )
    print(
        "Offline active-probe parity: PASS (4 protected/unknown HTTP/2 "
        "pairs, site GET+HEAD, JS asset and forged initiation have no device cookie)"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, AssertionError) as error:
        print(f"Offline HTTPS probe failed: {error}", file=sys.stderr)
        sys.exit(1)
