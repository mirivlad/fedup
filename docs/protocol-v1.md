# FedUp v1 — Experimental Framing (Draft 0.1)

**Status: EXPERIMENTAL.** This is a framing format for authenticated encrypted transports, not a complete VPN protocol or a guarantee of stealth.

## Header format

All multi-byte integers are unsigned **big endian**. A 12-byte header is followed by the declared payload.

| Offset | Bytes | Field | Constraint |
| --- | ---: | --- | --- |
| 0 | 1 | version | Exactly 1; unknown versions rejected |
| 1 | 1 | kind | Known enum value only |
| 2 | 2 | reserved flags | Must be 0 |
| 4 | 4 | stream_id | Control frames use zero; stream frames use nonzero |
| 8 | 4 | payload_len | <= 65536 bytes; checked **before allocation** |
| 12 | variable | payload | Exactly payload_len bytes |

Frame kinds: Ping=1, Pong=2, Error=3 (all control, stream_id=0); Open=4, Data=5, Close=6, Datagram=7 (all require nonzero stream_id).

No unauthenticated wire prefix is sent. The header is only defined **inside** an independently encrypted, authenticated channel.

## Correctness rules

- Read the 12-byte header exactly; socket read boundaries are not frame boundaries.
- Reject unknown protocol versions, frame kinds, nonzero reserved flags or invalid stream IDs.
- Reject sizes above 64 KiB before any payload-sized allocation.
- Treat truncated payloads as errors; never retry using an insecure alternate transport.
- Apply network read and write timeouts outside this library.
- No silent version downgrade.

## Golden vector

Data frame on stream 0x01020304 with payload AB:

01 05 00 00 01 02 03 04 00 00 00 01 AB

## Implemented and deferred

The codec parses/serializes all enumerated frame types. The loopback-only mTLS laboratory handles one Ping (max 64 bytes) and replies Pong. It does **not** implement stream multiplexing, flow control, UDP forwarding, TUN, DNS or HTTP/2.

Still to specify: capability negotiation, per-device enrollment and revocation, stream lifecycle, datagram semantics, error codes, quotas, reconnect, routing and protocol compatibility. These are prerequisites to a usable VPN.
