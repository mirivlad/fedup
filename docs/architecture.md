# FedUp — System Architecture (Draft v0.1)

> This is a **proposed architecture**. Nothing described here should be treated as already implemented or security-audited.

## 1. Design rules

- Separate **data plane** (user connections) and **control plane** (identity, enrollment, revocation, node catalog).
- Prioritize tested reliability and correctness over camouflage claims.
- Standard TLS 1.3 implementations provide encryption and server authentication; FedUp defines its own **application framing and session semantics**, not its own cryptography.
- Use the least privilege each platform permits and make all failure policies explicit.
- Be operational for one node; optional relays and redundant entries must not complicate the basic install.

## 2. Components

```text
     Android / Linux / Windows client
            ├─ user interface + enrollment
            ├─ platform policy (app list/routes/DNS/kill switch)
            └─ shared FedUp core
                    │ authenticated TLS transport
                    ▼
              Entry service
                    ├─ session admission & limits
                    ├─ authenticated forwarding
                    └─ secure administrative boundary
                           │
                [optional relay / egress split]
                           ▼
                       Egress
                           │
                        Internet

   Admin CLI/TUI ──[separate authenticated admin channel]── Control service
                              │ issues/revokes device credentials and node metadata
```

Client traffic and management must not share unauthenticated APIs or permissions.

## 3. Provisional transport choice

For the **first experiment**, evaluate HTTP/2 over TLS 1.3 using a standards-compliant library, with authenticated application-level sessions over it. Also evaluate a QUIC/HTTP/3 candidate **only after** the first transport is functional and measurable.

Questions to settle via experiments, not assumptions:
- Can standard long-lived streams carry the necessary bidirectional TCP and UDP semantics with bounded overhead?
- Which behaviors reveal an unusual tunnel despite standard TLS?
- How does it behave under lossy connections, captive portals, TLS interception, roaming and restrictive proxies?
- Are connection reuse and resource limits safe without breaking user applications?

FedUp's framing proposal (not a deployed wire format):
- Versioned **capabilities negotiation** after the authenticated transport is established.
- Bounded-size frames with explicit length, frame type and logical stream ID; integers and byte order are specified in the eventual protocol document.
- Frame classes: session control, open/close logical stream, stream data, datagram, flow control, keepalive, orderly error.
- Strict per-device and per-session quotas and unauthenticated request limits.
- No distinguishable magic prefix or homebrew cryptographic handshake sent before TLS.
- Unknown protocol version or capability: unambiguous rejection, with no unsafe downgrade.

## 4. Enrollment and trust

1. Operator initializes a server identity and a private administration credential.
2. Operator generates a short-lived, single-use invitation carrying a pinned server identity or other verifiable trust bootstrap.
3. Client displays server identity and requested permissions; device creates unique credential inside a supported secure store.
4. Server records device public identity and a scoped authorization.
5. Revocation invalidates new sessions immediately; existing sessions are terminated under an explicitly documented timeout.

**Never:** put a shared permanent VPN secret into QR codes or send device private keys to the server.

Credential storage must account for minimal Linux desktops with no unlocked keyring. Fail-closed should not mean an unexplained crash; use a supported encrypted store with user interaction or a clear refusal.

## 5. Routing, DNS and leak behavior

Modes: (1) protect all device traffic, (2) selective application policy where supported. These are distinct security profiles.

- Android: `VpnService` with `addAllowedApplication`; one active VPN per user/profile is assumed. Non-selected apps use system networking and may infer that a VPN is present.
- Linux: TUN + policy routing and nftables; optionally namespaces for isolation.
- Windows: Wintun or equivalent maintained driver plus route/firewall integration. Per-process routing requires separate validation and may be deferred.
- DNS: explicit tunnel DNS in full-protection mode; split DNS policies require tests; IPv6 must not silently escape.
- Kill switch: define whether it applies only to protected apps or all apps and provide clear UI. Prove the behavior under crashes/roaming.

## 6. Multi-node / availability

Start with a single entry+egress node. Later allow a list of independent entry endpoints and optional relay/egress split.

The endpoint catalog must be signed and updated with anti-rollback protections. Switching entries must not silently weaken security. Multiple endpoints **do not bypass broad IP/ASN blocks automatically**.

## 7. Observability

- Opt-in local diagnostics; redact tokens, peer addresses where possible, domain lists and user identities before sharing.
- Counters for errors, byte totals, latency and protocol version; no destination content or full per-user browsing logs by default.
- Public reproducible measurement tools use synthetic addresses and test fixtures.

## 8. Project layout (future)

```text
crates/
  fedup-protocol/      # framing and input validation
  fedup-transport/     # standard encrypted transport adapters
  fedup-client-core/   # sessions, retries and routing policy interface
  fedup-server-core/   # admission, sessions and forwarding
apps/
  server/              # Linux daemon + systemd packaging
  admin/               # CLI/TUI
  android/             # Kotlin VpnService + shared core bridge
  desktop/             # Linux/Windows GUI + OS integration
docs/
  adr/                 # numbered architecture decisions
tests/
  network/             # netns integration and leak checks
  captures/            # synthetic traffic and analysis
```

## 9. Sources

- https://www.rfc-editor.org/rfc/rfc8446 (TLS 1.3)
- https://www.rfc-editor.org/rfc/rfc9113 (HTTP/2)
- https://developer.android.com/develop/connectivity/vpn
- https://www.wintun.net/
