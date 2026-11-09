# Repeated synthetic FedUp traffic fingerprint experiment

We now collect **three independent packet captures per mode** for the *same* three-namespace IP workload, using raw TLS and genuine HTTP/2 (ALPN h2). This addresses the prior single-sample limitation without manufacturing a network censor detection rate.

The no-network Python tool \`tools/traffic-profile.py\` extracts a synthetic ClientHello and TCP flow metadata from each classic PCAP. \`tools/traffic-study.py\` validates provenance/ALPN, requires a minimum of three paired observations, and reports minimum, median, maximum and the number of distinct observed handshake shapes per mode. It explicitly excludes the **unmatched** OpenSSL/curl HTTPS control workload from comparative flow measurements.

Run \`python3 tools/test-traffic-study.py\` for no-network input validation tests. Run the six-capture experiment using \`FEDUP_TUN_TRANSPORT\` and \`FEDUP_CAPTURE_PCAP\` as documented in docs/ru/traffic-study.md. GitHub CI runs the whole procedure as part of the disposable namespace test suite.

**Evidence boundaries:** A repeated matched raw/h2 comparison tells us how two FedUp implementations differ, not how accurately commercial or government DPI can recognize them. No model is trained; no TPR/FPR or invisibility percentage is inferred. For that we need independent real browser HTTPS distributions, network variability, controlled negative samples and a held-out dataset. The capture is synthetic; never upload private browsing PCAPs to CI.

## First completed repeated run

Successful GitHub Actions: https://github.com/mirivlad/fedup/actions/runs/42583691995

Three independent synthetic captures per mode:

| Observed metric | Raw TLS | True HTTP/2 |
| --- | ---: | ---: |
| Independent samples | 3 | 3 |
| ClientHello size (min / median / max), bytes | 223 / 223 / 223 | 232 / 232 / 232 |
| Offered cipher suites | 9 | 9 |
| Offered ALPN | absent | h2 |
| TCP frame count (min / median / max) | 183 / 183 / 183 | 115 / 118 / 118 |
| TCP payload bytes (median) | 10,150 | 10,572 |
| Capture time window (median), ms | 10,014.1 | 10,004.3 |

The sets of observed extension identifiers differed across the three captures in each group despite stable ClientHello size; no causal explanation or fingerprint classifier is inferred from that alone.

These are **small synthetic matched-workload comparisons of two FedUp modes**. They do not represent browser HTTPS, real-world IP blocking, transport speed under Internet conditions or any classifier's true/false positive rate. The test orchestration affects capture duration and virtual interfaces may affect frame sizing. A standards-compliant ALPN h2 label and HTTP/2 frames do not make the rustls ClientHello browser-identical.
