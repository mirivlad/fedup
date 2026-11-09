# Repeated synthetic FedUp traffic fingerprint experiment

We now collect **three independent packet captures per mode** for the *same* three-namespace IP workload, using raw TLS and genuine HTTP/2 (ALPN h2). This addresses the prior single-sample limitation without manufacturing a network censor detection rate.

The no-network Python tool \`tools/traffic-profile.py\` extracts a synthetic ClientHello and TCP flow metadata from each classic PCAP. \`tools/traffic-study.py\` validates provenance/ALPN, requires a minimum of three paired observations, and reports minimum, median, maximum and the number of distinct observed handshake shapes per mode. It explicitly excludes the **unmatched** OpenSSL/curl HTTPS control workload from comparative flow measurements.

Run \`python3 tools/test-traffic-study.py\` for no-network input validation tests. Run the six-capture experiment using \`FEDUP_TUN_TRANSPORT\` and \`FEDUP_CAPTURE_PCAP\` as documented in docs/ru/traffic-study.md. GitHub CI runs the whole procedure as part of the disposable namespace test suite.

**Evidence boundaries:** A repeated matched raw/h2 comparison tells us how two FedUp implementations differ, not how accurately commercial or government DPI can recognize them. No model is trained; no TPR/FPR or invisibility percentage is inferred. For that we need independent real browser HTTPS distributions, network variability, controlled negative samples and a held-out dataset. The capture is synthetic; never upload private browsing PCAPs to CI.
