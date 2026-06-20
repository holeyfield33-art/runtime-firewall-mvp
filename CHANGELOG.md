# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-20

### Added

- **Behavioral detection pass (`FW_ENABLE_BEHAVIORAL`)**: default on (`1`); set to `0` to disable the behavioral pass and retain signature scanning only. Behavioral analysis tracks dangerous action sequences across and within modules using a state machine (see README for the five rules). Adversarial suite results: 12/12 blocked with behavioral on, 10/12 with behavioral off (the two that drop are the dedicated behavioral-assertion tests that also require a behavioral event type in the detection record). Set `FW_ENABLE_BEHAVIORAL=0` for signature-only mode in environments where behavioral false-positive rate is unacceptable.

- **Behavioral scope reset at dependency-tree root**: the cross-module behavioral state machine resets when a new dependency-tree root is compiled (`this.parent === null`). This prevents a benign module that reads a credential file in one dependency tree from poisoning the global state and triggering a false positive when an unrelated tree later makes a network call.

- **Self-integrity check at startup**: on every startup the firewall computes a SHA-256 hash over the concatenated bytes of all six engine files in a fixed order (`index.js`, `src/detector.js`, `src/behavior-tracker.js`, `src/policy-watcher.js`, `src/quarantine.js`, `src/audit-log.js`) and compares it to `.helios-baseline`. If the firewall code has been tampered with, startup is aborted with exit code 1. On first run with no baseline file, the baseline is written automatically.

- **Signed policy enforcement with continuous integrity verification**: `policy.signed.json` rules are loaded on startup. The `PolicyWatcher` computes the file's SHA-256 hash at load time and re-verifies it every 60 seconds. If the file is modified or replaced at runtime, an emergency lockdown is activated that causes all subsequent module loads to throw immediately.

- **npm lifecycle script scanning**: on startup, `package.json` scripts are scanned for supply-chain attack patterns (`curl | bash`, `wget | sh`, `bash -c '...'`, `eval $`, `base64 --decode`, etc.). Matches are blocked before any application code runs. Set `HELIOS_BLOCK_SCRIPTS=0` to downgrade from block to warn.

- **Telemetry worker thread (fail-open)**: `FW_TELEMETRY=1` starts a worker thread that batches detection events and POSTs them to `http://localhost:$FW_CONTROL_PORT/v1/telemetry` (default port 3000). With no control plane running the worker swallows connection errors silently and delivers nothing -- fail-open is intentional so the host application is never blocked by a missing control plane. No control plane ships in this package; see `packages/fw-control` in the monorepo for the optional server.

- **Zero runtime dependencies**: `aletheia-firewall` has no `dependencies` or `optionalDependencies`. All capabilities use Node.js built-in modules only (`fs`, `crypto`, `module`, `worker_threads`, `http`, `path`, `os`).

- **Aho-Corasick signature scanner**: O(N) multi-pattern matching over the first 2 KB of each module source, with 24 signatures covering crypto-miners, dynamic code execution, process/shell execution, outbound network egress, and supply-chain worm indicators.

- **Quarantine mode**: modules matching a `QUARANTINE` policy rule or triggering a `MEDIUM`-severity behavioral detection have their exports replaced with a logging `Proxy` that intercepts all property access and method calls without executing the module's code. Child `require()` calls from a quarantined module are also blocked.

- **Persistent append-only audit log**: every security event is written as a JSON line to `HELIOS_LOG_DIR` (default `/var/log/helios/audit.log`, falling back to `$TMPDIR/helios/audit.log`). Log files rotate at 10 MB, keeping 5 generations.

- **Graceful shutdown**: `SIGTERM` and `SIGINT` flush pending telemetry, terminate the worker thread, flush the audit log, and exit cleanly.

### Performance

Measured on a 900-module cold load (methodology: `packages/fw-control/test/bench.js`, median-of-5 cold-process A/B, 10-iteration warmup excluded), Node.js v24, Linux x64:

| Host | Median overhead | Gate budget | P95 overhead | Enforced? |
|------|----------------|-------------|-------------|-----------|
| AMD EPYC 9V74 (80-core) | ~20% | 25% | ~25-27% | Median only |
| AMD EPYC 7763 (64-core) | ~17% | 25% | ~31-37% | Median only |

Source files: `results/bench-n10-run-*.txt` (EPYC 9V74), `results/gate-3x-epyc-20260618.txt` (EPYC 7763).

The gate enforces the **median only** at a 25% budget. P95 is reported for operational transparency but is not a fail condition; it reflects shared-CPU scheduler contention on multi-tenant hardware, not firewall algorithmic cost, and is not stable across hosts.

[unreleased]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/releases/tag/v0.1.0
