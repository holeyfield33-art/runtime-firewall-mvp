# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-20

### Added

- **Behavioral detection pass (`FW_ENABLE_BEHAVIORAL`)**: default on (`1`); set to `0` to disable the behavioral pass and retain signature scanning only. Behavioral analysis tracks dangerous action sequences across and within modules using a state machine (see README for the five rules). Adversarial suite results: 14/14 test cases pass with behavioral on, 12/14 with behavioral off (tests 6 and 7 assert a behavioral event type in the detection record; both modules are still blocked by signature scanning when behavioral is disabled). Set `FW_ENABLE_BEHAVIORAL=0` for signature-only mode in environments where behavioral false-positive rate is unacceptable.

- **Behavioral scope reset at dependency-tree root**: the cross-module behavioral state machine resets when a new dependency-tree root is compiled (`this.parent === null`). This prevents a benign module that reads a credential file in one dependency tree from poisoning the global state and triggering a false positive when an unrelated tree later makes a network call.

- **Self-integrity check at startup**: on every startup the firewall computes a SHA-256 hash over the concatenated bytes of all seven engine files in a fixed order (`index.js`, `src/detector.js`, `src/behavior-tracker.js`, `src/policy-watcher.js`, `src/quarantine.js`, `src/audit-log.js`, `src/policy.js`) and compares it to `.helios-baseline`. If the firewall code has been tampered with, startup is aborted with exit code 1. On first run with no baseline file, the baseline is written automatically.

- **Policy integrity verification (SHA-256 file-hash tamper detection via PolicyWatcher)**: `policy.signed.json` rules are loaded on startup. The `PolicyWatcher` computes the file's SHA-256 hash at load time and re-verifies it every 60 seconds. If the file is modified or replaced at runtime, an emergency lockdown is activated that causes all subsequent module loads to throw immediately. Note: the `.signed` convention in the filename means the file is integrity-monitored at runtime via SHA-256 file hashing — this is NOT asymmetric/cryptographic signing.

- **npm lifecycle script scanning**: on startup, `package.json` scripts are scanned for supply-chain attack patterns (`curl | bash`, `wget | sh`, `bash -c '...'`, `eval $`, `base64 --decode`, etc.). Matches are blocked before any application code runs. Set `HELIOS_BLOCK_SCRIPTS=0` to downgrade from block to warn.

- **Telemetry worker thread (fail-open)**: `FW_TELEMETRY=1` starts a worker thread that batches detection events and POSTs them to `http://localhost:$FW_CONTROL_PORT/v1/telemetry` (default port 3000). With no control plane running the worker swallows connection errors silently and delivers nothing -- fail-open is intentional so the host application is never blocked by a missing control plane. No control plane ships in this package; see `packages/fw-control` in the monorepo for the optional server.

- **Zero runtime dependencies**: `aletheia-firewall` has no `dependencies` or `optionalDependencies`. All capabilities use Node.js built-in modules only (`fs`, `crypto`, `module`, `worker_threads`, `http`, `path`, `os`).

- **Aho-Corasick signature scanner**: O(N) multi-pattern matching over the first 2 KB of each module source, with 24 signatures covering crypto-miners, dynamic code execution, process/shell execution, outbound network egress, and supply-chain worm indicators.

- **Quarantine mode**: modules matching a `QUARANTINE` policy rule or triggering a `MEDIUM`-severity behavioral detection have their exports replaced with a logging `Proxy` that intercepts all property access and method calls without executing the module's code. Child `require()` calls from a quarantined module are also blocked.

- **Persistent append-only audit log**: every security event is written as a JSON line to `HELIOS_LOG_DIR` (default `/var/log/helios/audit.log`, falling back to `$TMPDIR/helios/audit.log`). Log files rotate at 10 MB, keeping 5 generations.

- **Graceful shutdown**: `SIGTERM` and `SIGINT` flush pending telemetry, terminate the worker thread, flush the audit log, and exit cleanly.

### Fixed

- **F-01 (HIGH) — sub-512B module scan-skip removed**: `src/detector.js` previously returned `OBSERVE` immediately for any module under 512 bytes, bypassing both signature and behavioral analysis entirely. A 487-byte `eval(require("child_process").exec("id"))` payload produced zero detections. The unconditional size pre-filter has been removed; all non-empty string content is now scanned. Gate overhead rose from ~17-20% to ~21% on EPYC hardware; the 25% budget is not breached.

- **F-02 (MEDIUM) — `src/policy.js` added to the 7-file self-integrity hash**: `policy.js` ships in the tarball and is `require()`d at runtime by the hashed engine file `quarantine.js`. It was excluded from the 6-file SHA-256 hash, so post-install tampering of `policy.js` was undetected. Now hashed as the 7th engine file. `.helios-baseline` regenerated to `935dfdc24026b0be17b6a42188f449f59fecb86ccd568ceb0eac588bc921232f`.

- **F-03 (MEDIUM) — adversarial test-harness state contamination fixed**: the shared `Detector` instance caused `BehaviorTracker.globalState` to accumulate across test cases; test 12 was firing `CROSS_MODULE_CODE_EXEC` via state leaked from test 7, not standalone detection. Added `detector.behaviorTracker.reset()` in the `test()` helper so each case starts clean. Two F-01 regression fixtures added as tests 13 and 14.

### Performance

Measured on a 900-module cold load (methodology: `run-gate-test.js`, median-of-5 cold-process A/B, 10-iteration warmup excluded), Node v22 (CI: 18, 20, 22), Linux x64:

| Host | Median overhead | Gate budget | P95 overhead | Enforced? |
|------|----------------|-------------|-------------|-----------|
| AMD EPYC 9V74 (80-core) | ~20% | 25% | ~25-27% | Median only |
| AMD EPYC 7763 (64-core) | ~17% | 25% | ~31-37% | Median only |

Post-v0.1.0-prerelease-fix (sub-512B scan-skip removed): median rose to ~21% on EPYC hardware — still within the 25% budget. See `results/gate-post-f01.txt` for the committed benchmark run.

Source files: `results/bench-n10-run-*.txt` (EPYC 9V74), `results/gate-3x-epyc-20260618.txt` (EPYC 7763), `results/gate-post-f01.txt` (post-F-01 fix).

The gate enforces the **median only** at a 25% budget. P95 is reported for operational transparency but is not a fail condition; it reflects shared-CPU scheduler contention on multi-tenant hardware, not firewall algorithmic cost, and is not stable across hosts.

[unreleased]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/releases/tag/v0.1.0
