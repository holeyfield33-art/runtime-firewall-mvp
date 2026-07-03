<!-- markdownlint-disable-file MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-07-03

### Fixed

- **F-02a (HIGH) — Dev-key policy verification refused in production**: `PolicyWatcher` fell back to the bundled Ed25519 dev key when `FW_POLICY_PUBKEY` was not set. The dev private key (`scripts/dev-private-key.pem`) is committed to the public repository, so any attacker could forge a valid policy signature and a forgetful production deploy would trust it — defeating the F-02 fix entirely. `start()` now refuses to load a policy file using the dev key unless `FW_ALLOW_DEV_POLICY_KEY=1` is explicitly set. Operators must either supply `FW_POLICY_PUBKEY` (their own production key) or set `FW_ALLOW_DEV_POLICY_KEY=1` to acknowledge the dev-key risk in local/dev/CI environments. Agents with no `policy.signed.json` on disk are unaffected — the guard only fires when a policy file is actually present.

## [0.2.1] - 2026-07-02

### Fixed

- **F-09 (MEDIUM) — Dashboard always authenticated**: `fw-control` previously left `/logs` open when `HELIOS_DASHBOARD_TOKEN` was not set (warning only). Now, if no token is provided, a cryptographically strong 32-byte random token is auto-generated at startup and printed once to stdout. The endpoint is therefore always protected — operators who want a stable token set `HELIOS_DASHBOARD_TOKEN` in their environment; those who do not still get auth, just ephemeral.

- **F-10 (LOW) — Self-integrity baseline is no longer trust-on-first-use**: `verifySelfIntegrity()` previously created `.helios-baseline` from the current disk state on first run if the file was absent. An attacker who tampered with the agent code and deleted the baseline file would get a freshly trusted hash. The `else` branch is replaced with a hard `process.exit(1)`: a missing baseline is treated the same as a failed hash comparison. The baseline is committed to the repository and shipped in the npm package, so it will always be present for legitimate installs.

- **F-11 (LOW) — Prototype freeze is now opt-in**: `primitiveLockdown()` previously froze `Object/Array/Function/Promise/RegExp` prototypes unconditionally on agent load. This breaks legitimate libraries (polyfills, some ORMs, test frameworks) silently. The lock is now gated on `FW_FREEZE_PROTOTYPES=1`. Default is off; operators who want the hardening set the flag explicitly.

- **F-12 (LOW) — Compile cache keyed on content hash**: `verifiedCompilationsCache` was a `Set` of filenames. A file rewritten on disk and re-required in a long-lived process (e.g. after `delete require.cache[f]`) would not be re-scanned. Changed to a `Map<filename, sha256>`: the cache only bypasses the scan when both the filename and the SHA-256 of the current content match the previously scanned version.

## [0.2.0] - 2026-07-02

### Fixed

- **F-03 (HIGH) — Full-content scanning**: The signature scanner previously truncated all modules to the first 2 KB before running Aho-Corasick, allowing malicious code to hide after an innocent-looking header. The truncation is removed; all module content is now scanned. Aho-Corasick is O(N) so this costs nothing asymptotically. Added adversarial regression test case 15 (3 KB benign padding + `stratum` URL at end → BLOCKED).

- **F-02 (HIGH) — Asymmetric policy signing replaces TOFU hash baseline**: `PolicyWatcher` no longer stores a SHA-256 hash in a sidecar `.baseline` file. Instead, `policy.signed.json` must carry a valid Ed25519 signature over its canonical payload `{ version, rules (sorted), signedAt }`. An invalid or missing signature triggers immediate lockdown — fail-closed with no backward-compatibility grace period. The public key is compiled into `src/policy-watcher.js` and is therefore part of the self-integrity hash. Operators can override it via `FW_POLICY_PUBKEY` (PEM). Utility scripts: `scripts/generate-policy-key.js`, `scripts/sign-policy.js`.

- **F-06 (MEDIUM) — Policy hot-reload without restart**: `PolicyWatcher` now delivers rules to `index.js` via an `onValidChange(rules)` callback on startup and on every verified policy update. When the periodic check detects a valid new signature with different rules, `policyMap` is rebuilt in place without restarting the process. Invalid signatures still trigger lockdown.

- **F-07 (MEDIUM) — Behavioral analysis no longer skips small modules**: `BehaviorTracker.analyzeModule()` had a `content.length < 100` guard that silently dropped all analysis for tiny modules. Removed. Added adversarial regression test case 16 (48-byte credential-exfiltration module → BLOCKED via behavioral detection).

- **F-08 (MEDIUM) — NETWORK_EGRESS regex extended**: Inline `require("https").get(...)` and `require("http").request(...)` patterns were not matched by the behavioral `NETWORK_EGRESS` regexes (which looked for `https.get(` as a bare identifier). Added: `/require\s*\(\s*['"]https?['"]\s*\)\s*\.\s*(?:get|request)\s*\(/`.

- **F-09 (MEDIUM) — Control plane binds to 127.0.0.1 by default**: `fw-control` previously listened on `0.0.0.0`, exposing the telemetry and dashboard endpoints on all network interfaces. Default host is now `127.0.0.1`. Production deployments that need external access should place a TLS-terminating reverse proxy in front.

- **F-13 (LOW) — Control plane warns when dashboard is unauthenticated**: If `HELIOS_DASHBOARD_TOKEN` is not set, `fw-control` now logs a startup warning rather than silently accepting all requests to `/logs`.

### Added

- `scripts/generate-policy-key.js`: generates a new Ed25519 key pair and prints instructions for embedding the public key and signing policies.
- `scripts/sign-policy.js`: signs a rules JSON file with a private key and writes a `policy.signed.json` ready for deployment. Also exports `{ signPolicy }` for programmatic use in tests.
- `scripts/dev-private-key.pem`: **development/CI private key — DO NOT use in production.** The corresponding public key is compiled into `src/policy-watcher.js`. Generate your own key pair before deploying.
- `packages/fw-agent/policy.signed.json`: example policy file signed with the dev key (empty rules — add your own BLOCK/QUARANTINE/OBSERVE entries and re-sign).

### Changed

- `PolicyWatcher` constructor API: second argument is now `{ onTamperDetected, onValidChange }` (callbacks object) instead of a bare function. `options.intervalMs` is unchanged.
- `detector.stats`: `chunkBypasses` counter removed (truncation is gone); `warnOnlyDetections` counter added for WARN-tier signature matches.
- `index.js` module-load hook: WARN-only detections (`warnOnly: true`) now emit `OBSERVE` telemetry and never escalate to `QUARANTINE`. Only `HIGH`/`CRITICAL`/`MEDIUM` block-tier detections affect module execution.

## [0.1.1] - 2026-07-02

### Fixed

- **F-01 (CRITICAL) — CI pipeline**: Unit and adversarial test steps were executing `npm test` inside `packages/fw-agent/`, which has no `scripts.test`. All test scripts now run from the monorepo root using `npm run test:unit` and `npm run test:adversarial` against the correct root `package.json`.

- **F-05 (MEDIUM) — Quarantine no longer kills the host process**: `QuarantineStub.record()` contained a `process.exit(9)` that fired when more than 100 intercepts occurred within 1 ms ("Wilsonian Regulator"). Killing the host application on a potential exhaustion probe defeats the point of a graceful quarantine. Replaced with a rate-limited `console.warn` (logs once per 10 occurrences) and an early `return` so the proxy remains inert without crashing the service.

- **F-04 (HIGH) — Reduced false positives via signature tiering**: The single `SIGNATURES` array (26 patterns, one AhoCorasick instance) is replaced with two tiers:
  - **`BLOCK_SIGNATURES`** (19 patterns, unchanged blocking behaviour): crypto-miner pool identifiers, `eval(`, `new function`, `child_process.*`, `execsync`, `spawnsync`, `curl` (with trailing space), `wget` (with trailing space), pastebin URLs.
  - **`WARN_SIGNATURES`** (7 patterns, `OBSERVE`-only, never block): `buffer.from`, `atob(`, `btoa(`, `https.request`, `http.request`, `net.createconnection`, `socket.connect`.
  WARN-tier matches produce a `{ severity: 'WARN', warnOnly: true }` detection entry and are counted in `stats.warnOnlyDetections` but never escalate to `QUARANTINE`.

### Added

- **F-14 — Basic test coverage** for previously untested components:
  - `packages/fw-agent/test/quarantine-unit-test.js`: proxy inertness, rate-limit behaviour, no `process.exit`.
  - `packages/fw-agent/test/policy-watcher-unit-test.js`: `verify()` pass/fail, lockdown callback, timer interval configurable via constructor `options.intervalMs`.
  - `packages/fw-agent/test/audit-log-unit-test.js`: file write, multi-line output, stderr fallback.
  - `packages/fw-control/test/control-plane-auth-test.js`: `/logs` 401 without token, 200 with correct token, 401 with wrong token, `/v1/health` unauthenticated.

## [0.1.0] - 2026-06-20

### Added

- **Behavioral detection pass (`FW_ENABLE_BEHAVIORAL`)**: default on (`1`); set to `0` to disable the behavioral pass and retain signature scanning only. Behavioral analysis tracks dangerous action sequences across and within modules using a state machine (see README for the five rules). Adversarial suite results: 14/14 test cases pass with behavioral on, 12/14 with behavioral off (tests 6 and 7 assert a behavioral event type in the detection record; both modules are still blocked by signature scanning when behavioral is disabled). Set `FW_ENABLE_BEHAVIORAL=0` for signature-only mode in environments where behavioral false-positive rate is unacceptable.

- **Behavioral scope reset at dependency-tree root**: the cross-module behavioral state machine resets when a new dependency-tree root is compiled (`this.parent === null`). This prevents a benign module that reads a credential file in one dependency tree from poisoning the global state and triggering a false positive when an unrelated tree later makes a network call.

- **Self-integrity check at startup**: on every startup the firewall computes a SHA-256 hash over the concatenated bytes of all seven engine files in a fixed order (`index.js`, `src/detector.js`, `src/behavior-tracker.js`, `src/policy-watcher.js`, `src/quarantine.js`, `src/audit-log.js`, `src/policy.js`) and compares it to `.helios-baseline`. If the firewall code has been tampered with, startup is aborted with exit code 1. On first run with no baseline file, the baseline is written automatically.

- **Policy integrity verification (SHA-256 file-hash tamper detection via PolicyWatcher)**: `policy.signed.json` rules are loaded on startup. The `PolicyWatcher` computes the file's SHA-256 hash at load time and re-verifies it every 60 seconds. If the file is modified or replaced at runtime, an emergency lockdown is activated that causes all subsequent module loads to throw immediately. Note: the `.signed` convention in the filename means the file is integrity-monitored at runtime via SHA-256 file hashing — this is NOT asymmetric/cryptographic signing.

- **npm lifecycle script scanning**: on startup, `package.json` scripts are scanned for supply-chain attack patterns (`curl | bash`, `wget | sh`, `bash -c '...'`, `eval $`, `base64 --decode`, etc.). Matches are blocked before any application code runs. Set `HELIOS_BLOCK_SCRIPTS=0` to downgrade from block to warn.

- **Telemetry worker thread (fail-open)**: `FW_TELEMETRY=1` starts a worker thread that batches detection events and POSTs them to `http://localhost:$FW_CONTROL_PORT/v1/telemetry` (default port 3000). With no control plane running the worker swallows connection errors silently and delivers nothing -- fail-open is intentional so the host application is never blocked by a missing control plane. No control plane ships in this package; see `packages/fw-control` in the monorepo for the optional server.

- **Zero runtime dependencies**: `aletheia-firewall` has no `dependencies` or `optionalDependencies`. All capabilities use Node.js built-in modules only (`fs`, `crypto`, `module`, `worker_threads`, `http`, `path`, `os`).

- **Aho-Corasick signature scanner**: O(N) multi-pattern matching over the first 2 KB of each module source, with 27 signatures covering crypto-miners, dynamic code execution, process/shell execution, outbound network egress, supply-chain worm indicators, and native binding/VM escape vectors.

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
| ---- | --------------- | ----------- | ------------ | --------- |
| AMD EPYC 9V74 (80-core) | ~20% | 25% | ~25-27% | Median only |
| AMD EPYC 7763 (64-core) | ~17% | 25% | ~31-37% | Median only |

Post-v0.1.0-prerelease-fix (sub-512B scan-skip removed): median rose to ~21% on EPYC hardware — still within the 25% budget. See `results/gate-post-f01.txt` for the committed benchmark run.

Source files: `results/bench-n10-run-*.txt` (EPYC 9V74), `results/gate-3x-epyc-20260618.txt` (EPYC 7763), `results/gate-post-f01.txt` (post-F-01 fix).

The gate enforces the **median only** at a 25% budget. P95 is reported for operational transparency but is not a fail condition; it reflects shared-CPU scheduler contention on multi-tenant hardware, not firewall algorithmic cost, and is not stable across hosts.

[unreleased]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/releases/tag/v0.1.0
