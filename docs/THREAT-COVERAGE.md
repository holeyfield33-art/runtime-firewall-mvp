# Threat Coverage Matrix

The authoritative, test-backed list of what the Aletheia firewall **protects against** and what
it **does not** (known bypasses). Every "Protected" row maps to an assertion in the test suites;
every "Bypass" row is either asserted as an expected bypass in the adversarial suite or is an
architectural scope boundary documented below.

- Detection engine: `packages/fw-agent/src/detector.js` (signatures) + `packages/fw-agent/src/behavior-tracker.js` (behavioral rules).
- Tests: `packages/fw-agent/test/behavior-tracker-unit-test.js`, `detector-unit-test.js`, `packages/fw-control/test/adversarial/adversarial.test.js`.
- Enforcement mapping: HIGH/CRITICAL → hard block (`require()` throws); WARN/MEDIUM → `OBSERVE` telemetry, module runs.

Last verified against the adversarial suite (all passing) and the engine-core coverage gate (100% lines / functions, ≥95% branches).

---

## 1. Protected — signature tier (Aho-Corasick, `BLOCK_SIGNATURES`)

O(N) full-content scan. A match is a hard block (crypto → CRITICAL, otherwise HIGH).

| Threat class | Signatures | Test |
|---|---|---|
| Crypto-miner pool URLs | `stratum+tcp`, `stratum://`, `pool.hashvault`, `coin-hive`, `coinhive`, `xmr-stak`, `nicehash`, `cryptonight` | adversarial "Crypto-miner stratum pool reference is blocked" |
| Crypto-miner brands (Phase 1) | `coinimp`, `jsecoin`, `webminepool`, `deepminer` | adversarial F-35 |
| Reverse-shell stdio redirect | `bash -i >&`, `sh -i >&`, `/dev/tcp/` | detector unit / signature coverage |
| Reverse-shell tooling (Phase 2, `BLOCK_REGEXES`) | `nc -e`, `ncat --exec`, `socat …EXEC:`, `mkfifo …nc`, `fsockopen(`, `Net.Sockets.TCPClient`, `ruby -rsocket`, `lua -e …os.execute` | adversarial F-40 |
| Supply-chain fetch-and-run | `\| bash`, `//pastebin`, `//paste.ee`, and (Phase 1 `BLOCK_REGEXES`) `\| sh` / `\| dash` / `\| zsh` — anchored `\bsh\b` to avoid `\| sha256sum`/`\| ssh` | adversarial "curl \| bash postinstall", F-38 |

> **Regex tier (`BLOCK_REGEXES`, detector.js):** idioms that a literal substring cannot express
> safely (a bare `\| sh` would match `\| shorten`) are matched with anchored regexes instead.
> They scan raw content (including comments), same as `BLOCK_SIGNATURES` — a benign package that
> writes e.g. `nc -e` in a *comment* would match; the top-100 soak (0 FP) is the guard for this.

> **False-positive guards (F-29):** bare `stratum` / `bash -i` were removed because they matched
> ordinary English prose and unrelated shell invocations. Guarded by the "word list containing
> stratum/substratum/stratus is not flagged" adversarial case.

## 2. Protected — behavioral tier (`behavior-tracker.js` rules)

Full-content regex state machine over dangerous action **sequences**. Catches obfuscated threats
that individual signatures miss.

| Rule | Fires when | Severity → action | Test |
|---|---|---|---|
| `CREDENTIAL_EXFILTRATION` | sensitive path (`.env`, `.ssh`, `id_rsa`, `.aws`, `.netrc`, `secret`, `passwd`, `shadow`, `credentials`) read **AND** network egress | CRITICAL → block | behavior-tracker unit: ".env read + egress", "id_rsa/.ssh/.aws" |
| `CREDENTIAL_EXFILTRATION` (.npmrc) | `.npmrc` read + egress **AND** (`_authToken`/`_auth`/`_password` field, or `{host:…}` override, or hardcoded non-registry destination) | CRITICAL → block | behavior-tracker unit: ".npmrc → non-registry host", "_authToken + host override" |
| `DYNAMIC_CODE_EXEC_CHAIN` | dynamic code (`eval`/`new Function`/`vm`) **AND** process exec (`child_process`/`execSync`/`spawnSync`/…) | CRITICAL → block | detector unit; adversarial "eval + child_process" |
| `OBFUSCATED_CODE_EXECUTION` **(F-31)** | decode (`Buffer.from(…,'base64'/'hex')` / `atob`) **AND** dynamic code (`eval`/`new Function`/`vm`) | HIGH → block | adversarial "Buffer.from base64 decode + eval"; behavior-tracker unit (base64/atob/hex) |

### Deliberate WARN-only (not blocked) — true-negative protection

These patterns are common in **legitimate** code; blocking them would be a false-positive disaster.
They surface as `OBSERVE`/WARN telemetry only.

| Pattern | Rule | Why not blocked |
|---|---|---|
| `process.env` read + network egress | `ENV_NETWORK_EGRESS` | The everyday analytics/telemetry SDK shape (F-16). Escalates to CRITICAL only with a real credential *path*. |
| `.npmrc` read + egress built from config | `NPMRC_NETWORK_EGRESS` | Every npm client reads `.npmrc` to resolve the registry (F-30). |
| Bare `eval(` / `buffer.from` / `child_process.spawn` | signature WARN tier | Appear in build tools, bundlers, test frameworks (F-20/F-26). |
| `require(variable)` (non-literal) | `DYNAMIC_MODULE_LOAD` (MEDIUM) | Pervasive: lazy loading, plugin systems, `require(path.join(...))`. Telemetry only (F-34). |

Guarded by adversarial/behavior-tracker cases: `nice-analytics` (env+https) allowed; decode-only,
eval-only, comment-only-decode, config-built `.npmrc` URL, hardcoded real-registry fetch — all clean.

## 3. Protected — host & lifecycle

| Vector | Mechanism | Test |
|---|---|---|
| Host `package.json` lifecycle scripts (`curl \| bash`, `wget \| sh`, `base64 --decode`, `eval $`) | `index.js` npm-script scanner (blocks by default; `HELIOS_BLOCK_SCRIPTS=0` to warn) | manual / demo |
| Runtime policy file tampered/replaced | `PolicyWatcher` Ed25519 re-verify every 60s → emergency lockdown | `policy-watcher-unit-test.js` |
| Firewall self-tamper | SHA-256 self-integrity vs `.helios-baseline` on startup | CI baseline check |
| Bun/Deno without preload | runtime detection, exit 1 | — |
| Non-`--require` load (strict mode) | `FW_STRICT_PRELOAD=1` real `--require` parsing (F-32) | audit-3 |
| Production with public dev key | refuse to start regardless of policy file (F-33) | audit-1 |

---

## 4. Known bypasses (NOT protected)

These require dynamic (runtime) analysis; static/behavioral analysis is fundamentally limited
against them. Each is asserted as an **expected bypass** in the adversarial suite so we notice if
the boundary ever shifts.

Detection has been raised from **55.2% → 76.0%** (69 → **95 / 125** malicious payloads caught,
**0** false positives on the 26 benign controls and the top-100 soak) across two hardening
phases — see the roadmap below. The **30** payloads that still bypass, grouped by root cause:

| Technique | Example | Why it bypasses | Would need |
|---|---|---|---|
| String-reassembly eval / require | `this["ev"+"al"](code)`, `global["ev"+"al"]`, `const fn = eval`, `Object.getPrototypeOf(eval).constructor`, `require(["ch","ild"].join(""))`, `String.fromCharCode`, unicode-escape, reversed strings | trigger token assembled at runtime; no literal call site in source | AST / taint analysis (Phase 3) |
| WASM / GeneratorFunction / constructor.constructor | `WebAssembly.instantiate`, `GeneratorFunction(code)`, `constructor.constructor(code)()` | no JS `eval`/`Function` literal at all | AST / runtime instrumentation (Phase 3) |
| Decode-without-eval config | miner pool URL held as a base64/hex blob and decoded at runtime, never `eval`'d; config-/env-driven pool with no literal | decode alone is benign (`CODE_DECODE` only chains with `DYNAMIC_CODE`); no signature | taint from decode → sink (Phase 3) |
| `decodeURIComponent` → eval | `eval(decodeURIComponent(...))`, `(0,eval)(decodeURIComponent(...))` | `decodeURIComponent` deliberately **not** a `CODE_DECODE` signal — it is ubiquitous in benign code (query-string parsers), so co-occurrence with `eval` is not enough | dataflow decode→eval (Phase 3) |
| Network + process-exec chain | pure-Node socket→`spawn('/bin/sh')`, HTTP-poll C2 (`fetch` cmd → `exec` → POST) | both primitives present but not linked by a blocking rule; a static "egress + child-process" rule would false-positive on legit CLIs | taint / behavioral sequencing with FP guards (Phase 3) |
| Shell-out / base64 command exec | exfil by shelling to `curl`; `/dev/tcp` base64-encoded then `bash -c` | outbound call is a child process, not a `NETWORK_EGRESS` primitive; command is decoded at runtime | command-string semantics (Phase 3) |
| Low-and-slow / benign-looking C2 | ngrok/telegram/IP-literal beacons, dependency-confusion fetch, deferred (exit-time) beacon, `bash -i` without `>&` | a single outbound call to an attacker host is statically indistinguishable from legitimate telemetry | runtime network egress allow/deny lists (Phase 3) |

**Closed in Phases 1–2** (were bypasses, now caught — kept as regression guards in the red-team
corpus with `knownBypass: false`): inline-require `net`/`tls`/`dgram`/`vm` egress & dynamic-code;
miner brands coinimp/jsecoin/webminepool/deepminer; `.docker/config.json` / `.kube/config` /
browser `Login Data` stores; `\| sh`/`\| dash`/`\| zsh` stagers; `REMOTE_FETCH_EXEC` (fetch→eval);
`nc -e`/`ncat`/`socat`/`mkfifo`/`fsockopen`/PowerShell-TCPClient/`ruby -rsocket`/`lua` reverse
shells; `dns.resolve` & `navigator.sendBeacon` exfil channels; `process.binding` process exec.

### Phased hardening roadmap

- **Phase 1 (done) — signature/list extensions, near-zero FP risk.** Inline-require egress &
  dynamic-code patterns; miner brands + `isCrypto` relabel; `SENSITIVE_CONFIG_PATH` for
  infra/browser cred stores (gated on a *deliberate* exfil destination so legit k8s/docker/browser
  clients are not flagged); anchored `\| sh`/`dash`/`zsh` stager regex. → **55.2% → 64.0%**.
- **Phase 2 (done) — behavioral rules & primitive coverage, each soak-gated.** `REMOTE_FETCH_EXEC`
  (network egress + dynamic code → HIGH); anchored reverse-shell tool signatures; `dns.resolve*`
  and `navigator.sendBeacon` egress channels; `process.binding` in `PROCESS_EXEC`; indirect
  `(0,eval)` in `DYNAMIC_CODE`. → **64.0% → 76.0%**.
- **Phase 3 (planned) — architectural / out of static-scan scope.** AST / taint analysis
  ("Phase 5" below) for string-reassembly, wasm, decode-without-eval, `decodeURIComponent→eval`,
  and network+process-exec chains; **runtime network-egress allow/deny lists** in the agent's
  runtime policy for the low-and-slow C2 class (a static scanner cannot separate an attacker
  beacon from legitimate telemetry).

### Cross-file correlation (opt-in: `FW_ENABLE_CROSSFILE=1`, default OFF)

A malicious package can split an attack across files — read `.env` in `a.js`, exfiltrate in
`b.js` — so no single per-file scan sees both halves. The engine can correlate signals across a
package's files (`analyzePackage()` / `finalizePackage()`), **scoped to one npm package** (never
across the whole app tree, or it would pair a config-reading module with any unrelated HTTP
module). Rules: `CREDENTIAL_EXFILTRATION_CROSS_FILE` (a genuine credential *path* + egress — not
bare `fs.readFile`, which the intra-file rule also excludes) and `DYNAMIC_CODE_EXEC_CHAIN_CROSS_FILE`.

It is **off by default** because soak validation on the top-100 showed it false-positives on
large legitimate packages that legitimately spread capabilities across files: `mongodb` reads
`~/.aws/credentials` and calls the instance-metadata endpoint for IAM auth (statically
indistinguishable from exfil), `babel`/`knex` generate code in one file and spawn processes in
another. Static co-occurrence cannot separate these from a real split attack — that needs the
Phase 3 taint analysis. The registry batch scanner enables it (via `finalizePackage()`) behind
human review of any `*_CROSS_FILE` verdict before it is published.

> These rows (and their benign-control counterparts) are all exercised by the
> **red-team attack suite** (`npm run redteam`, corpus under `red-team/`). Each
> is asserted as a documented *known bypass* so the suite fails only if a
> **new** hole opens (a `caught` case flips to `REGRESSION`) or a benign control
> starts over-blocking. The full machine-readable inventory is the `gap_report`
> array in `results/redteam-summary.json`.

### Architectural scope boundaries (out of scope by design)

| Boundary | Reason |
|---|---|
| Dependency `postinstall` hooks in `node_modules` | The npm installer runs these **before** the firewall loads. Only the host project's own root `package.json` scripts are scanned. Use `npm install --ignore-scripts` + a separate pre-install scan. |
| Bun / Deno full coverage | Preload is enforced (exit if absent) but interception coverage under these runtimes is limited. |
| AST-level obfuscation | Roadmap Phase 5. The behavioral tier mitigates via action-sequence detection but cannot match a determined AST-obfuscated payload. |
| Self-integrity baseline is committed alongside the code | Integrity *verification*, not *protection*: an attacker who can rewrite the source can rewrite `.helios-baseline`. External/signed anchoring is future work. |

---

## 5. How to reproduce this matrix

```bash
npm run test:adversarial   # every Protected/Bypass row above is asserted here or in:
npm run test:unit          # detector + behavior-tracker + policy + quarantine unit tests
npm run test:coverage      # engine-core coverage gate (95%)
npm run test:live          # end-to-end: miner + base64→eval both blocked (Blocked: 2)
npm run redteam            # 151-payload red-team suite: logs caught vs. bypassed + gap report
bash scripts/audit-1-policy.sh && bash scripts/audit-2-interception.sh && bash scripts/audit-3-runtime.sh
```
