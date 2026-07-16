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
| Reverse-shell stdio redirect | `bash -i >&`, `sh -i >&`, `/dev/tcp/` | detector unit / signature coverage |
| Supply-chain fetch-and-run | `\| bash`, `//pastebin`, `//paste.ee` | adversarial "curl \| bash postinstall pattern" |

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

| Technique | Example | Why it bypasses | Would need |
|---|---|---|---|
| Bracket-notation eval | `this["ev"+"al"](code)` | property name assembled dynamically; no `eval(` token | AST / V8 Inspector |
| String-concatenation eval | `global["ev"+"al"](code)` | same, via global | taint tracking |
| Variable-alias eval | `const fn = eval; fn(code)` | no `eval(` call-site token in source | runtime Proxy / taint tracking |
| Prototype-chain access | `Object.getPrototypeOf(eval).constructor(code)` | reaches Function constructor without literal | runtime instrumentation |
| Array-join reassembly | `require(["ch","ild"].join(""))` | module/name assembled at runtime | dynamic taint analysis (may be caught by cross-module state in practice) |

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
bash scripts/audit-1-policy.sh && bash scripts/audit-2-interception.sh && bash scripts/audit-3-runtime.sh
```
