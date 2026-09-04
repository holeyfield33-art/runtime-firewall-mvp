# Threat Coverage Matrix

The authoritative, test-backed list of what the Aletheia firewall **protects against** and what
it **does not** (known bypasses). Every "Protected" row maps to an assertion in the test suites;
every "Bypass" row is either asserted as an expected bypass in the adversarial suite or is an
architectural scope boundary documented below.

- Detection engine: `packages/fw-agent/src/detector.js` (signatures) + `packages/fw-agent/src/behavior-tracker.js` (behavioral rules).
- Tests: `packages/fw-agent/test/behavior-tracker-unit-test.js`, `detector-unit-test.js`, `packages/fw-control/test/adversarial/adversarial.test.js`.
- Enforcement mapping: HIGH/CRITICAL → hard block (`require()` throws); WARN/MEDIUM → `OBSERVE` telemetry, module runs.

Last verified against the adversarial suite (all passing) and the engine-core coverage gate
(≥99% lines, 100% functions, ≥90% branches — the `ast-scan.js` addition in Phase 3 pulled
aggregate branch coverage down from the prior ≥95% floor to just above the gate's 90% minimum;
see `npm run test:coverage`).

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
| `CREDENTIAL_EXFILTRATION` | sensitive path (`.env`, `.ssh`, `id_rsa`, `.aws`, `.netrc`, `secret`, `passwd`, `shadow`, `credentials`) read **AND** network egress, **within 200 characters of each other** | CRITICAL → block | behavior-tracker unit: ".env read + egress", "id_rsa/.ssh/.aws" |
| `CREDENTIAL_EXFILTRATION` (.npmrc) | `.npmrc` read + egress **AND** (`_authToken`/`_auth`/`_password` field, or `{host:…}` override, or hardcoded non-registry destination), **all three within 200 characters of each other** | CRITICAL → block | behavior-tracker unit: ".npmrc → non-registry host", "_authToken + host override"; adversarial "F-43/F-68: new TP" |
| `DYNAMIC_CODE_EXEC_CHAIN` | dynamic code (`eval`/`new Function`/`vm`) **AND** process exec (`child_process`/`execSync`/`spawnSync`/…), **within 200 characters of each other** | CRITICAL → block | detector unit; adversarial "eval + child_process" |
| `OBFUSCATED_CODE_EXECUTION` **(F-31)** | decode (`Buffer.from(…,'base64'/'hex')` / `atob`) **AND** dynamic code (`eval`/`new Function`/`vm`), **within 200 characters of each other** | HIGH → block | adversarial "Buffer.from base64 decode + eval"; behavior-tracker unit (base64/atob/hex) |
| `REMOTE_FETCH_EXEC` | network egress **AND** dynamic code, **within 200 characters of each other** | HIGH → block | adversarial "fetch(...).then(eval)" (F-39) |

**Proximity requirement (F-43/F-68, 2026-08):** every rule above used to check these signals as
whole-file booleans with no requirement that they actually occur near each other — correct for a
small hand-written malicious snippet, but false-positived hard on large bundled/minified files,
where a single chunk routinely contains a credential-path-shaped string, a network call, an
`eval()`, and a decode call somewhere in hundreds of KB of unrelated legitimate code. Confirmed on
the real `vite@8.2.1` `dist/node/chunks/node.js` chunk: a `.npmrc` reference and an unrelated
`host:` object key sit 312 characters apart by coincidence, while the real network call is 68,519
characters away — and the same file independently false-positived three more of the rules above.
Each rule now additionally requires its constituent signals to fall within 200 characters of each
other (swept empirically against the full red-team + adversarial corpus and a real-world
false-positive corpus of 15,728 files across the soak-100 packages plus `vite@8.2.1`/`astro`; see
the fix's commit message for the full sweep table). `astro` inherits the same fix transitively,
since it depends on the identical `vite@^8.0.13` chunk.

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

## 4. Known bypasses (NOT protected by default)

Two configurations now matter here, and they give genuinely different numbers — always say which
one a figure describes:

- **Default** (`FW_ENABLE_AST` unset): signature + behavioral tiers only. **73.4%** (105/143
  malicious payloads caught), **38** known bypasses, **0** false positives on the 36 benign
  controls. This is what a fresh install does out of the box — `npm run redteam`.
- **`FW_ENABLE_AST=1`** (opt-in, off by default pending soak — see §"AST-level detection" below):
  adds a narrow, hand-rolled AST pass. **88.8%** (127/143 caught), **16** known bypasses, **0**
  false positives (the same 36 benign controls, including six added specifically to guard the new
  fold/resolve surface). `npm run redteam:ast`.

> **"0 false positives" is measured against the 36 curated benign controls only** — it is not a
> measured general false-positive rate on arbitrary packages, and must not be read as one. Enabling
> the AST tier by default is gated on a broader benign-package soak (see the roadmap below).

**Benign-package soak with the AST tier enabled.** `aletheia-soak-test.js` now takes `--enable-ast`
(and `--incomplete-policy observe|quarantine|block`) so the AST tier's false-positive rate can be
measured on *real, popular npm packages* rather than the curated controls. Reproduce with:

```bash
npm install <corpus-top100.json packages>          # one-time
node aletheia-soak-test.js --agent ./packages/fw-agent --enable-ast
node aletheia-soak-test.js --agent ./packages/fw-agent --enable-ast --incomplete-policy quarantine
```

A preliminary run (36 of the top-100 packages installed, plus their full transitive `require()`
trees) recorded **0 false positives** under both `observe` and the strictest `quarantine`
incomplete policy, with 5/5 synthetic malicious samples still caught (`results/soak-2026-09-02.jsonl`).
This is **preliminary evidence, not the release gate**: flipping `FW_ENABLE_AST` to on-by-default
requires a *large* soak (the full top-100 and beyond) sustaining a near-zero FP rate. Until then the
AST tier stays opt-in.

**Bounded, prioritized AST scanning (F-91).** The AST tier parses at most a bounded number of
candidate *spans* per file (a large budget for rare high-risk shapes, a small one for ordinary
bundle noise), and it scans them **highest-risk-first**, never in file order. This closes a
span-exhaustion bypass where an attacker padded a module with >40 harmless prescreen-matching decoy
spans ahead of the real payload so it was never parsed. If a genuinely high-risk span is left
unanalyzed because the budget was exhausted, the scan is reported **incomplete** and
`FW_AST_INCOMPLETE_POLICY` decides what happens. Because an incomplete scan *is* the span-exhaustion
attack shape (flood the scanner with high-risk decoys so the real payload falls outside the budget),
the default is **fail-closed**: `quarantine`/`block` (the default) treats an un-analyzable suspicious
module as block-tier, so the bypass is closed by default and not only for operators who opt into a
non-default value; `observe` opts down to WARN-only telemetry for operators who prefer availability.
It only fires on pathological saturation (>256 rare high-risk spans in one module); ordinary large
bundles (many `require()`/`(0, x)`/`.join()` hits) are low-risk and never trip the gate (0 FP across
the AST-enabled benign soak, including under quarantine).

The remaining bypasses genuinely require dynamic (runtime) analysis beyond either tier; each is
asserted as an **expected bypass** in the adversarial and red-team suites so we notice if the
boundary ever shifts. Grouped by root cause, with which tier (if any) closes it:

> **F-1.1 — the default correlation model is text-proximity, not interprocedural.** The
> behavioral-correlation rules in `behavior-tracker.js` (`CREDENTIAL_EXFILTRATION`,
> `DYNAMIC_CODE_EXEC_CHAIN`, `REMOTE_FETCH_EXEC`, etc.) fire when the *positions* of two or more
> signals in a module's source text fall within a bounded structural window — at most
> `CORRELATION_MAX_SEPARATORS` (5) statement/line boundaries apart **and** at most
> `CORRELATION_MAX_CHARS` (8000) characters apart (see `buildSeparatorPrefix()`/`withinContext()`
> in `behavior-tracker.js`). The *separator* half of this is a genuinely padding-resistant
> proximity measure (F-69) — comment/whitespace padding between two co-located signals adds zero
> separator distance, so it cannot defeat that cap at any size — but the *character* half is a
> hard, disclosed ceiling regardless of padding composition: comment/whitespace padding large
> enough to exceed `CORRELATION_MAX_CHARS` (8000) between the two signals still falls outside the
> window (see the `CORRECTED CLAIM (PENTEST-003 finding)` note directly in `behavior-tracker.js`
> for the full accounting). Neither half of this proximity measure is a call-graph or
> interprocedural data-flow analysis, which is F-1.1's actual subject here. Two signals that are
> each individually
> unremarkable-looking, placed in **separate, ordinary named functions** far enough apart in the
> same file (more than a handful of intervening statements, or a large module), correlate exactly
> as if they were entirely unrelated code, even though a third function calls both in sequence at
> runtime. This is structurally different from the *padding* limitation F-69 already closed:
> padding tries to widen the textual gap between two signals that would otherwise sit together;
> function indirection is two signals that were never textually close to begin with, because
> ordinary program structure (function decomposition) put them in different places. Neither the
> signature tier nor the AST tier addresses this — the AST tier resolves *obfuscated or folded*
> signals back to their plain-text form so the existing regex/proximity checks can re-match them;
> it does not trace calls between functions. See `krc-function-indirection-exfil` in
> `red-team/corpus/credential-exfil.js` for a fixture reproducing this with concrete, otherwise
> real credential-exfiltration signals, tracked as an accepted, expected bypass (confirmed not
> closed by `FW_ENABLE_AST=1` either). Do not read this as arbitrary interprocedural or dataflow
> analysis being partially present and merely incomplete — none exists today; a bounded, narrow
> one-hop AST-level function-correlation pass is tracked as a separate future P2 enhancement, not
> a pre-release blocker (see the roadmap below).

| Technique | Example | Why it bypasses | Closed by |
|---|---|---|---|
| Function-indirection (same-file) | credential read and network egress each in their own ordinary named function, called from a third wiring function, with several unrelated statements between the two function definitions | correlation is text-proximity within a bounded window (≤5 statement boundaries, ≤8000 chars); functions placed apart in normal program structure fall outside it even though nothing is obfuscated | **Neither tier** — needs bounded interprocedural (one-hop call) correlation, tracked as future work |
| String-reassembly eval / require | `this["ev"+"al"](code)`, `global["ev"+"al"]`, `const fn = eval`, `Object.getPrototypeOf(eval).constructor`, `require(["ch","ild"].join(""))`, `String.fromCharCode`, unicode-escape, reversed strings | trigger token assembled at runtime; no literal call site in source | **AST tier** (`FW_ENABLE_AST=1`) |
| GeneratorFunction / constructor.constructor | `GeneratorFunction(code)`, `constructor.constructor(code)()` | no JS `eval`/`Function` literal at all — but a real, parseable JS *shape* | **AST tier** (`FW_ENABLE_AST=1`) |
| WASM | `WebAssembly.instantiate(bytes)` | no JS source text exists to parse or fold — architecturally unreachable by any JS-source AST, not merely unimplemented | **Not closeable by AST at all** — would need runtime/native instrumentation |
| Decode-without-eval config (literal in source) | miner pool URL held as a base64/hex blob, decoded at runtime, never `eval`'d, where the *encoded* form is a literal | decode alone is benign (`CODE_DECODE` only chains with `DYNAMIC_CODE`); no signature matches the encoded literal | **AST tier**: the decode is folded and the *decoded* value re-matched |
| Decode-without-eval config (env/runtime-sourced) | pool URL read from `process.env`/config, never a literal anywhere in source | nothing for a static fold to resolve — the value doesn't exist in source text at all | **Not closeable by AST** — needs runtime taint tracking |
| `decodeURIComponent` → eval | `eval(decodeURIComponent(...))`, `(0,eval)(decodeURIComponent(...))` | `decodeURIComponent` deliberately **not** a `CODE_DECODE` signal — it is ubiquitous in benign code (query-string parsers), so co-occurrence with `eval` is not enough | **AST tier**: recognized structurally as a CODE_DECODE-class primitive, correlates with the existing `eval(` match |
| Literal string/path reassembly | `'/etc/' + 'sha' + 'dow'`, `['/.ss','h/id_','rsa'].join('')` | no literal substring survives in source for `SENSITIVE_PATH`/`BLOCK_SIGNATURES` to match | **AST tier**: concat/join folded, result re-matched against the existing patterns |
| Network + process-exec chain | pure-Node socket→`spawn('/bin/sh')`, HTTP-poll C2 (`fetch` cmd → `exec` → POST) | both primitives present but not linked by a blocking rule; a static "egress + child-process" rule would false-positive on legit CLIs | **Neither tier** — needs cross-statement taint / behavioral sequencing with real FP guards |
| Shell-out command exec | exfil by shelling to `curl` with an *unfolded* (runtime-built) argument | outbound call is a child process, not a `NETWORK_EGRESS` primitive; the exfiltrated data isn't a foldable literal | **Neither tier** — needs command-string semantics beyond static folding |
| Low-and-slow / benign-looking C2 | ngrok/telegram/IP-literal beacons, dependency-confusion fetch, deferred (exit-time) beacon, `bash -i` without `>&` | a single outbound call to an attacker host is statically indistinguishable from legitimate telemetry | **Neither tier** — needs runtime network-egress allow/deny lists |

**Closed in Phases 1–2** (were bypasses, now caught unconditionally — kept as regression guards in
the red-team corpus with `knownBypass: false`): inline-require `net`/`tls`/`dgram`/`vm` egress &
dynamic-code; miner brands coinimp/jsecoin/webminepool/deepminer; `.docker/config.json` /
`.kube/config` / browser `Login Data` stores; `\| sh`/`\| dash`/`\| zsh` stagers;
`REMOTE_FETCH_EXEC` (fetch→eval); `nc -e`/`ncat`/`socat`/`mkfifo`/`fsockopen`/PowerShell-TCPClient/
`ruby -rsocket`/`lua` reverse shells; `dns.resolve` & `navigator.sendBeacon` exfil channels;
`process.binding` process exec.

**Closed under `FW_ENABLE_AST=1`, opt-in** (were bypasses under default settings, now caught when
the AST tier is enabled — corpus entries keep `knownBypass: true` since that reflects the true
*default*-configuration state, with a description note pointing at this section; flipping the flag
would make `npm run redteam`'s default run misrepresent out-of-the-box behavior, exactly the
overclaiming risk this project's docs otherwise go out of their way to avoid): `dce-bracket-eval`,
`dce-alias-eval`, `dce-join-require`, `dce-unicode-escape-eval`, `dce-eval-decodeuri`,
`dce-fromcharcode-eval`, `dce-reverse-eval`, `dce-constructor-constructor`,
`dce-generatorfunction`, `dce-indirect-eval-decodeuri`, `dce-span-exhaustion-front`,
`dce-span-exhaustion-middle`, `dce-span-exhaustion-end`, `miner-concat-stratum`,
`miner-base64-pool`, `miner-charcode-coinhive`, `miner-concat-cryptonight`, `miner-hex-pool`,
`revsh-base64-devtcp`, `exfil-concat-path`, `exfil-concat-etc-shadow`,
`krc-confusable-identifier-evasion` (22 total — run `npm run redteam:ast` to reproduce the full
list against `results/redteam-summary.json`).

**Still open under `FW_ENABLE_AST=1`** (16): `miner-hex-pool`'s config-driven sibling
`miner-env-pool`; `miner-wasm`/`dce-wasm-code`; `revsh-node-net-spawn`, `revsh-node-http-beacon`,
`revsh-bash-i-only`; `exfil-env-via-curl`; `sc-ngrok-beacon`, `sc-telegram-bot`,
`sc-ip-literal-c2`, `sc-dependency-confusion`, `sc-setimmediate-beacon`;
`krc-env-secret-exfiltration`, `krc-registry-mirror-substitution`, `krc-cross-sandbox-pivot` — all
documented above (the last three added by `redteam-kit-adapter`, reproducing the same
env-egress/dependency-confusion/lone-socket-egress gaps in this list under new ids) as needing
dynamic taint tracking or runtime egress allow-listing, not AST; and `krc-function-indirection-exfil`
(F-1.1, documented in the callout above this table), which needs bounded interprocedural
correlation rather than either tier's fold-and-re-match or taint-tracking approach.

### Phased hardening roadmap

Numbering note: this roadmap's phases are **detection-hardening rounds**, a different sequence
from the architectural-milestone "Phase 1–6" in the root `README.md`'s Roadmap section (async
telemetry, signature engine, integrity anchoring, behavioral state machine, ...). Round 3 below
*is* the work README's Roadmap calls "Phase 5: AST-level analysis" — same work, two independent
numbering schemes; stated explicitly here to stop conflating them.

- **Round 1 (done) — signature/list extensions, near-zero FP risk.** Inline-require egress &
  dynamic-code patterns; miner brands + `isCrypto` relabel; `SENSITIVE_CONFIG_PATH` for
  infra/browser cred stores (gated on a *deliberate* exfil destination so legit k8s/docker/browser
  clients are not flagged); anchored `\| sh`/`dash`/`zsh` stager regex. → **55.2% → 64.0%**.
- **Round 2 (done) — behavioral rules & primitive coverage, each soak-gated.** `REMOTE_FETCH_EXEC`
  (network egress + dynamic code → HIGH); anchored reverse-shell tool signatures; `dns.resolve*`
  and `navigator.sendBeacon` egress channels; `process.binding` in `PROCESS_EXEC`; indirect
  `(0,eval)` in `DYNAMIC_CODE`. → **64.0% → 76.0%**.
- **Round 3 (done, opt-in) — AST-level obfuscation detection.** `packages/fw-agent/src/ast-scan.js`
  (`FW_ENABLE_AST=1`, off by default pending soak — see the note above on why default-posture
  numbers are unaffected). Closes string-reassembly eval/require, GeneratorFunction/
  constructor.constructor, decode-without-eval where the encoded form is a literal,
  `decodeURIComponent→eval`, and literal string/path reassembly. → **74.2% → 90.6%** on the
  original 128-payload corpus when enabled (was 76.0% → 90.4% before the F-91 span-exhaustion
  regression fixtures were added to the corpus; see the note above for the current combined-corpus
  figures after `redteam-kit-adapter` and the F-1.1 function-indirection fixture were added —
  73.4% → 88.8% on 143 payloads).
  Deliberately does NOT attempt WASM (no JS text exists to parse), env-sourced values (nothing in
  source to fold), or network+process-exec taint chains (needs cross-statement dataflow with real
  FP guards, a different problem than AST parsing) — seen below and in the table above as still
  open, not silently dropped.
- **Round 4 (planned) — runtime network-egress allow/deny lists** in the agent's runtime policy,
  for the low-and-slow C2 class a static scanner (AST included) cannot separate from legitimate
  telemetry; and cross-statement taint tracking for the network+process-exec chain and
  shell-out-command classes.
- **P2 (future, investigate only) — bounded one-hop AST function correlation.** F-1.1's
  function-indirection gap (see the callout above): investigate whether the AST tier can extend
  its existing per-span analysis to a deliberately *narrow* interprocedural step — resolving a
  direct, unambiguous call from function A to function B within the same module (one hop, no
  recursion, no dynamic dispatch) so a signal in A and a signal in B reached through that single
  call are treated as correlated. Explicitly NOT a general call-graph or dataflow engine — scope
  creep into that territory is exactly what this line item exists to avoid before it's even
  started. Not a pre-release blocker; tracked as future work only.

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

### Execution-surface coverage (which code paths reach the detector at all)

The tables above cover *what content* is detected once a module reaches the firewall's hook.
This is the separate question of *which execution paths reach a hook in the first place* —
`scripts/execution-surface-matrix.js` (`npm run test:matrix`) is the authoritative, test-backed
answer, re-run on every change to either hook:

| Execution path | Status | Mechanism |
|---|---|---|
| `require()`, nested `require()` | `INTERCEPTED` | `Module.prototype._compile` |
| `worker_threads -> new Worker`, `child_process.fork()`, `child_process.spawn('node', ...)` — child's own `require()`/`import()` calls | `INTERCEPTED` | P0-4 `NODE_OPTIONS` / `execArgv` re-injection + `_compile` |
| `child_process.spawn('node', ['-e', src])` / `execSync('node -e ...')` — inline `-e` source itself | **`BYPASS`**, regardless of preload state | `node -e`'s inline eval path never calls `Module.prototype._compile` or the `registerHooks()` load hook — re-injection makes the child *preloaded*, but "preloaded" only covers what that child subsequently `require()`s/`import()`s, not code passed via `-e` |
| Module cached/loaded before the firewall preloads | `INTERCEPTED` | Content-hash re-scan on cache hit |
| `require.cache` pre-seeded/forged directly (bypassing `_compile` entirely — a forged `Module` or bare `{ exports }` object dropped into `require.cache[resolvedPath]`) | `INTERCEPTED`, policy-controlled | `Module._load` wrap (F-58) — three-state verified/unknown/blocked model, `FW_CACHE_POLICY=block\|audit\|allow` (default: `block` under `FW_MODE=enforce`, `audit` otherwise) |
| `import` (static) / `import()` (dynamic) of a `file://` module URL | `INTERCEPTED` on Node ≥22.15.0/≥23.5.0; **`BYPASS`** below that floor | `module.registerHooks()` (P2-01) — see root `README.md`'s Coverage table for the version-floor detail |
| `import()` of a `data:`, `http:`, `https:`, or `blob:` module URL | **`BYPASS`**, on every Node version, floor or no floor | The `registerHooks()` load hook returns before the detector runs for any non-`file://` scheme (`packages/fw-agent/index.js:623`) — a separate, independent gap from the version-floor one above |
| `vm.runInNewContext()` | `BYPASS` | Executes source directly via V8, never calls `require()`/`_compile` |
| Native addon (`.node`) load | `UNSUPPORTED` (architecturally unreachable) | Routes through `process.dlopen()`, never calls `_compile` |

### Architectural scope boundaries (out of scope by design)

| Boundary | Reason |
|---|---|
| Dependency `postinstall` hooks in `node_modules` | The npm installer runs these **before** the firewall loads. Only the host project's own root `package.json` scripts are scanned. Use `npm install --ignore-scripts` + a separate pre-install scan. |
| Bun / Deno full coverage | Preload is enforced (exit if absent) but interception coverage under these runtimes is limited. |
| `vm.runInNewContext()` | Never routes through `require()`/`_compile` at all — a different execution primitive entirely, not a detection gap. |
| Native addon (`.node`) loads | Not JavaScript source; `process.dlopen()` never calls `_compile`. |
| AST-level obfuscation (default config) | Root README's Roadmap Phase 5. An opt-in tier now exists (`FW_ENABLE_AST=1`, §4 above) but ships off by default pending soak, so default-configuration behavior is unaffected — the behavioral tier alone mitigates via action-sequence detection but cannot match a determined AST-obfuscated payload without it. |
| WASM payloads, env-sourced config values, network+process-exec taint chains | Out of scope even WITH the AST tier enabled — architectural limits of static/AST analysis, not gaps the AST tier missed. See §4's bypass table for why each specifically can't be closed this way. |
| Self-integrity baseline is committed alongside the code | Integrity *verification*, not *protection*: an attacker who can rewrite the source can rewrite `.helios-baseline`. External/signed anchoring is future work. |

---

## 5. How to reproduce this matrix

```bash
npm run test:adversarial   # every Protected/Bypass row above is asserted here or in:
npm run test:unit          # detector + behavior-tracker + policy + quarantine unit tests
npm run test:matrix        # execution-surface matrix (which code paths reach a hook at all)
npm run test:coverage      # engine-core coverage gate (95%)
npm run test:live          # end-to-end: miner + base64→eval both blocked (Blocked: 2)
npm run redteam            # 151-payload red-team suite: logs caught vs. bypassed + gap report
bash scripts/audit-1-policy.sh && bash scripts/audit-2-interception.sh && bash scripts/audit-3-runtime.sh
```
