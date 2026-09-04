# Helios Runtime Firewall — Red-Team Attack Suite

A full adversarial attack suite that fires a corpus of malicious (and benign)
JavaScript module payloads at the firewall's detector and **logs what gets
through and what gets blocked**, with per-category gap analysis and a
false-positive check.

Methodology is borrowed from the
[`aletheia-redteam-kit`](https://github.com/holeyfield33-art/aletheia-redteam-kit)
command-center flow (corpus → run → decision logging → gap report →
`summary.json`), but adapted to this firewall's real input surface. The kit
red-teams an **LLM audit API** with prompt payloads; this firewall is a
**code scanner** that takes JavaScript/npm module *source* and returns
`QUARANTINE` (block) or `OBSERVE` (pass). So the corpus here is module source,
not prompts, and "what got through" means a malicious module the detector let
compile.

## What it measures

Each payload is fed through `Detector.scanModuleSync` and classified using the
**exact** block rule `index.js` applies on every `require()`:

> a module is **BLOCKED** iff the detector produces at least one non-`warnOnly`
> detection (`scanResult.detections.filter(d => !d.warnOnly)`), otherwise it is
> **PASSED**.

| Verdict          | Meaning                                                             |
|------------------|--------------------------------------------------------------------|
| `caught`         | malicious payload → BLOCKED (firewall did its job)                  |
| `known-bypass`   | malicious payload → PASSED, but a **documented** static-analysis gap|
| `REGRESSION`     | malicious payload → PASSED that we did **not** expect — a real hole |
| `clean`          | benign control → PASSED (no false positive)                        |
| `FALSE-POSITIVE` | benign control → BLOCKED (over-blocking)                            |

The suite **fails (exit 1)** only on `REGRESSION`s or `FALSE-POSITIVE`s. Known
bypasses are logged as accepted gaps and never fail the build — so this doubles
as a CI guardrail: if someone weakens a detector rule, a `caught` flips to
`REGRESSION` and CI goes red.

## Running it

```bash
npm run redteam                       # full suite, human-readable report + JSON
npm run redteam:bypass                # only show what got through
node red-team/run.js --category credential-exfil
node red-team/run.js --quiet          # summary block only
node red-team/run.js -o runs/x.json   # choose the JSON output path
```

A machine-readable `results/redteam-summary.json` is written on every run
(`results/` is git-ignored — it's a generated artifact). Its shape:

- `totals` — attacks, malicious/benign split, blocked/passed, caught,
  bypasses, knownBypasses, regressions, falsePositives, detectionRatePct
- `categories` — per-category rollup
- `gap_report` — every malicious payload that got through (the "what gets
  through" log), each tagged `knownBypass: true|false`
- `false_positives` — benign controls that were over-blocked
- `results` — full per-attack rows (expected, outcome, verdict, rules fired)

## Corpus

**179 payloads** across 7 threat categories (143 malicious, 36 benign — 14 of
the extra 15 malicious entries and all 3 extra benign entries beyond the
original 128/33 come from `redteam-kit-adapter` (see
[Redteam-kit adapter](#redteam-kit-adapter) below); the 15th is
`krc-function-indirection-exfil` in `credential-exfil.js`, an unrelated
fixture for the F-1.1 function-indirection correlation gap — see
`docs/THREAT-COVERAGE.md`),
each of the original 6 categories split into a core catalog and an
`-extended` catalog under `corpus/`, all aggregated by `corpus/index.js`
(which validates every entry and rejects duplicate ids):

| Category            | Count | Covers                                                                             |
|---------------------|:-----:|------------------------------------------------------------------------------------|
| `crypto-miner`      |  26   | stratum pools, coinhive/xmr-stak/cryptonight/nicehash, uncovered brands, concat/hex/wasm evasions |
| `reverse-shell`     |  22   | `/dev/tcp` + curl\|bash (caught); nc/ncat/socat/php/ruby/powershell/lua, http-beacon, mkfifo (bypass) |
| `credential-exfil`  |  29   | `.env`/`.ssh`/`.aws`/`.npmrc`/shadow/passwd theft over http/ws/tls/udp; docker/kube/cookie stores + DNS/beacon/inline-require/function-indirection evasions |
| `dynamic-code-exec` |  33   | eval/Function/vm+exec, base64/hex/atob→exec; bracket/alias/unicode/fromCharCode/constructor/wasm evasions, AST span-exhaustion decoy-flood (front/middle/end) |
| `supply-chain`      |  21   | pastebin/paste.ee/postinstall (caught); raw-github/transfer.sh/ngrok/telegram/IP-literal/base64-domain beacons (bypass) |
| `benign-controls`   |  31   | axios/dotenv/JWT/npm-tooling/word-list, ws/udp/tls clients, git/ffprobe wrappers, template compilers, bundled npmrc/host/far-egress, Phase 3 AST false-positive guards (constructor typecheck, fromCharCode i18n, base64 data decode, array-join message, computed-property config, standalone indirect-eval) — must **not** block |
| `redteam-kit-adapter` | 17  | reconstructed `aletheia-redteam-kit` attack techniques (dataset/workflow-config RCE, credential/env/path-traversal exfil, supply-chain lateral movement, dependency confusion, multi-stage encoding, Unicode-confusable identifier evasion) — see below |

Files: `corpus/<category>.js` (core) and `corpus/<category>-extended.js` (the
100+ added variants).

### Redteam-kit adapter

[`aletheia-redteam-kit`](https://github.com/holeyfield33-art/aletheia-redteam-kit)'s
attack catalog (`attacks/`) targets LLM/agent chat endpoints — each entry is a
natural-language instruction scored by refusal-keyword matching over a chat
completion. That contract doesn't fit this firewall (a code scanner, not a
chat API), so `corpus/redteam-kit-adapter.js` does not feed the kit's payload
*text* through the detector. Instead, each entry **reconstructs the
underlying technique** a real malicious npm package implementing that kit
attack would contain as JS module source — the same "reconstruct, never copy"
principle the kit's own `adapters/aegis/shim.mjs` uses for its non-chat
targets. Each entry's `krcId` traces back to the source kit attack id
(e.g. `PSE_004` → `attacks/advanced/supply_chain_sandbox_egress.json`).

Running it (`node red-team/run.js --category redteam-kit-adapter`, with or
without `--enable-ast`) surfaced three gaps that were not new: `env-secret-exfiltration`,
`registry-mirror-substitution`, and `cross-sandbox-pivot` all reproduce
already-documented accepted gaps in `docs/THREAT-COVERAGE.md` (bare env-read
+ egress, non-literal `require()`, and a lone outbound socket call are each
statically indistinguishable from common legitimate patterns — see that doc
for why). One entry, `confusable-identifier-evasion` (a Unicode-homoglyph
alias for `eval`), is caught only under `FW_ENABLE_AST=1` — the same shape as
the existing `dce-alias-eval` gap, confirming the Phase 3 AST tier generalizes
to a genuinely new obfuscation variant this adapter introduced. All three
benign-control entries pass clean (no false positives).

### Adding an attack

Append an object to the relevant catalog:

```js
{
  id: 'exfil-new-trick',          // unique across the whole corpus
  category: 'credential-exfil',
  technique: 'short-slug',
  severity: 'CRITICAL',
  expected: 'BLOCK',              // 'BLOCK' (malicious) or 'PASS' (benign / by-design WARN)
  knownBypass: true,             // OPTIONAL: set only if you expect it to slip past today
  description: 'One line on what it does and why it (does not) get caught',
  code: `/* the module source to scan */`,
}
```

If you add a malicious payload without `knownBypass` and it slips through, the
suite reports a `REGRESSION` and fails — which is exactly the signal you want
when probing for a genuinely new hole. If you're demonstrating a *known* gap,
set `knownBypass: true` and it's logged under `gap_report` as `[known]`.

## Known gaps this suite documents

Two numbers matter here, depending on configuration — `npm run redteam` measures the
first, `npm run redteam:ast` the second:

- **Default** (signature + behavioral tiers, `FW_ENABLE_AST` unset): **105/143** malicious
  payloads caught (**73.4%**), **zero false positives** on the 36 benign controls, after two
  hardening rounds plus the `redteam-kit-adapter` addition (see `docs/THREAT-COVERAGE.md` →
  "Phased hardening roadmap"; baseline before round 1 was 69/125 ≈ 55% on the original corpus).
  **38** documented bypasses remain.
- **`FW_ENABLE_AST=1`** (opt-in, off by default pending soak): adds a narrow, hand-rolled
  AST pass (`packages/fw-agent/src/ast-scan.js`) that closes **22** of those 38 —
  **127/143** caught (**88.8%**), still **zero false positives**. **16** bypasses remain
  even with it enabled.

> "Zero false positives" is measured against the **36 curated benign controls only** — it is not
> evidence of a general 0% false-positive rate on arbitrary packages. A broader benign-package soak
> is a release gate before the AST tier could ship on by default.

The 16 that remain regardless of configuration are fundamental limits of static/AST
analysis and require runtime/dataflow (or, for the function-indirection case, bounded
interprocedural) instrumentation to close. They cluster into these classes:

- **Function-indirection (same-file)** — a credential-read signal and a network-egress
  signal, each individually plain and un-obfuscated, placed in separate ordinary named
  functions far enough apart in the same file that they fall outside the default
  proximity-based correlation window, even though a third function calls both in sequence
  (`krc-function-indirection-exfil`). Not an obfuscation gap — the AST tier's fold-and-
  re-match model doesn't apply. See `docs/THREAT-COVERAGE.md` § "F-1.1" for the full
  writeup and the tracked (non-blocking) future P2 item.
- **WASM / GeneratorFunction cores** — GeneratorFunction/`constructor.constructor` shapes
  are now closed by the AST tier; WASM (`WebAssembly.instantiate`) is not and architecturally
  cannot be — there is no JS source text to parse inside a wasm binary.
- **`decodeURIComponent` → eval** — now closed by the AST tier (`decodeURIComponent` is
  recognized structurally as a decode-class primitive, correlating with an existing `eval(`
  match) when literal; still open when the payload is entirely env/runtime-sourced.
- **Network + process-exec chains** — pure-Node socket→`spawn('/bin/sh')` and an
  HTTP-polling C2 beacon; both primitives present but not linked by a blocking
  rule (a static "egress + child-process" rule would false-positive on legit CLIs).
  Not closeable by AST parsing — needs cross-statement taint tracking.
- **Shell-out / base64 command exec** — exfil by shelling out to `curl` with a
  runtime-built argument; a `/dev/tcp` command base64-encoded then `bash -c` (the latter
  IS now closed by the AST tier when the encoded form is a literal — see
  `revsh-base64-devtcp`).
- **Config obfuscation, env/runtime-sourced** — a miner pool URL read from
  `process.env`/config, decoded at runtime, never a literal anywhere in source — nothing
  for a static fold to resolve. (The literal-in-source case, e.g. a hex/base64 *literal*
  decoded at runtime, IS now closed by the AST tier — see `miner-hex-pool`.)
- **Low-and-slow / benign-looking C2** — ngrok/telegram/IP-literal beacons,
  dependency-confusion fetch, exit-time deferred beacon; a single outbound call
  to an attacker host is statically indistinguishable from legitimate telemetry
  (needs runtime egress allow/deny lists — a different problem from parsing).

**String-level evasion of literals** — `eval` via bracket/alias/unicode
escape/`fromCharCode`/reverse/`constructor.constructor`; module names or pool
URLs reassembled by concatenation/`join`; sensitive paths reassembled by
concatenation/`join` — **all now closed by the AST tier** (`FW_ENABLE_AST=1`). This
was the single largest bypass class and the AST pass's primary target; see
`packages/fw-agent/src/ast-scan.js` and `docs/THREAT-COVERAGE.md` §4 for exactly how.

Closed unconditionally since the 55% baseline (now caught regardless of `FW_ENABLE_AST`,
kept as `knownBypass: false` regression guards): inline-require `net`/`tls`/`dgram`/`vm`;
miner brands coinimp/jsecoin/webminepool/deepminer; `.docker`/`.kube`/browser `Login Data`
stores; `| sh`/`| dash`/`| zsh` stagers; fetch→eval (`REMOTE_FETCH_EXEC`);
`nc -e`/`ncat`/`socat`/`mkfifo`/`fsockopen`/PowerShell/`ruby`/`lua` reverse shells;
`dns.resolve` & `navigator.sendBeacon` channels; `process.binding` exec.

Closed under `FW_ENABLE_AST=1` specifically (kept as `knownBypass: true` under default
settings, since that reflects true out-of-the-box behavior — see each entry's
`description` for the closure note, and `docs/THREAT-COVERAGE.md` §4 for the full list):
`dce-bracket-eval`, `dce-alias-eval`, `dce-join-require`, `dce-unicode-escape-eval`,
`dce-eval-decodeuri`, `dce-fromcharcode-eval`, `dce-reverse-eval`,
`dce-constructor-constructor`, `dce-generatorfunction`, `dce-indirect-eval-decodeuri`,
`miner-concat-stratum`, `miner-base64-pool`, `miner-charcode-coinhive`,
`miner-concat-cryptonight`, `miner-hex-pool`, `revsh-base64-devtcp`, `exfil-concat-path`,
`exfil-concat-etc-shadow`.

These remaining gaps are intentional trade-offs the detector makes to keep false
positives at zero on the benign corpus. The value of logging them is a live,
regression-guarded inventory of the firewall's real blind spots — the full
machine-readable list is the `gap_report` array in `results/redteam-summary.json`
(regenerate with `npm run redteam` for default, `npm run redteam:ast` for the AST tier).
