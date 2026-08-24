# Security Policy

## Supported Versions

| Version | Supported           |
|---------|---------------------|
| 0.2.x   | Yes                 |
| 0.1.x   | Security fixes only |
| < 0.1   | No                  |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security bugs.**

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to the repository page on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability**.
4. Fill in the form with a description, reproduction steps, and impact assessment.

We will acknowledge your report within 5 business days and aim to resolve and publish a fix within 90 days of confirmation. We will credit reporters who wish to be named in the advisory.

## Scope

### In scope

- **Detection bypass**: a technique that causes the firewall to allow a module it should block or quarantine, without requiring AST-level or full dynamic analysis (which are already documented as out-of-scope at the architectural level).
- **Firewall integrity**: an attack that defeats or silently disables the self-integrity check, the policy watcher's tamper detection, or the audit log without triggering a lockdown.

### Out of scope

- **Telemetry fail-open under `FW_TELEMETRY=1` with no control plane**: when `FW_TELEMETRY=1` is set and no control plane is running, the telemetry worker swallows connection errors and delivers nothing. This is intentional and documented behavior -- do not file a security report for it.
- **Known bypass techniques documented in README**: bracket-notation eval (`this["ev"+"al"]`), string concatenation (`global["ev"+"al"]`), array-join reassembly, and prototype-chain access all require AST-level or dynamic analysis. These are architectural limitations, not implementation bugs.
- **Issues in packages outside `aletheia-firewall`**: `fw-control` (the control plane server) is out of scope for this policy; its security posture is separate.
- **Performance or denial-of-service against the scanner itself**: the firewall is a synchronous in-process hook; its availability is tied to the host process.
- **False positives**: incorrect blocking of benign modules is a usability issue, not a security vulnerability.

## July 2026 Audit — Resolution Status

The following findings from the July 2026 internal audit have been addressed as of v0.2.0:

| Finding | Severity | Status | Fix version |
| ------- | -------- | ------ | ----------- |
| F-01: CI pipeline broken (wrong working-directory) | CRITICAL | ✅ Fixed | 0.1.1 |
| F-02: TOFU policy baseline attackable | HIGH | ✅ Fixed | 0.2.0 — Ed25519 signing |
| F-03: 2 KB truncation bypass | HIGH | ✅ Fixed | 0.2.0 — full-content scan |
| F-04: False positives on common patterns | HIGH | ✅ Fixed | 0.1.1 — WARN tier |
| F-05: `process.exit(9)` in quarantine | MEDIUM | ✅ Fixed | 0.1.1 — rate-limited return |
| F-06: No policy hot-reload | MEDIUM | ✅ Fixed | 0.2.0 — `onValidChange` callback |
| F-07: <100-byte skip in behavioral analyzer | MEDIUM | ✅ Fixed | 0.2.0 |
| F-08: Inline require("https").get missed | MEDIUM | ✅ Fixed | 0.2.0 |
| F-09: Control plane binds 0.0.0.0 | MEDIUM | ✅ Fixed | 0.2.0 — 127.0.0.1 default |
| F-13: No warning for unauthenticated dashboard | LOW | ✅ Fixed | 0.2.0 |
| F-14: No tests for watcher/quarantine/auditlog | INFO | ✅ Fixed | 0.1.1 — new test suite |

Deferred to Phase 3+ (out of scope for 0.2.0):

| Finding | Severity | Notes |
| ------- | -------- | ----- |
| F-10: AST-level obfuscation detection | MEDIUM | Requires V8 Inspector / AST pre-processing |
| F-11: Postinstall shim for pre-firewall hooks | MEDIUM | Architectural; hooks run before the firewall loads |
| F-12: Runtime taint tracking | LOW | Requires dynamic analysis infrastructure |

## August 2026 P0 Hardening Pass — Resolution Status

The following findings, from a two-session TMRP deliberation (strategic decision + technical
review) with orchestrator-verified evidence at every disputed point, have been addressed:

| Finding | Severity | Status | Notes |
| ------- | -------- | ------ | ----- |
| F-57: `policyMap`/`quarantinedModules` exported as live, mutable state | HIGH | ✅ Fixed | The live `Map`/`Set` are no longer exported at all; replaced with read-only query functions (`hasPolicy`, `getPolicyDecision`, `isQuarantined`). Any allowed code could previously call `.set()`/`.delete()`/`.clear()` on the real object and mutate enforcement state directly. |
| F-62: `crypto.verify`/`crypto.createHash` called fresh each time (monkeypatchable) | HIGH | ✅ Fixed | Pristine references captured at each file's own module top level, before any later-loaded code can run; used exclusively from then on. Verified with a regression test that monkeypatches `crypto.verify`/`crypto.createHash` *after* the module has loaded and confirms tamper detection, valid-signature acceptance, and hot-reload change-detection are all unaffected. |
| Dev key: `scripts/dev-private-key.pem` committed to the public repo | HIGH | ✅ Fixed | Deleted from `HEAD`; `DEV_PUBLIC_KEY_PEM` rotated to a freshly generated public key whose private half has never been committed anywhere. History was **not** rewritten (separate, explicit decision) — see "Policy signing key management" below for the full revocation record. |
| F-63: Quarantine Proxy's untrapped `defineProperty` throws on subsequent enumeration | MEDIUM | ✅ Fixed | Added a `defineProperty` trap matching the pretend-success pattern already used by every other trap in `quarantine.js`; never forwards to the real target, so `ownKeys`'s "no keys" invariant stays satisfied. `preventExtensions`/`isExtensible` deliberately left untrapped — confirmed by direct testing that the same pretend pattern breaks the Proxy invariant for those two specifically. |
| F-43/F-68: `CREDENTIAL_EXFILTRATION` and related behavioral rules false-positive on large bundled files | HIGH | ✅ Fixed | `behavior-tracker.js`'s multi-signal correlation rules (`CREDENTIAL_EXFILTRATION` — both the sensitive-path and `.npmrc` variants —, `DYNAMIC_CODE_EXEC_CHAIN`, `OBFUSCATED_CODE_EXECUTION`, `REMOTE_FETCH_EXEC`) now require their constituent signals to co-occur within a 200-character window, not just appear anywhere in the same file. Confirmed on the real `vite@8.2.1`/`astro` false positive and validated against a 15,728-file real-world corpus (0 false positives) with 100% true-positive retention. See `docs/THREAT-COVERAGE.md` §2 for details. |
| F-58: `require.cache` pre-seeding bypasses `Module.prototype._compile` scanning | HIGH | ✅ Fixed (specific mechanism only — see scope note) | `Module._load` is now wrapped with a three-state verified/unknown/blocked model; policy-controlled via `FW_CACHE_POLICY=block\|audit\|allow` (default `block` under `FW_MODE=enforce`, `audit` otherwise). **Scope:** cache enforcement closes `require.cache` **pre-seeding** that bypasses the scan path — a forged or bare-object `require.cache` entry inserted to make `require()` return unscanned exports — confirmed with a live repro before the fix and a full test matrix after. It does **not** close **reassignment of the loader functions themselves** (`Module._load`, `Module.prototype._compile`, `module.registerHooks()`), nor the broader same-process ceiling: code already running inside a protected process that finds some other way to install or return forged state, not via `require.cache`, is a different, broader problem this change does not address. See the F-70 disclosure below. |
| PR6: opt-in `Module.prototype._compile` freeze | — | Shipped (opt-in) | `FW_HARDEN_MODULE_PRIMITIVES=1`, default-off — complementary hardening against the classic `_compile` monkeypatch specifically; does nothing against `require.cache` poisoning (F-58's target). Not default-on for the same compatibility reasons `FW_FREEZE_PROTOTYPES` already isn't. |
| F-79: ESM `import` of a CommonJS package (CJS-through-ESM interop) skipped scanning | CRITICAL | ✅ Fixed | The ESM `load` hook early-returned for `result.format === 'commonjs'`, so a CJS module loaded via `import` was never scanned — it populated `Module._cache` without calling `_compile`. This was **both** a detection gap (a malicious CJS module imported via ESM ran unscanned — blocked via `require()`, free via `import`) **and** a false positive (the later `require()` of the same package, e.g. `vite`/`astro` referencing `picomatch` as both `import` and `__require`, hit F-58's cache gate as an "unverified" entry and was refused under `FW_CACHE_POLICY=block`). Fixed by running the interop-CJS source through the **same** scan-and-policy path as `_compile` (shared implementation, no drift) and only then marking it verified — closing both. Verified with a true-positive test (malicious CJS via `import` now BLOCKED; ran free before the fix), a false-positive test (benign CJS imported-then-required loads clean under `block`), the unchanged 10-test cache-poisoning matrix, a full red-team run (0 regressions / 0 false positives), and a live `import('vite')`/`import('astro')` load under `FW_CACHE_POLICY=block`. |
| F-70: `Module._load` (and the other loader functions) are reassignable by same-process code | CRITICAL | ⚠️ Disclosed, not fixed (same-process ceiling) | `Module._load` — F-58's own enforcement point — is a plain writable property; allowed code can capture the firewall's wrapped version and install a replacement that skips the check. Freezing it is neither cheap nor low-risk (it recreates the `_compile` compatibility problem PR6 keeps opt-in) and does not escape the same-privilege domain: an attacker who reassigns before the freeze, or keeps a reference to the original, still wins. This is the same-process ceiling, not a closable gap. See the detailed disclosure below. |

## September 2026 Independent Pentest — Resolution Status

The four commits above (F-69/F-71/F-73/F-74/F-79/F-70) were subjected to an independent pentest
(PENTEST-003) by a reviewer with no memory of the implementation work, in an isolated worktree,
before merge. It found three real gaps the implementation work missed, all live-reproduced with
evidence before being reported. All three were independently re-verified by the orchestrator
(not just trusted from the reviewer's self-report) before being fixed.

| Finding | Severity | Status | Notes |
| ------- | -------- | ------ | ----- |
| F-80: `canonicalPayload()`'s key-sort copy loop is prototype-pollution-interceptable | CRITICAL | ✅ Fixed | The F-71 fix captured byte-building *primitives* pristine, but `canonicalPayload()`'s own copy loop (`sorted[k] = rules[k]` onto a fresh `{}`) still used bracket assignment — a `[[Set]]` operation, not a primitive call, so it was interceptable independent of every F-71 capture. Two reproducible vectors: (a) the literal key `'__proto__'` is silently swallowed by Object.prototype's own built-in accessor for non-object values — no monkeypatch needed, stock JS semantics; (b) allowed code with earlier execution can pollute `Object.prototype` for *any* ordinary key name, generalizing the bug past `'__proto__'`. Either way, a policy signed *without* the target key, tampered post-signing (raw JSON-text edit, no private key) to add it, still verified as valid, and the forged rule was present in the applied rules. Fixed by building the copy target with `Object.create(null)` instead of `{}` — no inherited accessor anywhere in the chain to intercept the assignment. `scripts/sign-policy.js`'s separate copy of the same bug was fixed identically, required for the two to stay byte-compatible. |
| F-81: `buildSeparatorPrefix()` missed Automatic-Semicolon-Insertion statement boundaries | CRITICAL | ✅ Partially fixed; residual limit disclosed | Counting only literal `;`/`{`/`}` meant arbitrarily many real statements written without semicolons or braces (relying on ASI) accumulated **zero** separators, so the "falls off at ≥5 real intervening statements" invariant did not actually hold for semicolon-free code — it held for no count at all. **Fixed**: a newline is now also counted as a separator when the line it terminates has real content that didn't already end in a literal separator (comment/whitespace-only lines, correctly, still count as nothing, at any size) — this closes the many-statements case, verified against the original threshold (falls off at 5, matching semicolon-terminated code) and against the full red-team/adversarial/4,532-file real-corpus FP sweep (0 regressions, 0 new false positives). **Not fixed, and disclosed as inherent**: a *single* arbitrarily long statement (e.g. one huge string-literal assignment, no internal newline, no `;{}` anywhere) is genuinely one statement with zero real separators no matter its length, so it is bounded only by `CORRELATION_MAX_CHARS` (8000) — an independent, hard ceiling that a first attempt at closing (crediting extra separators for long unbroken runs) was proven, by construction, unable to affect: `withinContext()`'s two caps both require *closeness* to correlate, so adding separators to a long run can only push it further from correlating, never closer, and for this exact shape the character cap already excludes the window before separator-count is relevant. Raising the character cap does not help either — it is the same "any fixed character distance is defeatable by adding that many characters" argument the original F-69 redesign already made about the 200-char window, recursed one level onto the backstop. Distinguishing a legitimately long single statement (a large embedded JSON/base64 blob, a big lookup table) from one constructed purely as inert evasion padding requires understanding what the statement *does*, which text-scanning alone cannot provide. Documented, tested (an explicit evasion-limit test asserts the exact falls-off-at-8000 boundary), not silently missed. |
| F-82: `getCompileMetrics()`'s `Object.freeze()` call was not pristine-captured | LOW | ✅ Fixed | Unlike `crypto.createHash`/`crypto.verify`/the F-71 byte-building primitives, `getCompileMetrics()` called the ambient global `Object.freeze()` directly, so a monkeypatch installed by allowed code *after* the agent loads defeated the snapshot's immutability guarantee (`Object.isFrozen()` on the return value reported `false`, and it was fully mutable). Fixed with the same pristine-capture pattern used everywhere else in this codebase (`pristineFreeze`, captured at module top level). Low impact: `compileMetrics` is telemetry-only — no enforcement decision reads `getCompileMetrics()`'s return value; `shutdown()`/the exit handler read the private, non-exported `compileMetrics` object directly. |

**Correction to the August 2026 P0 pass's F-69 claim**: that entry's original wording described
correlation as "invariant to arbitrarily large comment/whitespace padding." That was an overclaim
— `withinContext()`'s character cap is ANDed with the separator cap and excludes a window
regardless of padding composition, so separator-immunity was never literally unbounded. The
accurate claim (now reflected in code comments and tests): separator-count is unconditionally
immune to comment/whitespace padding at any size; the *overall* correlation is additionally
bounded by `CORRELATION_MAX_CHARS` (8000) regardless of what's between the signals. In practice
this rarely matters for real attacks — genuine intervening code exhausts the separator budget at
~5 statements, almost always far short of 8000 characters — but it is the honest boundary, not an
unlimited one, and the padding-adversary tests now assert it explicitly rather than only
testing sizes safely below it.

## Second Independent Pentest (PENTEST-004) — F-83

A follow-up independent pentest (PENTEST-004) re-checked the F-80/F-81/F-82 fixes above once they
landed on `main`. The background reviewer hit a rate limit mid-run, but its partial output left a
lead — a suspected gap near `Array.prototype.sort` in the F-71 pristine-capture logic — that was
independently investigated and confirmed by the orchestrator with a live reproduction before being
fixed, the same independent-reproduction discipline applied to every finding above.

| Finding | Severity | Status | Notes |
| ------- | -------- | ------ | ----- |
| F-83: `canonicalPayload()`'s key-sort copy loop reads its key array with `for...of`, which is `Symbol.iterator`-interceptable | CRITICAL | ✅ Fixed | F-71 pristine-captured `Object.keys` and `Array.prototype.sort` themselves; F-80 hardened the copy loop's *target* (`Object.create(null)`). Neither touches `Array.prototype[Symbol.iterator]` — a distinct, uncaptured property that `for (const k of keysArray)` dispatches through. Allowed code with earlier execution in the process can replace it with a generator that yields every legitimate key while silently skipping one forged key of its choice; `Object.keys`/`sort` still return the real, complete list, so F-71's captures see nothing wrong — only the loop *consuming* that list is redirected. Live-reproduced: a policy signed without a target key, tampered post-signing (raw JSON-text edit, same technique as F-80) to add it, with a **targeted** `Symbol.iterator` installed that filters out exactly that key — `verify()` returned `true` and the forged rule was present in the applied `rules`, with F-80's fix still in place (the bypass is in the iteration source, not the assignment target, so F-80 does not gate it). Fixed by reading the sorted key array by index (`.length` + indexed access) instead of `for...of` — indexed access and `.length` are direct property reads, not `Symbol.iterator` dispatch, so no new pristine capture is needed. |

**Correction — F-83's first fix pass only fixed one of `scripts/sign-policy.js`'s two copies of
this loop.** The row above originally claimed both copies were "fixed identically." That was
inaccurate: `canonicalPayload()` in that file was switched to index-based iteration, but
`signPolicy()`'s own, separate copy (which builds the `sorted` object that becomes *both*
`canonicalPayload`'s input and the output `rules` field written to `policy.signed.json`) was left
on `for...of`. Caught by **PENTEST-005**'s Threat Modeler — a formal, isolated-worktree,
schema-validated run, unlike the informal, rate-limited PENTEST-004 run below that originally
surfaced F-83 — during the pre-merge gate for PR #73, before the fix was merged. Now fixed
identically (index-based iteration). The practical exposure is narrower than the verify-side bug:
because `signPolicy()`'s `sorted` feeds both the signed bytes and the returned `rules` field, a
`Symbol.iterator` pollution there drops a key from both *consistently* — it cannot decouple
signed-bytes from applied-rules the way the verify-side bug could, so it was not by itself a
forgery vector. It was a correctness and supply-chain-on-the-signing-tool concern: an operator
signing a policy meant to include a `BLOCK` rule, in an already-compromised offline signing
environment, could have silently gotten back a validly-signed policy missing that exact rule, with
no error. A new regression test (`policy-watcher-unit-test.js` Test 12) proves `signPolicy()`
itself — not just `canonicalPayload()` — resists this pollution, and that the resulting policy
still round-trips through `verify()` with the complete rule set intact.

**Scope check on the rest of the codebase**: `index.js` has several other `for...of` loops
(`intrinsicPrototypes` in `primitiveLockdown()`, `selfFiles` in the self-integrity hash, and
`Object.entries(pkg.scripts)` in the npm-lifecycle scan) and one `Object.keys(Module._cache)`
loop seeding `verifiedModulePaths`. All four run once, synchronously, during the agent's own
top-level bootstrap — before any application or dependency code has had a chance to execute in the
process, since the firewall is designed to be `--require`-preloaded ahead of everything else. That
timing, not a missing capture, is what closes the same `Symbol.iterator` vector here: there is no
window in which allowed code could have polluted `Array.prototype` before these loops run. This is
architecturally different from `canonicalPayload()`, which `PolicyWatcher` invokes repeatedly over
the life of a long-running process (on every file-watch-triggered policy reload), long after
application dependencies have executed. The two remaining spread usages (`{...metadata}` in
`emitTelemetry()`, `{...compileMetrics}` in `getCompileMetrics()`) are *object* spread, which
copies own-enumerable properties directly and never dispatches through `Symbol.iterator` at all.
None of these needed the F-83 fix; noted here so this was a completed audit, not an assumption.

## Third Independent Pentest (PENTEST-005) — F-84, pre-merge gate for PR #73

Before merging PR #73 (the F-83 fix), the repo owner requested a formal pre-merge gate: a Threat
Modeler (A1b) and Pentester (A2p) pair, run in genuinely isolated git worktrees with no memory of
the implementation work, plus a Compatibility Reviewer (A2v) and Release Auditor (A2r) auditing
the package that would actually publish — the `.agent/` orchestration graph's Team Configuration 2
and 4 tracks, run together as directed. Unlike the informal, rate-limited PENTEST-004 run above,
this is PENTEST-005's first formal, schema-validated pass, and it returned a real `FAIL`.

| Finding | Severity | Status | Notes |
| ------- | -------- | ------ | ----- |
| F-84: `canonicalPayload()`'s `Object.create(null)` call is not pristine-captured | CRITICAL | ✅ Fixed | F-80's entire fix depends on `Object.create(null)` actually producing a null-prototype object — but `Object.create` itself was never added to F-71's pristine-capture list, so it was still called as the live ambient global. Allowed code that monkeypatches `Object.create` *after* this module loads (e.g. redirecting the `proto === null` case to return an ordinary, Object.prototype-inheriting object instead) makes `canonicalPayload`'s copy target inherit from `Object.prototype` again, reopening F-80's exact bracket-assignment bug through a new vector: attacking the *construction* of the copy target, not the loop that populates it (F-71) or the loop's iteration mechanism (F-83). Live-reproduced by PENTEST-005's Pentester, independently re-verified by the orchestrator: with `Object.create` monkeypatched post-load, a policy signed *without* a `'__proto__'` rule, tampered post-signing (raw text edit, no private key) to add one, verified `VALID` again — the identical bypass shape the F-80 fix was supposed to have closed permanently. F-80's own opt-in `FW_FREEZE_PROTOTYPES=1` hardening does not mitigate this either: `Object.create` is an own property of the `Object` constructor function, not a property on any frozen prototype. Fixed by capturing `pristineCreate = Object.create` at module top level (added to F-71's capture list) and calling `pristineCreate(null)` instead of the ambient global, in `canonicalPayload()`. `scripts/sign-policy.js`'s three matching `Object.create(null)` call sites (`canonicalPayload` once, `signPolicy` once) were fixed identically. |

The Pentester's other priority targets (the F-83 delta itself, F-81's disclosed boundary, F-70's
loader-reassignment ceiling, F-79's ESM interop path, F-74/F-82's `Object.freeze` capture) all held
under fresh, genuinely new payloads — no other bypass found. The Compatibility Reviewer and Release
Auditor both independently returned `PASS`; the Compatibility Reviewer additionally flagged the
F-83 follow-up gap (see the correction above) as an advisory finding on its own, before this
document was updated to record it, corroborating the Threat Modeler's independent discovery of the
same gap.

**Why this pattern of misses (F-80 → F-83 → F-84, all in the same `canonicalPayload` construction)
matters and what it means going forward**: three consecutive pentest passes each found one more
ambient global this function depended on without capturing. F-71 captured the byte-building
primitives; F-80 found the copy loop's *target* was still a live `{}`; F-83 found the loop reading
the sorted keys was still live `for...of`; F-84 found the very call that constructs the
null-prototype target was still live `Object.create`. Each fix was real and each was independently
verified — but each also left exactly one more adjacent ambient global unexamined, discovered only
by the next pentest pass rather than by a first-pass audit of every operation `canonicalPayload`
touches. `canonicalPayload` now pristine-captures every operation involved in building its output
(`JSON.stringify`, `Object.keys`, `Array.prototype.sort`, `Buffer.from`, `Object.create`) plus
`crypto.verify`/`crypto.createHash` (F-62) — a genuinely completed set as of this pass, verified by
a pentest specifically primed to look for exactly this class of gap and finding none. If a future
change adds a new ambient-global call to this function's byte-building path, it needs the same
scrutiny this one finally received in full.

### F-70: same-process loader-reassignment ceiling (disclosure, 2026-08-20)

Aletheia enforces at Node's module-loading layer by wrapping `Module.prototype._compile` and
`Module._load`, and by registering an ESM `load` hook via `module.registerHooks()`. All three run
**at the same privilege level as the code they inspect** — they are ordinary JavaScript in the same
process. That is an inherent ceiling, not a bug, and F-70 is the concrete demonstration of it:

- `Module._load` is a plain writable property on the `Module` object. Allowed code that runs after
  the firewall installs its wrapper can read the wrapped function, then assign a replacement
  (`Module._load = function (...) { /* skip the cache check */ return original(...); }`) that
  never consults `verifiedModulePaths`. The F-58 cache gate is then simply not on the path.
- The same is true of `Module.prototype._compile` (the CJS scan point) and of any hook installed
  through `module.registerHooks()`.

**Why this is not fixed by freezing.** Freezing `Module._load` was considered and rejected for this
release (a unanimous session-3 decision):

1. It recreates the exact compatibility problem that keeps the `_compile` freeze opt-in
   (`FW_HARDEN_MODULE_PRIMITIVES`, default-off): legitimate loaders, instrumentation agents, and
   transpilers reassign these functions, so freezing them by default breaks real toolchains.
2. It does not escape the same-privilege domain even when it "works". An attacker running before
   the freeze installs (the pre-preload window the `FW_MODE=dev` disclosure already covers), or one
   that simply keeps a reference to the original `require`/`Module._load` before reassigning, still
   wins. A same-privilege defense cannot durably protect a mechanism the attacker shares.

**Scope statement for cache enforcement (F-58).** The cache-enforcement work closes `require.cache`
**pre-seeding** that bypasses the scan path. It does **not** close **reassignment of the loader
functions themselves** — that is the F-70 ceiling above. Both statements are also recorded in the
`Module._load` wrap's own code comment in `packages/fw-agent/index.js`.

The practical mitigations remain the ones the threat model already documents: preload the agent as
early as possible (so less code runs before it attaches — the `FW_MODE`/preload guidance), run under
`FW_MODE=enforce`, and treat the process boundary — not in-process interception — as the trust
boundary for code you do not control. Meaningfully raising this ceiling requires an out-of-process
or platform-level mechanism (a separate supervisor, OS sandbox, or VM boundary), which is explicitly
out of scope for a same-process, zero-dependency library.

### Policy signing key management

There is **no shared dev private key committed to this repository.** `DEV_PUBLIC_KEY_PEM` in
`packages/fw-agent/src/policy-watcher.js` is a public key with no matching private key held by
anyone — it exists only so `policy.signed.json` fixtures the project ships (empty-rules demo
files) can carry a valid signature, and so `FW_ALLOW_DEV_POLICY_KEY=1` has something concrete to
gate. Before deploying to production:

1. Run `node scripts/generate-policy-key.js` and keep the private key on your own machine —
   never commit it, never share it, and never write it to a path inside this repository.
2. Either set `FW_POLICY_PUBKEY` to your new public key at runtime (recommended — no source
   change needed), or replace `DEV_PUBLIC_KEY_PEM` in `packages/fw-agent/src/policy-watcher.js`
   for your own fork.
3. If you edited `policy-watcher.js`, regenerate `.helios-baseline`: `npm run baseline` (from
   the repo root). Do not hand-roll the hashing snippet — `scripts/generate-baseline.js` is the
   single source of truth for the hashed file list and hashing method; see `CONTRIBUTING.md`.
4. Sign your policy rules: `node scripts/sign-policy.js your-private-key.pem rules.json`.

#### Key revocation record (F-62, 2026-08-20)

`scripts/dev-private-key.pem` — a shared development/CI private key — was committed to this
public repository from the project's early history through the v0.5.0 release. Its matching
public key was hardcoded as `DEV_PUBLIC_KEY_PEM`. Anyone with read access to the repository
(or its git history) could use it to forge a validly-signed `policy.signed.json`; the only
guard was the `FW_ALLOW_DEV_POLICY_KEY=1` opt-in (required by `PolicyWatcher.start()`) and the
`NODE_ENV=production` check in `assertProductionKeyConfig()`, both of which depend on correct
deployment configuration rather than on the key itself being untrusted.

As part of this hardening pass:

- `scripts/dev-private-key.pem` was **deleted from `HEAD`**. `DEV_PUBLIC_KEY_PEM` was rotated to
  a freshly generated public key whose private counterpart has never been committed anywhere,
  in this repository or elsewhere, and never will be.
- The old private key **remains recoverable from this repository's git history** — history was
  deliberately not rewritten in this change (a separate, explicit decision, not an oversight).
  Treat every signature produced by the old key as **permanently untrusted**: a
  freshly-rotated agent rejects it regardless of `FW_ALLOW_DEV_POLICY_KEY`, because it no longer
  matches the bundled `DEV_PUBLIC_KEY_PEM` or any key an operator would configure via
  `FW_POLICY_PUBKEY`.
- Production deployments were already required to set `FW_POLICY_PUBKEY` explicitly
  (`assertProductionKeyConfig()` refuses to start under `NODE_ENV=production` against the
  bundled dev key without it); this rotation does not change that contract, it only closes the
  exposure window for anyone who was relying on the bundled key outside of local dev/CI.
