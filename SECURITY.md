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
