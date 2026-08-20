# AUDIT-VERIFICATION-v0.5.2.md

**Subject:** Independent verification of PR #68 ("P0 hardening: proximity-based correlation,
cache-substitution detection, key rotation") — `holeyfield33-art/runtime-firewall-mvp`,
branch `claude/aletheia-firewall-p0-hardening-s9t06q`, base `main` @ `85f3b4b`, PR head
`e357586` at audit time.

**Issued:** 2026-08-20

**Method:** Four independent teams, each in its own isolated git worktree, auditing the SAME
PR from a different lens, with no visibility into each other's findings during their run
(cross-contamination would produce false consensus). Read-only: no team modified source files
or proposed fixes. Every finding below carries the command that reproduces it and real,
observed output — nothing here is asserted without a command backing it.

**Scope note:** this audit verifies PR #68's *own changes*, not the pre-PR state. PR #68 itself
was written in response to an earlier, separate audit (`AUDIT-VERIFICATION-v0.5.1.md`, unmerged
on `audit/v0.5.1-post-blockers`) that had already found the same base state's issues (including
the vite@8.2.1 false positive that became F-43/F-68 here). This document does not re-derive
that earlier audit — it checks whether PR #68's fixes actually hold up.

---

## Headline result

PR #68 makes real, verified progress on all six items it claims to fix — the vite/astro false
positive, the dev-key rotation, and the state-encapsulation cleanup are all genuine and
independently reproduced by at least one team using live, non-mocked evidence (real npm
packages, real signature forgery attempts, real process spawns). **But four of the fix
mechanisms have a reproducible CRITICAL gap each**, found independently by three different
teams working from different angles. None of these are the already-disclosed "same-process
ceiling" caveat restated — each is a specific, previously-unlisted way to defeat a specific
mechanism this PR just added, with a working reproduction.

## Consolidated findings

| ID | Severity | Team | Finding | Evidence |
|----|----------|------|---------|----------|
| **F-69** | **CRITICAL** | T1 | The 200-char proximity window (F-43/F-68's fix) is trivially defeated by ~100–150 characters of ordinary comment/whitespace padding between a credential-theft or code-exec payload's two halves — a **true-positive regression**: payloads the pre-PR engine blocked now load unimpeded. | `Detector.scanModuleSync` on an `.npmrc`/`_authToken`/`fetch()` theft payload: 0 padding → CRITICAL/QUARANTINE; 100 chars of `// comment` padding → span 211 chars → verdict flips to `NPMRC_NETWORK_EGRESS` WARN-only, action=OBSERVE (loads). A `new Function(...)` → `execSync()` chain flips from QUARANTINE to OBSERVE at exactly 150 chars of padding (span 225). Confirmed the pre-PR `BehaviorTracker` blocked the identical source at every padding level tested. |
| **F-70** | **CRITICAL** | T2 | `Module._load` (F-58's own enforcement point) is a plain, writable, configurable property — any in-process code can capture the firewall's wrapped version and install a replacement that skips the check for a chosen path, silently. **PR6's opt-in freeze does not cover this** (it only freezes `Module.prototype._compile`), so even the strictest configuration (`FW_MODE=enforce FW_CACHE_POLICY=block FW_HARDEN_MODULE_PRIMITIVES=1`) is defeated. | Real spawned child, `FW_CACHE_POLICY=block`: attacker script re-wraps `Module._load` post-patch, forges a `require.cache` entry, delegates everything else to the captured wrapped function. Result: `RESULT:{"result":{"stolen":true},"threw":null,"compilationsDelta":0}`, exit 0. **No `CACHE_SUBSTITUTION_*` audit-log event at all** — unlike every attack path in the committed test suite, which always logs even under `allow`. Re-confirmed with PR6 fully enabled: `compileFrozenWritableFalse: true, loadStillReassignable: true`, forged export still returned. |
| **F-71** | **CRITICAL** | T3 | `policy-watcher.js`'s `canonicalPayload()` — the function that builds the exact bytes `pristineVerify` checks the signature against — calls global `JSON.stringify` directly, **not pristine-captured** like `crypto.verify`/`crypto.createHash` were (F-62). Monkeypatching `JSON.stringify` post-load reproduces an old validly-signed payload's bytes regardless of the actual `rules` object, planting a malicious `rules` object under a stale valid signature — a full policy-signature bypass. | Two-phase PoC: baseline (no monkeypatch) `verify()` → `false` (correctly rejected); with `JSON.stringify` monkeypatched after `require()`, `_loadAndVerify()` returns `{ rules: { 'evil.js': 'ALLOW', ... } }` — bypass confirmed. F-62's own regression test (`policy-watcher-unit-test.js` Test 8) monkeypatches only `crypto.verify`/`crypto.createHash`, never `JSON.stringify` — this gap is real, not vacuously covered by the existing test. |
| **F-72** | **CRITICAL** | T3 | F-63's `defineProperty` trap fix is incomplete: if the quarantine proxy's target is made genuinely non-extensible first (`Object.preventExtensions(proxy)` or `Object.freeze(proxy)` — both forward to the real target by design, per F-63's own deliberate choice not to trap them), a **subsequent `defineProperty` call throws the exact class of raw, firewall-uncontrolled `TypeError` F-63 was written to eliminate** — including the identical `{value:1, configurable:true}` shape F-63's own test asserts `doesNotThrow` for. `Object.freeze(moduleExports)` is a realistic real-world pattern (ESM-interop shims, defensive-immutability wrappers), not a contrived trigger. | `Object.preventExtensions(p); Object.defineProperty(p,'x',{value:1,configurable:true})` → `TypeError: 'defineProperty' on proxy: trap returned truish for adding property 'x' to the non-extensible proxy target`. Same with `Object.freeze(p)` first. The committed tests (3d, 3e) test `defineProperty` alone and `preventExtensions`/`isExtensible` alone — never combined — so this is a real, uncovered gap. |
| F-73 | HIGH | T1 | Six signals gate their boolean flag on `scanSrc` (comments/URLs stripped, specifically to prevent comment-only mentions from counting — F-27b/F-28) but their **proximity positions are computed against raw `content`** instead, reopening the exact comment-based false-positive class `scanSrc` exists to prevent, for the proximity check specifically. | A genuine `.aws/credentials` read 534 chars from a real `fetch()`, plus a comment mentioning `.aws/credentials` only 52 chars before the same `fetch()`, fires `CREDENTIAL_EXFILTRATION` CRITICAL. Same pattern reproduced for `CODE_DECODE`/`OBFUSCATED_CODE_EXECUTION` via a comment mentioning `atob`. |
| F-74 | MEDIUM | T3 | `compileMetrics` is still exported as the live, mutable object — the identical vulnerability shape F-57 fixed for `policyMap`/`quarantinedModules`, left unaddressed in the same PR. Telemetry only (no enforcement branches on its values), so it doesn't reopen a bypass, but allowed code can corrupt the shutdown/monitoring summary. | `fw.compileMetrics.filesCompiled = 999999; fw.compileMetrics.quarantined = -1` → succeeds, `Object.isFrozen(fw.compileMetrics)` is `false`. |
| F-75 | MEDIUM | T4 | No `CHANGELOG.md` entry for this PR at all, despite a strong, established one-entry-per-fix convention (35 existing `F-` references across dozens of dated entries) and this PR touching four core engine files plus adding a whole new SECURITY.md section. Reads as an oversight, not a deliberate omission — nothing in the PR's commits addresses skipping it. | `git diff origin/main...HEAD -- CHANGELOG.md` → empty. |
| F-76 | MEDIUM | T4 | `AUDIT.md`'s "Note on `scripts/dev-private-key.pem`" section is now factually stale (asserts, present-tense, "This IS a private key committed to the repo") and its cited line numbers (`policy-watcher.js:177`, `index.js:145`) no longer resolve to the same content after this PR's edits (policy-watcher.js +49 lines, index.js +198 lines). The PR was otherwise in "sweep every doc mentioning this key" mode (README/SECURITY/THREAT-COVERAGE all updated) but skipped this one. Not clearly deliberate — the section reads as an evergreen security claim, not an inline-dated historical note. | `git diff origin/main...HEAD -- AUDIT.md` → empty (untouched). `grep -rn "dev-private-key" --include="*.md" .` shows AUDIT.md:106,118 still asserting present-tense. |
| F-77 | LOW | T3 | `src/policy.js`'s `hashMemoryObject()` uses uncaptured `crypto.createHash` — the one crypto-relevant helper in fw-agent's `src/` F-62 didn't touch. Forgeable, but impact is limited: its live caller (`quarantine.js`'s forensic-event hashing) only weakens downstream audit-log tamper-evidence: the function that would actually gate trust on the hash, `verifyPolicyIntegrity()`, is dead code (only called from its own unit test). | Monkeypatch `crypto.createHash` post-load → `hashMemoryObject()` returns an attacker-chosen hash instead of the real one. `grep -rn "verifyPolicyIntegrity("` confirms no production call site. |
| F-78 | LOW | T1 | `red-team/README.md` was not updated by this PR and now understates the corpus: still states "151 payloads... (125 malicious, 26 benign)" / lists `benign-controls` as 24; actual current run is 152 total / 27 benign (this PR's new `benign-controls-extended.js` fixture). Documentation drift only. | `git diff 85f3b4b...HEAD -- red-team/README.md` → empty. Live run: `Attacks run: 152 (125 malicious, 27 benign)`. |

## Confirmed clean (no finding, verified with real evidence, listed for completeness)

- **vite@8.2.1 / astro false positive is genuinely fixed** (T1-5, T1-6): live-installed real packages, `import('vite')` and `import('astro')` both clean post-fix; base-vs-PR diff on the *same real file content* confirms 5 blocking violations → 0. All three numeric claims in the fix's commit message (312-char, 68,519-char, 337-char distances) independently recomputed and matched exactly.
- **`withinProximity()` is algorithmically correct** (T1-7): 20,000-trial fuzz test against an O(n) brute-force reference, 0 mismatches; boundary is correctly inclusive at exactly 200.
- **Extension gating (`.js`/`.cjs` only) matches real `_compile` invocation behavior** (T2-2), empirically confirmed on live Node.
- **Retroactive `verifiedModulePaths` seeding correctly covers the agent's own bootstrap chain** (T2-3), and the trusted set is not reachable from the exported surface (T2-4) — moot in light of F-70, but correct as designed.
- **Three additional cache-substitution variants** (wholesale `Module._cache` replacement, relative-path requests, race-on-same-path) **are all correctly blocked** (T2-6) — F-70's bypass is specific to reassigning `Module._load` itself, not a general weakness in the check.
- **`Module._load` wrap overhead is small in absolute terms** (T2-7): ≈+10µs/call.
- **F-57's export-surface cleanup breaks no other consumer in the repo** (T3-5); **dev-key rotation is complete and consistent** (T3-6, including live `PolicyWatcher.verify()` checks against both committed `policy.signed.json` files); **F-62's committed regression test is non-vacuous**, confirmed by live revert-and-rerun (T3-7).
- **Adversarial suite (53/53) and red-team suite (152 attacks, 95/125 malicious caught, 0 false positives, 0 regressions) reproduce exactly as the PR claims** (T1-3, T1-4).
- **Baseline mechanism, doc-to-code consistency for `FW_CACHE_POLICY`/F-58's disclosure, packaging scope (fw-agent tarball unaffected by the new `proxyquire` devDependency, zero new fw-agent dependencies), and all 4 new test files correctly wired into `test:unit`** (T4-1, T4-3, T4-5, T4-6).

## What this means for items PR #68 marked "done"

Every one of F-58, F-62, and F-63 — all listed as "✅ Fixed" in PR #68's own SECURITY.md
table — has a live, reproduced bypass of the *specific* mechanism that PR added (F-70, F-71,
F-72 respectively), not just exposure to the already-disclosed general same-process ceiling.
F-43/F-68 (the proximity fix) is real for the exact case it names (vite/astro) but introduces
its own new true-positive regression (F-69) and a narrower false-positive reopening (F-73). Of
the six items in this PR, only F-57 (state encapsulation) and the dev-key rotation come out of
this audit with no CRITICAL/HIGH finding against them — though F-57 has a same-class MEDIUM
sibling (F-74, `compileMetrics`) the PR didn't also catch.

## Contradictions between teams

None found. No team's "clean" result was contradicted by another team's finding — e.g., Team 1
confirming the vite/astro fix is real is not in tension with Team 1's own F-69 (the general
mechanism has a padding-based regression); Team 3 confirming F-62's `crypto.verify` capture
works is not in tension with Team 3's own F-71 (a *different*, uncaptured function in the same
trust chain). Findings compound rather than conflict.

## Net-new vs. the original P-A/B/C/D-era audit list

All ten numbered findings here (F-69–F-78) are new — none correspond to an item in the earlier
`AUDIT-VERIFICATION-v0.5.1.md` (which predates PR #68 and audited the pre-fix state). They are
specifically about defects in PR #68's fix mechanisms, not restatements of what PR #68 was
written to address.

---

*No fixes proposed in this document, per the audit's own ground rules. Phase directives for
F-69 through F-78 should be written one at a time, after independent re-verification of this
document itself, matching this project's established process.*
