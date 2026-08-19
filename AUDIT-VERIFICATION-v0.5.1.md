# AUDIT-VERIFICATION-v0.5.1.md

**Issued:** 2026-08-19
**Scope:** Fresh 4-team re-derivation of the findings list against current `main`, post P-A/B/C/D.
**Base commit audited:** `85f3b4b` (`origin/main` tip at issue time — PR #67, "opt-in fail-closed for
missing ESM coverage; state floor at Quick Start (N-03)").
**Status:** Audit findings only. No fixes proposed, no files other than this one touched. Not merged.
Hand this branch to an independent reviewer (fresh clone) for confirmation before any phase directive
is written against it — same pattern as P-A through P-D.

---

## 0. Precondition check (done by the orchestrating agent before spawning teams)

The directive required confirming `claude/p-d-esm-floor-visibility` is merged to `main` before running
anything, specifically to avoid re-flagging N-03 (ESM floor visibility) as open when it's already closed.

```
$ git merge-base --is-ancestor origin/claude/p-d-esm-floor-visibility origin/main && echo MERGED || echo "NOT MERGED"
NOT MERGED
```

A literal ancestor check fails because PR #67 landed as a **squash merge** (`a3a7f3e` on the feature
branch → `85f3b4b` on `main`, different hashes, same author/message/timestamp-adjacent content). Content
was verified directly instead of trusting the ancestor check:

```
$ git diff origin/main origin/claude/p-d-esm-floor-visibility -- index.js README.md packages/fw-agent/.helios-baseline
(empty — zero delta on every file the branch touched)

$ git show origin/main:packages/fw-agent/index.js | grep -n "FW_REQUIRE_ESM_COVERAGE"
755:  // FW_REQUIRE_ESM_COVERAGE=1 is a separate, more specific assertion than FW_MODE=enforce: "I
759:  if (process.env.FW_REQUIRE_ESM_COVERAGE === '1') {
762:    console.error(`[CRITICAL] [Helios] ${message} FW_REQUIRE_ESM_COVERAGE=1 is set. Refusing to start.`);
```

**Verdict: precondition satisfied.** P-D's content is on `main`. N-03 is closed and is correctly *not*
re-flagged below.

A second trap surfaced during setup, worth recording since it's the exact failure mode the directive
warned about ("shallow clones have produced false confidence in this repo before"): the orchestrating
agent's own primary working copy was itself a **shallow clone** (`git rev-parse --is-shallow-repository`
→ `true`, 154 commits visible). It was unshallowed (`git fetch --unshallow origin`, 154 → 184 commits)
before any team clone was cut. A second, subtler trap followed: cloning locally via `git clone
--no-local /home/user/runtime-firewall-mvp <dest>` silently picked up a **stale local branch named
`main`** in that working copy (pinned at old commit `6da81ac`, unrelated to `origin/main`) instead of
the real GitHub `main`. All four team clones were re-cut directly from
`https://github.com/holeyfield33-art/runtime-firewall-mvp` to guarantee they were both non-shallow and
pointed at the actual current `origin/main` (`85f3b4b`, 184 commits, verified per-clone with
`git rev-parse --is-shallow-repository` → `false`).

## 1. F-number baseline (collision avoidance)

```
$ git grep -oE "F-[0-9]+" | grep -oE "F-[0-9]+$" | sort -t- -k2 -n -u | tail -5
F-38
F-39
F-40
F-41
F-42
```

Highest existing F-number in the repo (all tracked files, not just `.md`) is **F-42**. Fresh findings
below are numbered **F-43 onward**. `AUDIT-VERIFICATION-v0.5.0.md` itself is **not present** in the
repo as a tracked file (confirmed: `git ls-files | grep -i AUDIT` → only `AUDIT.md`,
`.agent/agents/release-auditor.md`, `.agent/contracts/release-audit-receipt.schema.json`,
`.agent/directives/RELEASE-001-fw-agent-package-audit.json`), so direct line-by-line comparison against
its original text was not possible; comparisons below are against the figures/claims this directive's
own brief attributes to it, and against what the affected commit messages themselves claim.

## 2. Methodology

Four independent agents, each given a full non-shallow clone of `origin/main` at `85f3b4b`
(verified separately, see §0), a fixed scope, and the instruction that every claim needs a real
command + real output — no finding without a reproduction. None of the four could see another team's
output before submitting. This document is the first point at which their findings are combined.

## 3. Consolidated findings

| ID | Sev | Finding | Evidence (command) | Team |
|----|-----|---------|---------------------|------|
| F-43 | **HIGH** | `require('vite')` (vite@8.2.1, a real, current, top-tier npm package) is hard-blocked as `CREDENTIAL_EXFILTRATION` in `FW_MODE=enforce`, live/reproducible today. Root cause: `HOST_OPTION` regex (`behavior-tracker.js:75`, `/host\s*:\s*['"\`][^'"\`]+/`) matches anywhere in a file with no proximity requirement, and combines with an unrelated `.npmrc` string 18 lines later in a 37K-line bundled chunk to trip the `.npmrc`-exfiltration CRITICAL escalation (`behavior-tracker.js:341-361`). Not present in the curated 26-package soak corpus's historical runs (0 FP on 2026-07-15 ×3 and 2026-08-13); vite@8.2.1 was published 2026-08-06, i.e. corpus drift, not an engine regression. | `FW_ENABLE_DETECTION=1 FW_ALLOW_DEV_POLICY_KEY=1 node --require ./packages/fw-agent -e "require('vite')"` → `[COMPILATION LOCKDOWN] ... CREDENTIAL_EXFILTRATION, CREDENTIAL_EXFILTRATION, ...` (reproduced 3/3); `node aletheia-soak-test.js --agent ./packages/fw-agent` → `FALSE POSITIVES : 1/99 legit blocked (1%) -> vite:CREDENTIAL_EXFILTRATION` | 1 |
| F-44 | Low | `FINDINGS-INBOX.md`'s `data:`-module-identity design gap: the *symptom* (bypass) is documented in `THREAT-COVERAGE.md`/`fw-agent/README.md`, but the *architectural blocker* (no policy-key scheme for non-`file://` imports) exists only in `FINDINGS-INBOX.md`, referenced from nothing else — no roadmap-phase tag, unlike the adjacent AST-obfuscation row which is tagged "Roadmap Phase 5." | `grep -rn "data:" .agent/directives/` → no output; `grep -n -i "data:.*module\|dataurl" CHANGELOG.md` → no output | 1 |
| F-45 | Low | The `node -e` inline-eval bypass is asserted only in `THREAT-COVERAGE.md` prose (line 154); `scripts/execution-surface-matrix.js`'s 10 actual test rows don't include it, so `npm run test:matrix` — the repo's own CI-authoritative gate — would not catch a silent regression or fix in that specific bypass. `FINDINGS-INBOX.md` itself flags this as intentionally deferred by P-C. | `grep -n "id:" scripts/execution-surface-matrix.js` → 10 rows, none for `node -e` or `data:`/`http:`/`blob:` schemes | 1 |
| F-46 | Info | `FINDINGS-INBOX.md` is not cross-referenced from any other tracked file (no CHANGELOG entry, no `.agent/` directive pointer, no README pointer) and has had exactly one commit since creation — nothing forces periodic triage. | `grep -rn "FINDINGS-INBOX" --include="*.md" --include="*.json" . \| grep -v "^./FINDINGS-INBOX.md"` → no output | 1 |
| F-47 | Info | `aletheia-soak-test.js` — the only test that exercises the detector against real, unpinned, live third-party code (the exact mechanism behind F-43) — has no `npm run` entry point, is not wired into CI, and has no version-pinned lockfile for its corpus, so its own historical snapshots aren't reproducible guarantees. | `cat package.json` scripts block has no `soak` entry; `aletheia-soak-test.js` header states "no npm spawning" (reads via `require.resolve` against whatever happens to be installed) | 1 |
| F-48 | Medium | Root `README.md`'s Coverage table (line 8 summary + line 23 row) still makes an unqualified "ESM `import`/`import()` on Node ≥22.15.0/≥23.5.0 = ✅" claim. P-C split this into `file://` (✅ above floor) vs. `data:`/`http:`/`https:`/`blob:` (❌ always, any Node version) in **`packages/fw-agent/README.md`** (lines 36-37, 48-52) and **`docs/THREAT-COVERAGE.md`** (lines 156-157) — but not in root `README.md`, which P-C's own diff confirms it never touched. | `git show --stat 6c82aee` → `README.md` absent from changed files; `grep -n -iE "data:\|blob:\|http:\|file://" README.md` → zero matches (only unrelated `http://localhost` examples) | 2 |
| F-49 | Low/Info | The `node -e` inline-eval bypass (documented in `THREAT-COVERAGE.md:154`) appears in neither README's "what this does NOT intercept" summary. Possibly a deliberate scope decision (`FINDINGS-INBOX.md` only discusses the matrix generator, not the READMEs) — flagged as unresolved, not asserted as a defect. | `grep -n -E "node -e\|execArgv\|spawn\('node'" README.md packages/fw-agent/README.md` → no relevant hits | 2 |
| F-50 | Medium | `FW_REQUIRE_ESM_COVERAGE` — the new opt-in fail-closed env var shipped in the *same commit* (`85f3b4b`/P-D) that edited root `README.md` — is absent from both README's Environment Variables reference tables. A reader can only discover the variable's exact name from source, not documentation. | `grep -n "FW_REQUIRE_ESM_COVERAGE" README.md packages/fw-agent/README.md` → zero hits in either table (`README.md:250-264`, `fw-agent/README.md:66-78`); confirmed shipped: `packages/fw-agent/index.js:755,759,762` | 2 |
| F-51 | Medium | `CHANGELOG.md`'s `[Unreleased]` section is empty. Neither P-C (`6c82aee`) nor P-D/N-03 (`85f3b4b`) added an entry, despite the repo's own PR template requiring "CHANGELOG entry added under `[Unreleased]`" under a "Documentation" checklist — the same checklist P-B's release-readiness pass explicitly called out changelog cadence for. | `sed -n '8,12p' CHANGELOG.md` → `## [Unreleased]` followed immediately by `## [0.5.0] - 2026-08-18`, nothing between; `git show --stat 85f3b4b \| grep -i changelog` and same for `6c82aee`/`de1eca9` → all empty | 2 |
| F-52 | Medium | (Re-confirmation of a previously known, still-open item — original audit's F-05-equivalent / phase P-H, unstarted.) `.agent/scripts/release-warden.js:468` derives its changed-file list from `` `${candidateSha}^..${candidateSha}` `` — the last commit's parent only — never `base_sha..candidate`. This starves **three** downstream gates, not just forbidden-path detection: `FORBIDDEN_PATH_PATTERNS` (line 503), `SYNC_TRIGGER_PATTERNS` (line 786), and the engineer-receipt `changed_files` exact-set cross-check (lines 487-500). The code's own comment (lines 454-463) documents this as resting on an *unenforced* single-commit-per-candidate convention; no code path checks it and no test constructs a multi-commit fixture to exercise the violation (`release-warden.test.js` uses one fixed, already-single-commit real pair). | `grep -n "diff\|exec\|spawn" .agent/scripts/release-warden.js` → line 468 quoted in full; `grep -n "git commit\|git init" .agent/scripts/__tests__/release-warden.test.js` → zero matches | 3 |
| F-53 | Low | (Re-confirmation, original audit's F-09-equivalent / phase P-I, unstarted.) The self-integrity/Helios baseline hash concatenates all 9 tracked files' raw content with `hash.update(content, 'utf8')` per file — **no length-prefix, separator byte, or filename mixed in** — identically across all **four** independent implementations of this hash (`packages/fw-agent/index.js:177-186`, `scripts/generate-baseline.js:36-48`, `.agent/scripts/release-warden.js:67-75`, `.github/workflows/ci.yml:74-78`), and in the lockstep test's own oracle (`self-integrity-lockstep.test.js:125-134`) — so the test suite shares the same construction and cannot catch this class of issue even in principle. Practical exploitability requires an attacker who can already edit ≥2 adjacent listed files' committed source to shift bytes across a file boundary while keeping both halves independently valid, loadable JS — real but constrained; flagged as speculative on exploitability, not on the construction weakness itself. | `grep -n "createHash\|hash.update\|\.digest(" packages/fw-agent/index.js scripts/generate-baseline.js .agent/scripts/release-warden.js .github/workflows/ci.yml` → all 4 sites quoted, identical no-separator pattern | 3 |
| F-54 | **Medium-High** | Version **0.5.0** — current in both `packages/fw-agent/package.json` and `packages/fw-control/package.json`, and at the top of `CHANGELOG.md` — has **never been published to npm** and has **no git tag**. The commit that claims to "release 0.5.0" (`374bb30`/PR #65) did not actually cut a tag or publish. Actual npm registry state: only `0.3.0` and `0.4.0` exist, `dist-tags.latest = "0.4.0"`. | `git tag -l --sort=-v:refname` → `v0.4.0`, `v0.3.0` (no `v0.5.0`); `curl -sS https://registry.npmjs.org/aletheia-firewall` → `"dist-tags":{"latest":"0.4.0"}`, versions `0.3.0`/`0.4.0` only | 4 |
| F-55 | Low | `SECURITY.md`'s "Supported Versions" table still lists `0.2.x`/`0.1.x`/`< 0.1` — never updated for the actually-published `0.3.0`/`0.4.0` (per F-54, real registry state) or the in-repo `0.5.0`. As written it implies no currently-published version is "Supported." | `cat SECURITY.md` (full file read) lines 5-9 | 4 |
| F-56 | **Medium** | `SECURITY.md`'s "Policy signing key management" section (step 3, `.helios-baseline` regeneration instructions) still lists only the **old 7-file** self-integrity set — omitting `src/aho-corasick.js` and `sync-worker.js`, the exact two files whose omission `CHANGELOG.md`'s `[0.5.0]` entry and commit `374bb30` fixed as a security gap. This is a phase already marked "done" (the 9-file self-integrity fix) leaving a live, actively-wrong instruction in a doc outside that phase's stated scope: anyone following `SECURITY.md` verbatim today regenerates an **incomplete** baseline. | `cat SECURITY.md` (full file read), "Policy signing key management" step 3, vs. `ci.yml`'s 9-file list (Finding 2b, Team 4) and `.agent/scripts/release-warden.js`'s `HELIOS_SELF_INTEGRITY_FILES` (Team 3) | 4 |

### Confirmed clean / no finding (negative results — kept because they're load-bearing for consolidation)

| Area | Result | Evidence | Team |
|------|--------|----------|------|
| Node version-floor numbers | Identical (`≥18` CJS, `≥22.15.0`/`≥23.5.0` ESM) across README.md, fw-agent/README.md, THREAT-COVERAGE.md, CHANGELOG.md — 7/7 hits agree | `grep -n "22\.15\|23\.5"` across all 4 files | 2 |
| Red-team figures (95/125, 76%, 30 bypasses, 0 FP) | Identical across README.md, fw-agent/README.md, red-team/README.md; **and** freshly reproduced live (`npm run redteam` → `95/125`, `30 known bypasses`, `0 regressions`, `0 false positives`, run twice, byte-identical) — no drift in the curated corpus | `grep -n -E "[0-9]+/[0-9]+"` across 3 docs; `npm run redteam` output | 1, 2 (cross-checked independently, agree) |
| `test:adversarial` | 52/52 pass | `npm run test:adversarial` → `Results: 52 passed, 0 failed out of 52 tests` | 1 |
| Engine files (`behavior-tracker.js`, `detector.js`, `aho-corasick.js`) | **Byte-for-byte unchanged** since `3f70cc7` (pre-P-A) through `85f3b4b` (HEAD) — 8 intervening commits (P-A/B/C/D + the PR #64 release-readiness pass), none touch these 3 files. Engine-sync discipline held. | `git diff 3f70cc7 HEAD -- <3 files>` → empty; `git hash-object` matches `git show 3f70cc7:<file> \| git hash-object --stdin` for all 3 | 1 |
| `test:self-integrity`, `baseline:check`, `test:agent-graph` | All pass against current tree (4/4, baseline hash matches `85f3b4b`'s claimed `a7b8ae7c...`, 20/20) | `npm run test:self-integrity` / `npm run baseline:check` / `npm run test:agent-graph` real output | 3 |
| P-D's `index.js` change vs. release-warden pattern matching | No adverse interaction — pure content addition inside an existing `if` block, no new file, no rename, no export-signature change; both `FORBIDDEN_PATH_PATTERNS` and `SYNC_TRIGGER_PATTERNS` match whole paths (content-insensitive); baseline-regeneration carve-out independently re-invoked against the real commit and matches | `git show 85f3b4b -- packages/fw-agent/index.js` (single hunk); direct `verifyHeliosBaselineRegeneration('85f3b4b...')` call → `{"ok":true,...}` | 3 |
| `npm pack --dry-run` (fw-agent) | 13 files, matches `ci.yml`'s own enforced expectation ("verify 13-file manifest") | `cd packages/fw-agent && npm pack --dry-run` → 13 files listed | 4 |
| `.github/workflows/publish.yml` | Confirmed absent — only `ci.yml` present, no `npm publish`, no registry secrets, no `id-token: write` (expected pre-P-E state) | `ls .github/workflows/` → `ci.yml` only | 4 |
| npm attestations for `aletheia-firewall@0.3.0`/`0.4.0`/`0.5.0` | All three real `404 {"error":"Not found"}` — confirmed by live request, not assumed | `curl -sS https://registry.npmjs.org/-/npm/v1/attestations/aletheia-firewall@<ver>` ×3 | 4 |

## 4. (a) Findings that contradict something `AUDIT-VERIFICATION-v0.5.0.md` claimed

The original doc is not present in this repo as a file (§1), so no line-for-line contradiction check
was possible. Against what this directive's own brief and the affected commit messages attribute to
it:

- **No contradiction, but a scope qualifier**: the brief attributes "0 false positives" to the original
  audit's red-team figures. Team 1 reproduced that exact figure against the curated 26-benign-package
  corpus (still 0 FP, unchanged) — **but** separately found a live false positive against a real,
  uncurated npm package (F-43) that was never part of that corpus. The two aren't in conflict (they
  measure different things), but "0 false positives" read without the corpus-scope qualifier is now
  demonstrably not a general claim, as of today.
- **No contradiction**: the brief's implied "attestations = Not found" state (Team 4, §3 confirmed
  clean) and "F-05/F-09 (P-H/P-I) still unfixed" (Team 3, F-52/F-53) both independently re-verified as
  still true from current code/registry state, not carried forward from memory.

## 4. (b) Findings suggesting a phase marked "done" isn't fully done

- **P-C** (THREAT-COVERAGE.md / fw-agent-README scheme split): correctly done within its own stated
  file scope, but the root `README.md` — which makes the same class of claim — was never brought into
  sync (F-48). Whether this is "P-C incomplete" or "P-C correctly scoped, follow-on gap" is a judgment
  call left to the reader; the inconsistency itself is not in dispute.
- **P-D** (`FW_REQUIRE_ESM_COVERAGE` + Quick Start note): the env var it introduced is undocumented in
  either README's reference table, including the one P-D itself edited (F-50) — this one reads more
  clearly as P-D's own scope, incompletely executed, rather than a downstream sync gap.
- **P-B** (9-file self-integrity fix, `374bb30`): the core fix (index.js, generate-baseline.js,
  release-warden.js, CI) is correct and lockstep-tested (confirmed clean, §3) — but `SECURITY.md`'s
  parallel/duplicate instructions for manually regenerating the baseline were never updated and still
  describe the pre-fix 7-file list (F-56). `SECURITY.md` wasn't in P-B's stated file scope, which is
  exactly why this drifted unnoticed.
- **The "release 0.5.0" commit** (`374bb30`, same PR as P-B): claims a release in its own commit message
  and in `CHANGELOG.md`'s heading, but no `v0.5.0` tag was cut and nothing was published to npm — the
  registry's actual latest is still `0.4.0` (F-54). This is the most significant "marked done, not
  actually done" item in this batch: it isn't a doc-sync gap, it's the release step itself not having
  happened.
- **P-C's changelog cadence and P-D's changelog cadence**: both skipped the PR template's own
  "CHANGELOG entry added under `[Unreleased]`" checklist item (F-51), immediately after P-B's PR
  explicitly fixed changelog cadence as part of its own release-readiness scope.

## 4. (c) Net-new findings, no corresponding item anywhere in the original P-A through P-J list

F-43 (live vite false positive), F-50 (undocumented new env var), F-54 (0.5.0 never actually
published/tagged), F-55 and F-56 (SECURITY.md staleness), F-51 (changelog gap). F-44/F-45/F-46/F-47 are
net-new *observations* but not net-new *problems* — they're mostly Team 1 independently re-discovering
and cross-referencing gaps that P-C's own `FINDINGS-INBOX.md` had already disclosed and intentionally
parked; listed here for completeness since the directive asked for anything with no corresponding
original-list item, not just genuinely-hidden gaps.

## 5. Cross-team consistency

No direct factual contradictions were found between the four teams. Two teams touched adjacent ground
from different angles without conflicting: Team 1 (F-45, test-coverage lens) and Team 2 (F-49,
documentation lens) both flag the `node -e` bypass's incomplete surfacing, from different documents,
and agree on the underlying fact (`THREAT-COVERAGE.md` has it, nothing else does). Team 1 and Team 2
independently reproduced/cross-checked the red-team 95/125 figure via different methods (Team 1: fresh
suite run; Team 2: cross-doc grep) and agree. Team 1's commit-range enumeration (`3f70cc7..HEAD`,
8 commits) and Team 2's independent P-A/B/C/D-to-commit-hash mapping (via `git log --grep`) are
consistent with each other and with the orchestrator's own precondition check in §0.

## 6. Next steps

Per the directive: this document stops at consolidated findings. No phase directives are drafted here.
Hand this branch (`audit/v0.5.1-post-blockers`) to an independent reviewer with a fresh clone to
confirm or correct each finding above before anything gets acted on — same pattern as every phase
through P-D.
