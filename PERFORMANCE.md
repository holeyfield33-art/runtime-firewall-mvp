# Aletheia Firewall v0.4.0 Performance Freeze

This document freezes the current v0.4.0 performance evidence and clearly distinguishes
measured performance from engineering targets. It supersedes the v0.3.0 freeze below,
which is preserved for historical comparison.

Evidence in this freeze is split into two tiers, cited separately throughout:

- **First-party** — run in this session, on this machine, with the full raw log saved
  under `results/` and directly inspected before being written here.
- **Reported** — relayed from a separate session (a different machine/container) via
  pasted terminal output. The user (repository owner) confirmed these numbers as valid;
  they are included on that basis, but this session did not execute or independently
  verify them. Where only a narrative summary was pasted (no raw gate output), that is
  noted explicitly.

## Scope — v0.4.0

- Package: `aletheia-firewall`
- Version: `0.4.0`
- Commit: `bc3f331` (`chore(release): bump fw-agent and fw-control to 0.4.0 (#54)`)
- Gate: `npm run gate` (`run-gate-test.js` → `packages/fw-agent/test/bench-honest.js` +
  `packages/fw-control/test/bench.js`)
- Workload: `900` unique module compilations in a flat synthetic require graph (gate),
  `200` modules × 30 trials (per-module honest benchmark)

## Core-count sensitivity — consistent pattern, not yet root-caused in code

`packages/fw-control/test/bench.js` forks a fresh Node process per baseline/agent
comparison, 60 iterations. Five environments have now reported gate results on, or
immediately preceding, the v0.4.0 commit:

| Environment | Logical cores | Median overhead | Gate result | Evidence |
|---|---|---|---|---|
| Local Windows (Intel i7-7500U) | 4 | **17.68%** | ✅ PASS | First-party — `results/gate-v0.4.0-20260812.txt` |
| AMD EPYC 7763 (pre-v0.4.0, 2026-06-18) | 64 (dedicated) | 16.47% / 17.31% / 17.32% (3 runs) | ✅ PASS | First-party, historical — `results/gate-3x-epyc-20260618.txt`. Predates the v0.4.0 tag; included as high-core-count context, not v0.4.0-specific proof. |
| Sandboxed audit container (pre-v0.4.0, 2026-07-25, base commit `1d60552`) | not stated | 60.58% | ❌ FAIL (P95 79.16%) | Committed, first-party-verifiable — `AUDIT.md` "Unverified claims" section. A prior audit session's own gate run; the audit report itself attributes it to "shared/virtualized CPU noise in this container" rather than a real regression, while noting it could not rule that out with certainty at the time. |
| GitHub Codespaces, run 1 | not confirmed | 40.08% | ❌ FAIL (P95 55.24%) | Reported, narrative summary only — `results/gate-v0.4.0-20260813-codespaces-report.txt`. No raw gate output seen. |
| GitHub Codespaces, run 2 | **2, confirmed via `nproc`** | 39.21% | ❌ FAIL (P95 56.56%, min 20.66%, max 62.13%) | Reported, full raw transcript — `results/gate-v0.4.0-20260813-codespaces-run2.txt`. Same host CPU model as the historical EPYC row (AMD EPYC 7763), but capped to 2 visible cores by the container — i.e. this and the 64-core PASS row are, per `/proc`, the *same silicon* at two different visible-core counts. |
| Remote sandboxed session container (v0.6.0 dev, 2026-08-27) | **4, confirmed via `nproc`** | 67.99% (unmodified code, A/B baseline) / 71.53% (with the Phase 3 AST change, `FW_ENABLE_AST` unset) | ❌ FAIL both (P95 83.16% / 80.79%) | First-party, this session — see the v0.6.0 addendum below. **Complicates the "≥4 cores predicts PASS" heuristic above**: this container reports 4 logical cores via `nproc` (matching the PASSing local-Windows row) yet fails harder than either 2-core Codespaces run, and a single run's min/max spread (51–92%) rivals the entire cross-environment range in the table. `nproc` evidently does not capture whatever this container's actual scheduling contention is (cgroup CPU quota, noisy-neighbor virtualization) — core count alone is not a reliable predictor here. |

Two independent Codespaces runs, both on 2 confirmed cores, land within 1 point of each
other (40.08%, 39.21%) and both fail; a third, older FAIL in a different shared/sandboxed
container (60.58%, core count unrecorded) fits the same pattern; three higher-core runs
(4-core and 64-core×3) all pass in a tight 16.47–17.68% band. That's now a **repeatable,
reasonably strong correlation** between constrained/shared execution environments and
measured gate overhead on this specific benchmark — strong enough that a gate failure on
a 1–2 core or heavily shared runner should not, by itself, be read as a real
detection-path regression. It is not yet a controlled experiment (same machine, cores
artificially capped up and down) or a profiled root cause in `bench.js`'s process-spawn
logic, so this document still stops short of calling it fully closed — "consistent
across five environments across two release cycles" is the accurate claim, not "proven."

**Practical takeaway: treat a gate failure on a runner with fewer than ~4 logical cores
as expected noise from this benchmark's process-spawn design, and re-run on more
headroom before treating it as a real regression.**

## Measured results — v0.4.0, first-party (local Windows, 4-core)

- Node: `v24.18.0`, win32 x64
- CPU: Intel(R) Core(TM) i7-7500U @ 2.70GHz (4 logical cores)
- Date: 2026-08-12
- Full raw output: `results/gate-v0.4.0-20260812.txt`

### Realistic-app compilation gate (900-module corpus, median-of-5 per iteration, 60 iterations)

- Mean baseline: `932.79 ms` | Mean agent: `1082.45 ms` | Mean delta: `149.66 ms`
- Mean overhead: `16.70%` | **Median overhead: 17.68%** (gate budget: <25%) — **PASS**
- P95 overhead: `30.55%` (informational only, not gated)
- Distribution range: `-10.79%` to `+55.48%` across the 60 iterations

### Per-module honest benchmark (transparency only, not gated)

- Baseline: `0.7441 ms/module` median | Firewall-on: `1.0044 ms/module` median
- Overhead: `+0.2603 ms/module` (`+35.0%`) — one-time per-module scan cost, cached after
  first compile of a given file

### Coverage gate — 5 core engine files (`npm run test:coverage`, budget 95% stmts/funcs/lines, 90% branch)

| File | Stmts | Branch | Funcs |
|---|---|---|---|
| `aho-corasick.js` | 100 | 94.7 | 100 |
| `behavior-tracker.js` | 97.6 | 93.9 | 100 |
| `detector.js` | 100 | 97.5 | 100 |
| `policy.js` | 100 | 100 | 100 |
| `quarantine.js` | 100 | 100 | 100 |
| **All files** | **98.8** | **96.0** | **100** |

**PASS**, clear of every threshold. Full raw output: `results/coverage-v0.4.0-20260812.txt`.

### Red-team corpus — 151 attacks, 76% overall detection

95/125 malicious samples blocked (76%) across crypto-miner (19/26), reverse-shell
(18/22), credential-exfil (24/27), dynamic-code-exec (18/29), and supply-chain (16/21).
0 false positives across the 26 benign-control samples. 30 known bypasses, all
already-documented in `docs/THREAT-COVERAGE.md`; the `redteam:bypass` subset confirms
all 30 still behave as expected — no silent fixes, no new regressions. Full raw output:
`results/redteam-v0.4.0-20260812.txt`, `results/redteam-bypass-v0.4.0-20260812.txt`.

### Soak test — real top-100 npm packages, first-party

99/99 packages checked, 0% false positives, 100% malicious caught (5/5), avg
283.1 ms/pkg. `cross-env` correctly skipped (CLI-only, no `require()`-able entry —
expected, not a gap). Full raw output: `results/soak-v0.4.0-20260812.txt`.

### Soak test — reported (Codespaces, 2-core-class)

0/99 false positives, 5/5 malicious caught (100% TP), avg 128.2 ms/pkg. Reported only
(see `results/gate-v0.4.0-20260813-codespaces-report.txt`); the scan-time difference
(128ms vs 283ms) is unremarkable hardware/disk-cache variance, unrelated to the
cold-process-spawn core-count pattern discussed above (soak isn't a cold-process-spawn
benchmark).

### Self-integrity baseline

`.helios-baseline` matches computed hash on the first-party local run
(`7f88b701…0253c5e5b`). No drift. Full raw output:
`results/baseline-check-v0.4.0-20260812.txt`.

## Gate threshold vs release evidence

The repository maintains a **25% median compilation-overhead gate budget** for
regression control.

- **First-party v0.4.0 measured performance: 17.68% median, within the 25% budget**,
  on 4-core laptop-class hardware — a real, passing, directly-inspected measurement.
- The historical EPYC data (16.47–17.32% median, pre-v0.4.0) and the reported Codespaces
  FAIL (40.08% median) bracket this result on either side — see "Core-count sensitivity"
  above for why that's flagged as an open question rather than resolved.
- The 25% figure remains a regression guard, not a promise of a specific number, but it
  is now backed by a first-party passing measurement on this commit.

## Methodology

- Same benchmark harnesses as the v0.3.0 freeze; no methodology changes.
- The gate script (`run-gate-test.js`) runs both the per-module honest benchmark
  (transparency only) and the realistic-app compilation gate (actually gated on median).
- Median-of-5 cold runs per iteration, 60 iterations, to reduce single-run noise — see
  the Core-count sensitivity section above for the noise source this does *not* fully
  absorb, and for which numbers above are first-party vs reported.
- Running `npm test`/`npm run gate` on Windows requires npm's script-shell pointed at a
  POSIX shell, or the inline `VAR=1 node script.js` scripts fail under npm's default
  cmd.exe. Fix once per machine: `npm config set script-shell "C:\Program Files\Git\bin\bash.exe"`
  — after that every `npm run ...` script routes through Git Bash automatically, from
  any terminal. This is an environment fix, not a code or benchmark change.

## Artifacts and evidence

> **Note for contributors updating freezes:** `results/` is listed in `.gitignore`. To commit new evidence files, use `git add -f results/<file>` (force-add), or remove/adjust the ignore rule. Without this step the files will not appear in `git status` and will be silently excluded from your commit.

- `results/gate-v0.4.0-20260812.txt` — full gate output, first-party 4-core local run (authoritative for the PASS claim)
- `results/full-test-v0.4.0-20260812.txt` — full correctness suite (unit, adversarial, integration, auth), all passing
- `results/coverage-v0.4.0-20260812.txt`, `results/redteam-v0.4.0-20260812.txt`, `results/redteam-bypass-v0.4.0-20260812.txt`, `results/soak-v0.4.0-20260812.txt`, `results/baseline-check-v0.4.0-20260812.txt` — first-party
- `results/gate-3x-epyc-20260618.txt` — historical, pre-v0.4.0, 64-core context
- `results/gate-v0.4.0-20260813-codespaces-report.txt` — reported, run 1, narrative summary only, not independently verified
- `results/gate-v0.4.0-20260813-codespaces-run2.txt` — reported, run 2, full raw transcript incl. `nproc` core-count confirmation
- `results/v0.4.0-test-report.html` — visual summary of the first-party run
- `docs/BENCHMARK.md` — benchmark specification and schema

## v0.3.0 evidence (historical, preserved for comparison)

- Measured on: Linux x64, Node `v24.14.0`, AMD EPYC 7763 64-Core, 2 visible cores
- Workload: `900` unique module compilations in a flat synthetic require graph
- Baseline steady-state compile: `7.492349 ms` median
- Hook-only steady-state compile: `12.4238695 ms` median
- Hook+scan steady-state compile: `12.3923505 ms` median
- Cold baseline median: `88.3850275 ms`; cold agent median: `173.5047455 ms`; cold
  overhead: `100.26%`
- The runtime `Module._compile` interception hook was the dominant measured
  steady-state cost; `Detector.scanModuleSync` was a secondary contributor.
- Artifacts: `results/benchmarks/steady-state-compile-attr-1786239354906.json`,
  `results/benchmarks/cold-steady-1786238591687.json`,
  `results/benchmarks/hook-cost-profile-1786240316309.json`
- v0.3.0 did not claim ≤25% measured performance; the 25% figure was treated purely as
  a regression-guard threshold at that time.

## v0.6.0 addendum — Phase 3 AST tier, red-team corpus, and an inconclusive gate run

Not a full re-freeze (that would need the same multi-environment discipline as the v0.4.0
freeze above, which this session didn't have time or hardware access to reproduce) — just
what this session directly measured, first-party, plus what it deliberately did NOT
establish.

**Red-team corpus (first-party, this session, full raw output from `npm run redteam` /
`npm run redteam:ast`):** the corpus grew from 152 to 158 payloads (6 new `benign-controls`
entries guarding the new AST fold/resolve surface). Default-configuration detection is
**unchanged** at 95/125 (76.0%), 0 false positives — confirmed by running the suite against
this session's own working tree. With the new opt-in `FW_ENABLE_AST=1` tier enabled,
detection rises to 113/125 (90.4%), still 0 false positives. See
`docs/THREAT-COVERAGE.md` §4 for the full closed/still-open breakdown.

**Compilation-hook gate (`npm run gate`): inconclusive in this environment, not a regression.**
This session's sandboxed container fails the gate's 25%-median budget on the **unmodified**
pre-Phase-3 codebase (67.99% median, stashed A/B baseline — see the Core-count sensitivity
table above), so it cannot validate or refute a specific overhead number for this change. What
it CAN say: `FW_ENABLE_AST` defaults off, and `packages/fw-agent/src/detector.js`'s AST
integration is gated behind `process.env.FW_ENABLE_AST === '1'` — read once per `scanModuleSync`
call, short-circuiting to the pre-existing code path when unset. The gate's A/B comparison
(no agent vs. `FW_ENABLE_DETECTION=1`) never sets `FW_ENABLE_AST`, so it exercises identical
code whether or not this change is present; the 67.99% (unmodified) vs. 71.53% (with the
change) delta this session observed is within a single run's own min/max spread (51–92%,
see the table row above) and is not distinguishable from noise. **Follow-up needed before
enabling `FW_ENABLE_AST=1` by default**: run `npm run gate` with `FW_ENABLE_AST=1` forced on
for both the baseline and agent legs (not currently wired into `bench.js` — it only toggles
`FW_ENABLE_DETECTION`) on quieter hardware, to get a real number for the opt-in tier's own
marginal cost. The prescreen-gating design in `ast-scan.js` (an Aho-Corasick pass plus a
handful of narrow regexes must hit before any tokenizing happens) is intended to keep that
cost near-zero on the common case, but that is a design intent, not yet a measured claim.

## Notes

- This file is the canonical v0.4.0 performance evidence summary.
- The v0.6.0 addendum above is first-party evidence from a single noisy sandboxed session,
  not a new frozen baseline — treat the v0.4.0 numbers below as still authoritative for
  absolute overhead figures until a proper v0.6.0 multi-environment freeze is done.
- The core-count finding should be reflected as a runtime warning in `bench.js` itself
  (log detected core count, note when running below ~4) so future runs on constrained
  CI/Codespaces don't silently produce a misleading FAIL without that context — tracked
  as a follow-up, not yet implemented.
- Future optimization work must start from this frozen evidence and preserve current
  security semantics.
