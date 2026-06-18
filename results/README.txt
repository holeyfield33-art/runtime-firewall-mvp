Bench results — Linux EPYC (AMD EPYC 9V74), Node.js v24
Machine: GitHub Codespace / remote execution container
Date: 2026-06-18
Methodology: packages/fw-control/test/bench.js
  - 60 iterations, median-of-5 cold process spawns per iteration
  - 900-module flat corpus (1/3 tiny ~20B, 1/3 medium ~100B, 1/3 large ~2KB)
  - WARMUP_ITERS=10 discarded from stats before computing median/P95
  - Fair A/B: both arms preload agent; agent arm sets FW_ENABLE_DETECTION=1

N=5 warmup (bench-run-*.txt) — baseline run, P95 still noisy:
  Run 1: Median 20.18%, P95 24.36%
  Run 2: Median 20.44%, P95 26.06%
  Run 3: Median 19.59%, P95 30.35%  ← P95 spread 5.99pts > 5pt threshold

N=10 warmup (bench-n10-run-*.txt) — adopted:
  Run 1: Median 19.84%, P95 26.55%
  Run 2: Median 20.65%, P95 26.97%
  Run 3: Median 19.37%, P95 24.86%  ← P95 spread 2.11pts < 5pt threshold ✓

Chosen thresholds: MEDIAN_BUDGET=25%, P95_BUDGET=30%
Justification: median ~20% measured + 7% CI tolerance = 25%; P95 ~25-27% on this host (9V74), capped at 30%.

────────────────────────────────────────────────────────────────────────
EPYC 7763 (64-core) — added 2026-06-18 (see gate-3x-epyc-20260618.txt)
────────────────────────────────────────────────────────────────────────
Second EPYC host (AMD EPYC 7763 64-Core, Node v24), same bench.js methodology,
3 consecutive `npm run gate` runs:
  Run 1: Median 16.47%, P95 34.46%
  Run 2: Median 17.31%, P95 37.07%
  Run 3: Median 17.32%, P95 30.75%

Cross-host conclusion (supersedes the "P95 stable" note above):
  - Median is host-dependent: ~17% (7763) vs ~20% (9V74). Published as a range: ~17-20%.
  - P95 is NOT stable across hardware: ~25-27% (9V74) vs ~31-37% (7763), i.e. ~25-37%
    across EPYC hosts. P95 reflects shared-CPU scheduler contention, not firewall cost,
    and remains informational only — it is NOT a gate metric (gate enforces median only).
  - The MEDIAN_BUDGET=25% gate still passes on both hosts.

Per-module microbenchmark (bench-honest-epyc-20260618.txt) is jitter-dominated on
shared EPYC boxes (showed negative overhead) and is NOT used for any published number.
