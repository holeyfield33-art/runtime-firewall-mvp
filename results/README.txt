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
Justification: median ~20% measured + 7% CI tolerance = 25%; P95 stable at ~25-27%, capped at 30%.
