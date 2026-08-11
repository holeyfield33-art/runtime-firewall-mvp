# Benchmark Specification — Aletheia Runtime Firewall

Purpose: specify reproducible performance benchmark metadata, workloads, modes, iterations, and machine-readable result schema for the compilation-hook gate.

## 1. Environment (must be recorded for each run)

- OS: `process.platform`
- architecture: `process.arch`
- CPU: `os.cpus()` model and core count
- memory: `os.totalmem()` (bytes)
- Node version: `process.version`
- npm version: `npm --version`
- git SHA: `git rev-parse HEAD` (nullable if not a git checkout)
- package version: root `package.json` `version`
- benchmark version: string set by harness (e.g., `bench-v1`)

## 2. Modes

- `OFF`: agent not installed (baseline)
- `OBSERVE`: agent installed but non-blocking observations only
- `BLOCK`: agent blocking detections active
- `QUARANTINE`: quarantine behavior active

## 3. Workloads (identity strings used in artifacts)

- `small-module`: small set of modules (microbenchmark)
- `medium-module`
- `large-module`
- `dependency-tree`: real app dependency tree
- `cold-900-module-flat`: the realistic gate workload (900 unique top-level requires)
- `hook-microbench`: direct Module._load microbenchmark
- `cold-start`, `warm-start`, `repeated-require` are conceptual labels; cold vs warm are measured separately

## 4. Zero-baseline handling

- When a measured baseline sample for an iteration is exactly zero (`baseline_i === 0`), a relative percentage overhead cannot be calculated. The harness MUST record the per-iteration overhead sample as `null` in the raw `overheads` array to preserve measurement provenance.
- Statistical summaries (median, mean, percentiles, stddev) are computed only over numeric overhead samples; `null` entries are ignored for aggregation but preserved in raw output.

## 5. Metadata

- `metadata.package`: `{ name, version }` — the package under test (the agent package `packages/fw-agent/package.json`)
- `metadata.repositoryVersion`: the repository root `package.json` `version` (recorded separately)

## 6. Iteration policy

- Warm-up iterations MUST be run then excluded from measured samples. The harness must record `warmupIterations`.
- Measured iterations MUST be independent samples; the harness records `measuredIterations` and raw `samples`.
- Choose repetitions to characterize variance; the existing gate uses `iterations=60`, `repeatsPerIter=5`, `warmupIters=10` for the `cold-900-module-flat` workload.

## 7. Statistical methodology

- Store raw samples (do not overwrite). Derived statistics computed deterministically from raw samples.
- Percentiles: nearest-rank method (rank = ceil(p/100 * N)). Documented and stable.
- Report: `min`, `median`, `p95`, `p99`, `max`, `mean`, `stddev` (population stddev, ddof=0).

## 8. Machine-readable result schema

Top-level object:

```jsonc
{
  "metadata": { /* environment provenance */ },
  "workload": { "name": "cold-900-module-flat", "modules": 900, "iterations": 0, "repeatsPerIter": 0, "warmupIters": 0 },
  "mode": "cold-process",
  "raw": { "baseline": [...], "agent": [...], "overheads": [...] },
  "statistics": {
    "baseline": { "min": 0, "median": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0, "stddev": 0 },
    "agent": {...},
    "overhead": {...}
  },
  "gate": { "medianBudget": 0, "p95Budget": 0 }
}
```

Fields are deliberately explicit: raw arrays contain steady-state samples only (warmup excluded). Percentile method is nearest-rank; implementers must not change it silently.

## 9. Reproducibility

- Harness MUST write artifacts to `results/benchmarks/raw/` using a timestamped filename.
- Also produce a human-readable console summary but never replace raw samples with summarized values.

## 10. Notes

- This document is Phase 1 deliverable: specification + schema. Implementation of harness writes JSON artifacts alongside existing human-readable output.
