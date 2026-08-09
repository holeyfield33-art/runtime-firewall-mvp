# Aletheia Firewall v0.3.0 Performance Freeze

This document freezes the current v0.3.0 performance evidence and clearly distinguishes measured performance from engineering targets.

## Scope

- Package: `aletheia-firewall`
- Version: `0.3.0`
- Measured on: Linux x64
- Node: `v24.14.0`
- CPU: AMD EPYC 7763 64-Core Processor
- Visible cores: 2
- Workload: `900` unique module compilations in a flat synthetic require graph
- Benchmark artifacts: `results/benchmarks/steady-state-compile-attr-1786239354906.json`, `results/benchmarks/cold-steady-1786238591687.json`, `results/benchmarks/hook-cost-profile-1786240316309.json`

## Measured results (current evidence)

### 900-module steady-state compile attribution

From `results/benchmarks/steady-state-compile-attr-1786239354906.json`:

- Baseline steady-state compile: `7.492349 ms` median
- Hook-only steady-state compile: `12.4238695 ms` median
- Hook+scan steady-state compile: `12.3923505 ms` median

### What this means

- The runtime `Module._compile` interception hook is the dominant measured steady-state cost.
- `Detector.scanModuleSync` is not the dominant cost for the verified 900-module steady-state workload.
- Hook-only and hook+scan medians are effectively identical, which confirms scan execution is a secondary contributor in this workload.

### Cold-start evidence

From `results/benchmarks/cold-steady-1786238591687.json`:

- Cold baseline median: `88.3850275 ms`
- Cold agent median: `173.5047455 ms`
- Cold median overhead: `100.26490337768423 %`

This cold-start artifact shows that agent initialization and cold compilation preparation remain a significant startup cost in the current v0.3.0 evidence.

## Gate threshold vs release evidence

The repository maintains a **25% median compilation-overhead gate budget** for regression control, but that is a budget/threshold, not a measured v0.3.0 guarantee.

- **Current measured performance is not claimed to be ≤25%.**
- The 25% figure is a regression guard used by the gate, not a release guarantee.
- The current v0.3.0 evidence instead shows that the actual hook path is the current performance limiter.

## Methodology

- The baseline and agent measurements use the existing repository benchmark harnesses.
- No benchmark methodology has been altered for this freeze.
- The steady-state attribution harness records warmups and measured iterations separately, then reports medians and percentiles from steady-state samples.
- The hook attribution artifact measures the compilation hook with and without scanner invocation to isolate cost centers.

## Artifacts and evidence

- `results/benchmarks/steady-state-compile-attr-1786239354906.json` — steady-state compile attribution evidence for baseline, hook-only, and hook+scan workloads.
- `results/benchmarks/cold-steady-1786238591687.json` — cold-start baseline and agent evidence.
- `results/benchmarks/hook-cost-profile-1786240316309.json` — hook component profiling evidence.
- `docs/BENCHMARK.md` — benchmark specification and schema for reproducible results.

## Notes

- This file is the canonical v0.3.0 performance evidence summary.
- Public-facing documentation should continue to treat 25% as a gate budget rather than a demonstrated release result.
- Future optimization work must start from this frozen evidence and preserve current security semantics.
