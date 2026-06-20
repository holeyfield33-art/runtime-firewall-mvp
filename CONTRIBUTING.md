# Contributing to Aletheia Firewall

Thank you for contributing. This document encodes the non-negotiable rules for this codebase. Violating any of them in a PR is grounds for rejection regardless of the change's other merits.

## Rules

### 1. Engine-file edits require a baseline regeneration in the same PR

The six self-hashed engine files are:

- `packages/fw-agent/index.js`
- `packages/fw-agent/src/detector.js`
- `packages/fw-agent/src/behavior-tracker.js`
- `packages/fw-agent/src/policy-watcher.js`
- `packages/fw-agent/src/quarantine.js`
- `packages/fw-agent/src/audit-log.js`

Any edit to any of these files MUST be accompanied by a regenerated `.helios-baseline` committed in the same PR. If they diverge, the firewall will refuse to start.

To regenerate the baseline, run this from `packages/fw-agent`:

```bash
node -e "
const crypto = require('crypto');
const fs = require('fs');
const files = [
  'index.js',
  'src/detector.js',
  'src/behavior-tracker.js',
  'src/policy-watcher.js',
  'src/quarantine.js',
  'src/audit-log.js',
];
const hash = crypto.createHash('sha256');
for (const f of files) hash.update(fs.readFileSync(f));
fs.writeFileSync('.helios-baseline', hash.digest('hex') + '\n', 'utf8');
console.log('Baseline written.');
"
```

If you are unsure whether your change touches an engine file, err on the side of regenerating.

### 2. Never loosen the performance gate

The gate enforces **median overhead only**, at a **25% budget**. P95 overhead is reported for transparency but is not a fail condition, and no threshold is defined for it.

- Do not lower the median budget below 25%.
- Do not add a P95 gate.
- Do not change the gate from median to mean, max, or any other statistic.

If a code change causes the median to exceed 25% on a reproducible benchmark, the change must be reworked -- the gate exists to catch regressions, not to be softened.

### 3. Every performance number must trace to results/

Do not hand-paste or quote numbers from memory in documentation or commit messages. Every figure cited in docs must correspond to a committed file in `results/`. Performance is host-dependent:

- AMD EPYC 9V74 (80-core): median ~20% -- see `results/bench-n10-run-*.txt`
- AMD EPYC 7763 (64-core): median ~17% -- see `results/gate-3x-epyc-20260618.txt`

The published range is ~17-20%. Always name the hardware. Never pin a single number without a host qualifier. P95 (~25-37% across hosts) is informational and must be labeled as such.

### 4. Stage files by name; never `git add .`

This is a public repository. Staging every file explicitly by name prevents accidentally committing `.env`, benchmark scratch files, demo artifacts, or results noise.

```bash
# Correct
git add packages/fw-agent/src/detector.js packages/fw-agent/.helios-baseline

# Never do this
git add .
git add -A
```

### 5. Zero runtime dependencies in fw-agent

The `aletheia-firewall` package must have no `dependencies` or `optionalDependencies`. It uses only Node.js built-ins. Adding a runtime dep requires a team discussion and a documented rationale in the PR.

### 6. Explicit error handling; no silent broad catch

```javascript
// Bad: swallows unexpected failures
try { doSomething(); } catch (e) {}

// Acceptable only when documented with the specific expected failure
try { fs.mkdirSync(dir); } catch (e) { /* EEXIST is expected; re-throw anything else */ if (e.code !== 'EEXIST') throw e; }
```

If you must swallow an error, name the specific case you are handling and why.

## Build and Test

All commands run from `packages/fw-agent` unless noted otherwise.

```bash
# Unit tests (Aho-Corasick automaton + detector logic)
npm test

# Adversarial bypass suite (12 test cases; all must pass)
npm run test:adversarial

# Both (from repo root)
npm run test:unit && npm run test:adversarial
```

Before opening a PR, confirm that:

1. `npm test` passes from `packages/fw-agent`.
2. `npm run test:adversarial` passes from `packages/fw-agent`.
3. `npm pack --dry-run` from `packages/fw-agent` shows exactly 13 files.
4. If you touched any of the six engine files, `.helios-baseline` has been regenerated and the self-integrity CI step passes.

## PR Description

Include:
- What changed and why.
- Which rules above apply and how you satisfied them.
- If any performance numbers are added or updated, which `results/` file they come from.
