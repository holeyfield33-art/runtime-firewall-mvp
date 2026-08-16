# Security Gates

These are the deterministic conditions `scripts/release-warden.js` evaluates. None of them are
subject to model judgment. If the code and the prose here ever disagree, the code in
`scripts/release-warden.js` is authoritative — this file documents intent, the script enforces it.

## FREEZE conditions (stop everything, no auto-recovery)

| Condition | Detection |
|---|---|
| Missing engineer or verifier receipt | file existence check |
| Receipt fails schema validation | `validate-receipt.js` against `contracts/*.schema.json` |
| Candidate SHA mismatch across engineer receipt / verifier receipt / checkpoints | set comparison |
| Candidate SHA changed between `a2-verify-start` and `a2-verify-end` | checkpoint comparison |
| Forbidden file modified | path pattern match against `engineer-receipt.changed_files` |
| Cited evidence missing from `evidence/index.json` | index lookup |
| `docs-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/docs-receipt.schema.json` |
| `docs-receipt.changed_files` contains a path outside the documentation allowlist, or a forbidden path | set comparison against `DOC_PATH_ALLOWLIST` / `FORBIDDEN_PATH_PATTERNS` |

## Forbidden paths (any match in `changed_files` is an automatic FREEZE)

```
mrn[-_]?crs                        (anywhere in the path, case-insensitive)
.npmrc
.helios-baseline
policy.signed.json
.agent/contracts/**
.agent/scripts/**
.agent/rules/**
.agent/agents/**
```

The last four exist so Agent 1 cannot edit the gate that judges its own work — the control plane
must be out of scope for the very directive it is enforcing.

## Documentation allowlist (Agent 4 only — any match NOT in this list is an automatic FREEZE)

```
CHANGELOG.md
README.md                          (root, or any packages/*/README.md)
docs/**
.agent/README.md
```

Unlike A1's list, this is an **allowlist**, not a blocklist: Agent 4's entire mandate is
documentation, so a `docs-receipt.changed_files` entry that matches neither this list nor the
forbidden-path list above is still out of scope — there is no third category. This is checked
only if `docs-receipt.json` exists in the run directory; its absence never affects `PASS`/`BLOCK`/
`FREEZE` for the A1/A2/A3 loop.

## BLOCK conditions (verification loop must continue, not a fatal stop)

| Condition | Detection |
|---|---|
| `red-team-verifier` reported `FAIL` | `verifier-receipt.status !== 'PASS'` |
| Any `engineer-receipt.tests_run[*].exit_code !== 0` | P0 regression signal |
| `verifier-receipt.regressions[*]` contains a non-OK entry | explicit regression report |

BLOCK differs from FREEZE: BLOCK means "this candidate isn't good enough yet, send it back to
`A1_REWORK`." FREEZE means "something about the process/provenance itself broke — a human must
look at this before anything continues."

## Manual checks not automatable from `changed_files` alone

`release-warden.js` cannot see diff content, only the file list an engineer receipt declares.
Before a human approves any release, additionally check by hand:

- `package.json` version fields were not bumped by Agent 1 (that is a human/release decision).
- No `publishConfig` changes.
- `npm pack --dry-run` output has no unexpected files (see root release procedure in the
  Phase 2 directive — this is unchanged and still applies after the `.agent/` graph passes).

## Registry modification

"Registry" here means the npm package registry and its local config surface (`.npmrc`,
`publishConfig` in any `package.json`, anything that would run during `npm publish`). The
`.agent/` graph never runs `npm publish` itself. Any evidence command containing `npm publish`
must be treated as a FREEZE-worthy anomaly if ever found in a run's evidence log.
