# Security Gates

These are the deterministic conditions `.agent/scripts/release-warden.js` evaluates. None of them are
subject to model judgment. If the code and the prose here ever disagree, the code in
`.agent/scripts/release-warden.js` is authoritative — this file documents intent, the script enforces it.

## FREEZE conditions (stop everything, no auto-recovery)

| Condition | Detection |
|---|---|
| Missing engineer or verifier receipt | file existence check |
| Receipt fails schema validation | `validate-receipt.js` against `contracts/*.schema.json` |
| Candidate SHA mismatch across engineer receipt / verifier receipt / checkpoints | set comparison |
| Candidate SHA changed between `a2-verify-start` and `a2-verify-end` | checkpoint comparison |
| `base_sha` equals `candidate_sha`, or is not a real git ancestor of it | `git merge-base --is-ancestor` |
| `base_sha` differs from the matching directive's own `base_sha` with no `base_sha_note` disclosing why | directive lookup by `phase_id` |
| Engineer's self-reported `changed_files` doesn't exactly match the git-derived list | set comparison (see below) |
| Forbidden file modified | git-derived path list — `.agent/scripts/release-warden.js` runs `git diff --name-only candidate^..candidate` (the candidate commit's own diff against its immediate parent, never the self-reported list, and never the distant directive-level `base_sha` — see the script's own comment for why that distinction matters) |
| Cited evidence missing from `evidence/index.json` | index lookup |
| `docs-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/docs-receipt.schema.json` |
| `docs-receipt.changed_files` contains a path outside the documentation allowlist, or a forbidden path | set comparison against `DOC_PATH_ALLOWLIST` / `FORBIDDEN_PATH_PATTERNS` in `.agent/scripts/release-warden.js` |
| Directive sets `require_reliability_review: true` but `reliability-receipt.json` is missing | file existence check, directive lookup by `phase_id` |
| `reliability-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/reliability-receipt.schema.json` |
| `reliability-receipt.candidate_sha` does not match the resolved `candidate_sha` | set comparison |
| `reliability-receipt` cites evidence missing from `evidence/index.json` | index lookup |
| Directive sets `require_threat_model: true` but `threat-model.json` is missing | file existence check, directive lookup by `phase_id` |
| `threat-model.json` present but fails schema validation | `validate-receipt.js` against `contracts/threat-model.schema.json` |
| `threat-model.candidate_sha` does not match the resolved `candidate_sha` | set comparison |
| `threat-model` cites evidence missing from `evidence/index.json` | index lookup |
| Directive requires a threat model and `threat-model.status !== 'COMPLETE'` | field check — attacking off an admittedly incomplete map is refused |
| Directive sets `require_quality_review: true` but `quality-receipt.json` is missing | file existence check, directive lookup by `phase_id` |
| `quality-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/quality-receipt.schema.json` |
| `quality-receipt.candidate_sha` does not match the resolved `candidate_sha` | set comparison |
| `quality-receipt` cites evidence missing from `evidence/index.json` | index lookup |
| Directive sets `require_test_review: true` but `test-coverage-receipt.json` is missing | file existence check, directive lookup by `phase_id` |
| `test-coverage-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/test-coverage-receipt.schema.json` |
| `test-coverage-receipt.candidate_sha` does not match the resolved `candidate_sha` | set comparison |
| `test-coverage-receipt` cites evidence missing from `evidence/index.json` | index lookup |
| Directive sets `require_compatibility_review: true` but `compatibility-receipt.json` is missing | file existence check, directive lookup by `phase_id` |
| `compatibility-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/compatibility-receipt.schema.json` |
| `compatibility-receipt.candidate_sha` does not match the resolved `candidate_sha` | set comparison |
| `compatibility-receipt` cites evidence missing from `evidence/index.json` | index lookup |
| Directive sets `require_release_audit: true` but `release-audit-receipt.json` is missing | file existence check, directive lookup by `phase_id` |
| `release-audit-receipt.json` present but fails schema validation | `validate-receipt.js` against `contracts/release-audit-receipt.schema.json` |
| `release-audit-receipt.candidate_sha` does not match the resolved `candidate_sha` | set comparison |
| `release-audit-receipt` cites evidence missing from `evidence/index.json` | index lookup |
| `release-audit-receipt.packaged_files` contains any path matching `PACKAGE_DENY_PATTERNS` | mechanical scan — runs whenever the receipt exists, regardless of its own `status` field or the `require_release_audit` opt-in |

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

## Package deny patterns (any match in a Release Auditor's `packaged_files` is an automatic FREEZE)

```
test/, tests/, __tests__/    (anywhere in the path)
*.test.js, *.spec.js
.git/, .github/
node_modules/
.env, .env.*
*-key.pem, dev-private-key.pem
.agent/
red-team/
coverage/, .nyc_output/
*.log
```

Unlike the forbidden-path list above (which governs what Agent 1 may *change*), this governs what
a Release Auditor's real `npm pack --dry-run` output may *contain* — checked mechanically by
`release-warden.js` whenever `release-audit-receipt.json` exists, independent of that receipt's
own `status` field and independent of whether `require_release_audit` was even set. See
`.agent/agents/release-auditor.md` for why this one check deliberately doesn't trust the role's
own prose verdict.

## `.helios-baseline` carve-out (narrow, mechanically-verified — not a blanket exception)

`packages/fw-agent/.helios-baseline` is on the forbidden list above, but any legitimate change to
a self-integrity-checked file (`index.js`, `src/detector.js`, `src/behavior-tracker.js`,
`src/policy-watcher.js`, `src/quarantine.js`, `src/audit-log.js`, `src/policy.js`) mechanically
requires regenerating that baseline or the agent refuses to start at all — discovered running
P2-01 (the first real, non-throwaway directive to touch `index.js`).

`release-warden.js` excuses a `.helios-baseline` hit from `FREEZE` **only if** it independently
recomputes the exact same SHA-256 algorithm `index.js`'s own `computeSelfHash()` uses (same file
list/order, same `\r\n`→`\n` normalization) by reading every input via `git show <candidate_sha>:
<path>`, and the result matches the committed baseline exactly. This never trusts Agent 1's
regenerated file byte-for-byte — it is forced to be correct by the candidate's own committed code,
or the FREEZE stands with a more specific reason (a mismatch is treated as a *stronger* signal of
tampering than a bare forbidden-path hit, not a pass). Every other forbidden path is unaffected —
proven with `runs/exp001-freeze-baseline-tamper/` (a deliberately wrong baseline that still
FREEZEs) alongside the real P2-01 run (a correctly-regenerated baseline that PASSes).

## Documentation allowlist (Agent 4 only — any match NOT in this list is an automatic FREEZE)

```
CHANGELOG.md
README.md                          (root, or any packages/*/README.md)
docs/**
.agent/README.md
.agent/RUNBOOK.md
```

Unlike A1's list, this is an **allowlist**, not a blocklist: Agent 4's entire mandate is
documentation, so a `docs-receipt.changed_files` entry that matches neither this list nor the
forbidden-path list above is still out of scope — there is no third category. This is checked
only if `docs-receipt.json` exists in the run directory; its absence never affects `PASS`/`BLOCK`/
`FREEZE` for the A1/A2/A3 loop.

## Reliability Reviewer opt-in (Agent 2b, `.agent/agents/reliability-reviewer.md`)

`reliability-receipt.json` is optional per run: `release-warden.js` only requires it (missing =>
FREEZE) when the run's directive sets `"require_reliability_review": true`. Every directive that
predates this field is unaffected — its absence has always meant "not evaluated," never "passed by
default." If the receipt is present anyway, even without an opt-in directive, it is still validated
and can still BLOCK on a reported `FAIL` — a stricter run than required is honored, never ignored.

## BLOCK conditions (verification loop must continue, not a fatal stop)

| Condition | Detection |
|---|---|
| `red-team-verifier` (or `pentester`) reported `FAIL` | `verifier-receipt.status !== 'PASS'` |
| Any `engineer-receipt.tests_run[*].exit_code !== 0` | P0 regression signal |
| `verifier-receipt.regressions[*]` contains a non-OK entry | explicit regression report |
| `reliability-receipt.status !== 'PASS'` (only evaluated if the receipt exists) | reliability-reviewer reported a blocking finding |
| `quality-receipt.status !== 'PASS'` (only evaluated if the receipt exists) | quality-reviewer reported a blocking finding |
| `test-coverage-receipt.status !== 'PASS'` (only evaluated if the receipt exists) | test-engineer reported a blocking finding (most often a confirmed false-positive test) |
| `compatibility-receipt.status !== 'PASS'` (only evaluated if the receipt exists) | compatibility-reviewer reported a blocking finding |
| `release-audit-receipt.status !== 'PASS'` (only evaluated if the receipt exists) | release-auditor reported a blocking finding |

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
