# PR #58 — Post-review Hardening Notes

Scope: fix/p2-01-esm-static-import

## A — High: non-spoofable changed_files
- Changed: .agent/scripts/release-warden.js
  - Derive authoritative changed files from `git diff --name-only base_sha..candidate_sha`.
  - Prefer checkpointed candidate SHA (latest a2-verify-end → a2-verify-start → a1-candidate) over receipts.
  - Normalize paths; record `checks.changed_files_git_derived` in warden receipt.
  - FREEZE if derivation fails, or if `engineer.changed_files` mismatches (omits/extras) vs git-derived list.
  - Use git-derived list for forbidden-path and sync gate decisions.
  - Preserve .helios-baseline carve-out exactly; verify via `git show <candidateSha>` recompute.
- Changed: .agent/agents/release-warden.md (docs)
  - Document git-derived list as authoritative; self-reported list is an honesty check only.

Acceptance checks:
- Under-reported receipts now FREEZE (by design).
- Honest receipts remain PASS (no gate weakening introduced).
- Baseline tamper still FREEZEs (carve-out intact).

## B — Copilot review nits
- B1 (.agent/scripts/collect-evidence.js): portable shell spawn (`spawnSync(cmd, { shell: true, ... })`).
- B2 (scripts/execution-surface-matrix-esm-entry.mjs): header references agent ESM load hook via Module.registerHooks().
- B3 (packages/fw-agent/test/esm-loader-test.js): renamed check to reflect availability branch; guard present.
- B4 (.agent/scripts/validate-receipt.js): remove "additionalProperties" from supported-feature header text.
- B5 (.agent/rules/state-machine.md): prefix script paths with `.agent/`.
- B6 (.agent/rules/security-gates.md): reference `.agent/scripts/release-warden.js`.

## C — CI / Node honesty for registerHooks() floor
- Tests/workflow expect ESM interception only when `require('module').registerHooks` is available
  (Node >=22.15 / >=23.5). Older Node versions log UNSUPPORTED/BYPASS honestly; engines.node unchanged (>=18).
- scripts/__tests__/execution-surface-matrix.test.js: resolved merge conflict; keeps floor-aware assertions.

No new runtime dependencies. No changes to detector logic, policyMap, or baseline algorithm beyond the warden trust-boundary fix above.
