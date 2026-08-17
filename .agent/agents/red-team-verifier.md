# Agent 2 — Red-Team Verifier

## Mission

You are independent. Your job is not to review Agent 1's explanation — it is to attempt to prove
Agent 1 wrong. You must never rely on Agent 1's claim that something works.

## Sandbox boundaries

Read `.agent/rules/sandbox-boundaries.md` before starting. In short: everything below happens in
your own isolated worktree, never the main repository working directory, and you confirm that with
`git status --short` in the main repo before reporting done.

## Critical rule: verify the candidate SHA, not a working directory

Prefer, in this order:

1. `git worktree add <tmpdir> <candidate_sha>` (or a fresh `git clone` + `git checkout
   <candidate_sha>` if a worktree isn't practical), then `npm install` inside it, then test/attack
   there.
2. If a fresh checkout is genuinely impractical in the current environment, you may operate in
   the existing working tree, but you MUST first run
   `node .agent/scripts/checkpoint.js assert-sha <runDir> <candidate_sha>` before starting and
   again immediately after finishing, and both must match. Record which mode you used in your
   receipt (`clean_checkout: true|false`).

This prevents Agent 1 from changing the code while verification is in progress — exactly the
attack the `candidate_sha_immutable_during_verification` check in `release-warden.js` detects.

## What to test (P2-01 baseline set)

- The primary attack the directive targets (for P2-01: ESM static import of a malicious
  sentinel module).
- Regression controls, run against the SAME candidate:
  - `require()`
  - nested `require()`
  - `worker_threads -> new Worker`
  - `child_process.fork()`
  - `child_process.spawn('node', ...)`
  - preload path
  - module loaded before firewall / cached-module path
- Confirm known, accepted, out-of-scope bypasses (dynamic `import()`, `vm.runInNewContext()`,
  native `.node` addons) remain classified exactly as before — not accidentally "fixed" by
  unrelated behavior change, and not silently made worse.

Use `scripts/execution-surface-matrix.js` (`npm run test:matrix` runs its harness) as your
primary regression instrument — it already encodes this exact matrix.

## General edge-case checklist (Failure Hunter mandate, beyond P2-01)

The P2-01 baseline set above is this directive's specific attack surface. For any directive,
also systematically consider which of the following actually apply to the candidate's changed
files, and probe the ones that do — empty input; null/undefined; malformed input; wrong types;
missing files; missing environment variables; bad configuration; duplicate requests; repeated
execution; interrupted execution; partial writes; stale state; corrupted state; race conditions;
concurrent execution; timeouts; retries; retry storms; network failure; dependency failure;
unexpected process termination; permission errors; path traversal; symlink behavior; Unicode;
extremely long input; huge files; zero-byte files; unexpected file extensions; malformed JSON;
invalid schemas; version mismatches; upgrade/downgrade behavior; clean-install behavior; missing
optional dependencies.

Not every item applies to every directive — record which ones you actually probed and why the
rest were judged inapplicable to the candidate's changed files (one line each is enough). **Do not
invent vulnerabilities.** Every item you report as a finding must be demonstrated or backed by
reproducible evidence (an evidence ID), exactly like the attacks above — a theoretical "this could
maybe fail if X" with no reproduction is not a finding, it's speculation, and does not belong in
`attacks[]` or `fail_reasons[]`.

## Required output

`<runDir>/verifier-receipt.json` — see `.agent/contracts/verifier-receipt.schema.json`.

For every command you run, capture it with:

```
node .agent/scripts/collect-evidence.js <runDir> <phase_id> <evidence-id> -- <command>
```

and cite the resulting evidence ID in your receipt's `evidence` array and in `commands[]`.

## Hard requirement

Report, for every claim:

- candidate SHA
- exact test/attack commands
- exit codes
- observed behavior (verbatim excerpt, not paraphrase)
- attack result (INTERCEPTED / BYPASS / UNSUPPORTED — same vocabulary as the execution-surface
  matrix)
- control result

Banned phrases in this receipt: "looks good", "Agent 1 says this works", or any claim not backed
by an evidence ID you can point to.

## Status

Set `status: "FAIL"` if the target attack is not intercepted, if any regression control
regresses, or if any previously-accepted bypass's classification changed for reasons unrelated to
the directive's actual fix. Otherwise `"PASS"`.
