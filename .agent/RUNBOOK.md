# `.agent/` Runbook — How to Actually Run This

`README.md` explains what this is and why it exists. This document is the operational
manual: how to start a run, how each role actually gets played (human, subagent, or local
model), how to switch roles/prompts, how to read a `FREEZE`, and how the rework loop works —
grounded in the two real runs this graph has actually been through
(`P2-EXPERIMENT-001`, throwaway; `P2-01`, real, two iterations including a genuine `FREEZE`).

If you haven't read `README.md` and `rules/state-machine.md` yet, read those first — this
document assumes you know the state machine (`DIRECTIVE -> A1_WRITE -> CHECKPOINT -> A2_VERIFY ->
A3_GATE -> RELEASE_CANDIDATE`, with `A4_DOCS` optional afterward) and the four roles.

---

## 1. Before you start

**Requirements:** just Node.js and git. `validate-receipt.js` is a hand-rolled, zero-dependency
JSON Schema subset validator — nothing in `.agent/scripts/` needs `npm install`. `gh` (GitHub
CLI) is only needed if you're opening a PR at the end; not needed to run the graph itself.

**One thing that will surprise you if you don't know it going in:** if your directive touches
any of `packages/fw-agent/{index.js,src/detector.js,src/behavior-tracker.js,src/policy-watcher.js,
src/quarantine.js,src/audit-log.js,src/policy.js}`, you MUST run `npm run baseline` before your
candidate can even start (self-integrity check) — and that regenerated file
(`packages/fw-agent/.helios-baseline`) has to be in your `changed_files`, or `release-warden.js`
FREEZEs on missing evidence... no wait, it FREEZEs because `.helios-baseline` is a forbidden path
in general. Read §7 ("Reading a FREEZE") before you hit this for real; we hit it on `P2-01` and
it's the single most likely FREEZE you'll cause by accident.

---

## 2. Five-minute quick start (throwaway proof run)

This reproduces the shape of `P2-EXPERIMENT-001` — a trivial, non-functional candidate, useful
for sanity-checking the graph itself (e.g. after editing `release-warden.js`) without touching
real code.

```bash
# 1. Make a run directory
mkdir -p .agent/runs/my-test

# 2. Make some trivial, harmless change and commit it (any branch, not main)
git checkout -b test/graph-sanity-check
echo "// noop" >> packages/fw-agent/test/some-harmless-file.js   # anything non-forbidden
git add -A && git commit -m "test: graph sanity check"

# 3. Checkpoint the candidate
node .agent/scripts/checkpoint.js create .agent/runs/my-test a1-candidate

# 4. Collect evidence for whatever "test" you're claiming you ran
node .agent/scripts/collect-evidence.js .agent/runs/my-test TEST-PHASE a1-check -- "npm test"

# 5. Hand-write engineer-receipt.json (see contracts/engineer-receipt.schema.json for required
#    fields, or copy .agent/runs/exp001-pass/engineer-receipt.json as a template)

# 6. Checkpoint + evidence + hand-write verifier-receipt.json the same way (a2-verify-start,
#    your verification commands, a2-verify-end)

# 7. Run the gate
node .agent/scripts/release-warden.js .agent/runs/my-test TEST-PHASE
echo "exit=$?"   # 0=PASS 1=BLOCK 2=FREEZE
```

For a real run against real code, skip to §4 — this quick-start is for sanity-checking the
graph's own mechanics, not for doing real work.

---

## 3. Concepts, in one paragraph each

**Directive** (`directives/<PHASE_ID>-*.json`) — a human-authored JSON file scoping one piece of
work: `phase_id`, `title`, `objective`, `base_sha` (+ a note on when it was last verified against
`main`), `scope` (in-bounds), `out_of_scope` (explicitly not required, though incidental overlap
must be disclosed, not hidden — see `P2-01`'s dynamic-`import()` side effect), `success_criteria`.
Written before any agent runs. Nobody downstream may expand scope past what's written here
without it being a disclosed, human-visible deviation.

**Run directory** (`runs/<run-id>/`) — one per attempt at a directive. Accumulates
`engineer-receipt.json`, `verifier-receipt.json`, `warden-receipt.json`, optionally
`docs-receipt.json`, `checkpoints.json` (append-only), and `evidence/` (one JSON summary +
`.stdout.log`/`.stderr.log` per command, plus `index.json`). Real run directories are
**gitignored by default** (`.agent/runs/*` except `.gitkeep` and `exp001-*`) — they're a local
audit trail, not something every run commits. If a real run is worth preserving as a permanent
example (like `P2-01`'s), that's a deliberate human choice to `git add -f` it or rename it into
the `exp001-*`-style whitelist pattern, not automatic.

**Receipt** — a JSON file one role writes, validated against a schema in `contracts/`. Prose in a
receipt has zero authority by itself; only what `release-warden.js` computes from the receipts'
*structured fields* (`candidate_sha`, `changed_files`, `status`, `tests_run[].exit_code`, etc.)
matters.

**Checkpoint** (`checkpoint.js create <runDir> <label>`) — an append-only record of `{label,
timestamp, sha, branch, dirty, status}` from the current git state. This is how
`release-warden.js` proves a candidate's SHA didn't move mid-verification, and (for rework loops)
which checkpoint is the *latest* for a given label.

**Evidence** (`collect-evidence.js <runDir> <phaseId> <id> -- <command>`) — runs a command for
real, captures exit code + stdout/stderr, hashes them, writes `evidence/<id>.json` +
`.stdout.log`/`.stderr.log`, and appends `<id>` to `evidence/index.json`. A receipt that cites an
evidence ID not in that index is an automatic FREEZE — you cannot claim you ran something you
didn't actually capture.

**The trust boundary** — repeated because it's the whole point: **the model is not trusted, none
of A1/A2/A3's prose is trusted.** Only the JSON Schemas, the checkpoint log, the evidence hashes,
and `release-warden.js`'s own logic decide `PASS`/`BLOCK`/`FREEZE`. A human approves the actual
release at the end, always.

---

## 4. Starting a real run, step by step

### 4.1 Write (or verify) the directive

If one doesn't exist yet for your phase, copy `directives/P2-01-esm-static-import.json`'s shape.
Before A1 starts, **re-verify `base_sha`** against current `main`:

```bash
git rev-parse main
```

If it moved, don't silently trust the directive file — note the real base in the engineer
receipt's `base_sha_note` field (see `agents/boundary-engineer.md` step 1). This actually happened
on `P2-01`: the directive said `base_sha: 0793227` (main), but the candidate was built on top of
`agent/p2-orchestration-proof`'s tip instead, because the `.agent/` tooling itself only existed on
that branch. That's a legitimate, disclosed deviation, not a violation — see that run's
`engineer-receipt.json.base_sha_note` for exactly how it was worded.

### 4.2 Create the run directory and play A1 (Boundary Engineer)

```bash
mkdir -p .agent/runs/<run-id>
```

**How A1 actually gets "played"** — three options, all equally valid, none more or less
"trusted" than the others (trust comes from the mechanical checks below, not from who/what wrote
the receipt):

- **Human, or a coding agent (like the one that wrote this runbook) acting as itself.** Read
  `agents/boundary-engineer.md` verbatim, implement the directive's `success_criteria`, run tests
  for real, commit, then hand-write `engineer-receipt.json`. This is what happened for both
  `P2-EXPERIMENT-001` and `P2-01` in this repo so far.
- **A genuinely separate subagent** (e.g. Claude Code's `Agent` tool, `general-purpose` type).
  Give it a self-contained prompt: the directive, a pointer to `agents/boundary-engineer.md` to
  follow verbatim, the run directory path, and explicit instructions to checkpoint + write the
  receipt + validate it before reporting back. This is *more* valuable for A2 (independence
  matters more there — see §4.3) but works fine for A1 too if you want the loop to run without a
  human typing code directly.
- **A local model via `model-runner.js`.** `node .agent/scripts/model-runner.js <model> <prompt>`
  sends a prompt to a local Ollama instance and prints the raw text response. This script is
  *not* wired into anything automatically — you'd feed it `agents/boundary-engineer.md` plus the
  directive as the prompt, then take its output (a proposed diff, a proposed receipt) and route it
  through the exact same commit → checkpoint → schema-validate → gate pipeline as the other two
  options. If Ollama isn't reachable, this script exits 2 (`FREEZE: Ollama not reachable`) rather
  than silently degrading — treat that as a real FREEZE for any run depending on it, per the
  original design directive.

Whichever you pick, the actual mechanical steps are identical:

```bash
# after implementing + testing + committing on a feature branch:
node .agent/scripts/checkpoint.js create .agent/runs/<run-id> a1-candidate
node .agent/scripts/collect-evidence.js .agent/runs/<run-id> <PHASE_ID> a1-<name> -- "npm test"
# ...write .agent/runs/<run-id>/engineer-receipt.json by hand or via the model's output...
node .agent/scripts/validate-receipt.js engineer-receipt .agent/runs/<run-id>/engineer-receipt.json
```

**If your candidate touches a self-integrity-checked file** (see §1): run `npm run baseline`
*before* checkpointing, and include `packages/fw-agent/.helios-baseline` honestly in
`changed_files`. Do not omit it to dodge the forbidden-path check — the whole point of the receipt
is that it's checked, and `release-warden.js` will only excuse it if it can independently
recompute the same hash from your candidate's own committed code (see §7).

### 4.3 Play A2 (Red-Team Verifier) — independence matters here more than anywhere else

A2's entire value is that it does **not** trust A1. If the same session/context that played A1
also plays A2, you get a weaker signal — not worthless (schema validation and the gate still
apply), but weaker. **Prefer a genuinely separate subagent for A2** whenever you can — spawn a
fresh `Agent` call with no shared context, give it only: the candidate SHA, the run directory, a
pointer to `agents/red-team-verifier.md`, and explicit instructions to do a fresh `git worktree`
checkout rather than reusing whatever's in the main working tree. This is exactly what happened
for both `P2-01` iterations — two separate subagent calls, each blind to the other's (and A1's)
reasoning, both came back with **findings A1 hadn't reported** (a real pre-existing evasion on
iteration 1; a genuinely new cross-CJS/ESM correlation capability on iteration 2).

```bash
node .agent/scripts/checkpoint.js create .agent/runs/<run-id> a2-verify-start
# ... fresh worktree, real attacks, real regression suite, collect-evidence for everything ...
node .agent/scripts/checkpoint.js create .agent/runs/<run-id> a2-verify-end
# ...write verifier-receipt.json...
node .agent/scripts/validate-receipt.js verifier-receipt .agent/runs/<run-id>/verifier-receipt.json
```

If a fresh worktree is genuinely impractical, `agents/red-team-verifier.md` allows operating in
the existing tree *if and only if* you `checkpoint.js assert-sha` immediately before and after —
record `clean_checkout: false` honestly in the receipt if you take this path.

### 4.4 Run A3 (Release Warden) — never "played," always run

There is no judgment call here. Run the script, report exactly what it prints:

```bash
node .agent/scripts/release-warden.js .agent/runs/<run-id> <PHASE_ID>
echo "exit=$?"
```

- **exit 0, `PASS`** → this run is a release candidate. `sync_required` tells you (deterministically,
  from `changed_files` alone) whether a human release step needs to confirm downstream awareness.
  Still needs human approval before anything is tagged/published/merged.
- **exit 1, `BLOCK`** → not fatal. Loop back to A1_REWORK (§5).
- **exit 2, `FREEZE`** → stop. Read §7 before doing anything else.

### 4.5 Optionally play A4 (Docs Scribe) — only after a real `PASS`

Same "how it gets played" options as A1. Read `warden-receipt.json`, confirm `status === 'PASS'`,
draft the `CHANGELOG.md` `[Unreleased]` entry and any directly-affected docs pages from receipt
fields only (never invent a claim you can't trace to `engineer-receipt.security_invariant`,
`known_limitations`, or `warden-receipt.sync_required`/`sync_reason`), commit, write
`docs-receipt.json`, validate it, then **re-run `release-warden.js`** — it re-checks the docs
receipt against the documentation allowlist and will FREEZE if A4 touched anything outside
`CHANGELOG.md` / `README.md` / `docs/**` / `.agent/README.md`.

---

## 5. The rework loop, using the real `P2-01` example

`A1_REWORK` re-enters `A1_WRITE` **in the same run directory**. Two different reasons this
happens, both legitimate:

**Reason A — A2 or A3 says no.** Verifier `FAIL`, or `release-warden.js` returns `BLOCK` (P0
regression, verifier-reported regression). This is what `P2-EXPERIMENT-001`'s
`exp001-fail-rework` scenario proves.

**Reason B — new information, no FAIL involved.** This is what actually happened on `P2-01`:
iteration 1 got a verifier `PASS`. Then, *after* that, new information surfaced (`module.register()`
turned out to be a deprecated API) that made the engineer decide to rework anyway, unprompted by
any FAIL. The state machine supports this fine — it's just A1 choosing to go around the loop
again with a better candidate. What matters mechanically:

```bash
# Preserve the record before overwriting (both iterations stay auditable):
cp .agent/runs/<run-id>/engineer-receipt.json .agent/runs/<run-id>/iteration-1-engineer-receipt.json
cp .agent/runs/<run-id>/verifier-receipt.json .agent/runs/<run-id>/iteration-1-verifier-receipt.json
cp .agent/runs/<run-id>/warden-receipt.json   .agent/runs/<run-id>/iteration-1-warden-receipt.json

# New commit, new checkpoint label:
node .agent/scripts/checkpoint.js create .agent/runs/<run-id> a1-rework-candidate

# ...fresh A2 verification pass against the NEW candidate_sha (a genuinely separate subagent
# call again — don't reuse the first pass's context)...

# ...re-run A3...
```

`release-warden.js`'s SHA-consistency check already handles this correctly: it compares against
the **latest** checkpoint per label (`a1-candidate` or `a1-rework-candidate...`,
`a2-verify-start`, `a2-verify-end`), not the full history — so stale checkpoints from a superseded
iteration never get compared against the current receipts. This was itself a bug found and fixed
early in this graph's own development (see `git log --oneline -- .agent/scripts/release-warden.js`
for `3e91bd4`) — worth knowing about if you're editing that script yourself.

There is no enforced bound on how many rework iterations you take. `checkpoints.json` is the full
audit trail regardless.

---

## 6. How to switch out roles and prompts

Three genuinely different things people mean by "switch the prompts," with different answers:

### 6.1 Changing what a role is *told* to do (safe, expected, do this freely)

Edit `agents/boundary-engineer.md` / `agents/red-team-verifier.md` / `agents/release-warden.md` /
`agents/docs-scribe.md` directly. These are prose procedure documents — mission, allowed/forbidden
lists, required output shape. Changing them changes what a *conscientious* agent will attempt, but
remember: **prompts are guidance, not enforcement.** A misbehaving or careless agent that ignores
its own role file is still caught by the mechanical checks in `release-warden.js` (forbidden
paths, SHA consistency, evidence presence) — that's the entire design. If you want a behavior to
be *guaranteed*, it needs to be a check in `release-warden.js`/`validate-receipt.js`, not just a
sentence in a role file. (`.helios-baseline` is the cautionary example here: for a while,
`agents/boundary-engineer.md` didn't even mention it, and the *mechanical* forbidden-path list
still caught it correctly — the prose gap was a documentation quality issue, never a safety gap.)

### 6.2 Changing *who or what* plays a role (safe, per-run choice)

Nothing in the graph cares whether a receipt was typed by a human, produced by a subagent, or
drafted by a local model and transcribed by a human. Pick per role, per run, based on what you
actually have available and how much independence you want for A2 specifically (§4.3). Swapping
this needs zero code changes — it's purely about who runs the commands in §4.

### 6.3 Changing the *mechanical* policy itself (requires explicit human sign-off, every time)

This means editing `.agent/scripts/`, `.agent/contracts/`, or `.agent/rules/` — the actual trust
boundary. **No role is allowed to do this to itself** (every role file explicitly forbids editing
these directories, and `release-warden.js`'s own `FORBIDDEN_PATH_PATTERNS` mechanically blocks it
regardless of what any role file says). This has to be a deliberate, human-directed change made
*outside* the A1/A2/A3 loop — exactly like the `.helios-baseline` carve-out added to
`release-warden.js` after `P2-01` surfaced the need for it: a human picked the resolution
approach, the change was implemented, tested against both a positive case (a real candidate that
should now pass) and a negative case (a deliberately tampered baseline that must still freeze —
see `runs/exp001-freeze-baseline-tamper/`), and committed as its own reviewable change, separate
from any single directive's work.

### 6.4 Adapting this for a different repository entirely

`FORBIDDEN_PATH_PATTERNS`, `SYNC_TRIGGER_PATTERNS`, and `DOC_PATH_ALLOWLIST` in
`release-warden.js` are hardcoded to this repo's specific paths (`packages/fw-agent/...`,
`.helios-baseline`, `mrn-crs`, etc.) — this prototype was deliberately built repo-specific first,
generalized later if ever needed. Porting this graph to another repository means rewriting those
three constants (and the self-integrity file list in the `.helios-baseline` carve-out) for the
new repo's actual security-relevant paths — not a config flag, a real edit to
`release-warden.js`, which per §6.3 needs the same human-directed, tested-both-ways treatment.

---

## 7. Reading a `FREEZE`

`freeze_reason` in `warden-receipt.json` always names the specific mechanical check that fired.
Cross-reference against `rules/security-gates.md`'s authoritative table. The ones you're most
likely to actually hit, in rough order of how often they'll surprise a first-time user:

| `freeze_reason` contains... | What actually happened | What to do |
|---|---|---|
| `forbidden file(s) modified: ...helios-baseline...` **and** `baseline recomputation: ... does NOT match` | Either you forgot to run `npm run baseline` after touching a self-checked file, or something is genuinely wrong (a stale/hand-edited baseline). | Run `npm run baseline` for real, re-checkpoint, re-verify, re-gate. If the mismatch persists after a genuine regeneration, stop and investigate by hand — do not force it through. |
| `forbidden file(s) modified: .agent/scripts/...` (or `contracts`/`rules`/`agents`) | A1 (or its receipt) claims to have touched the control plane itself. | This should never happen from a real A1 run if the role file was followed — investigate why it happened before doing anything else; do not just remove the file from `changed_files` to make the freeze go away. |
| `candidate SHA mismatch across artifacts` | Engineer receipt, verifier receipt, and/or checkpoints disagree on the candidate's git SHA. | Almost always a copy-paste error writing the receipts by hand, or a stale/reused run directory from a previous attempt. Check every SHA field against `git log` directly. |
| `candidate SHA changed during verification` | The `a2-verify-start` and `a2-verify-end` checkpoints recorded different SHAs — exactly the "code changed mid-verification" attack this check exists to catch. | If this is legitimate rework, you needed a NEW run through A1_REWORK (§5), not a continuation of the same verification window. If it's not legitimate, treat it as a real finding. |
| `base_sha equals candidate_sha` or `base_sha (...) is not a git ancestor of candidate_sha` | Your engineer receipt's `base_sha` is wrong, unreachable, or a degenerate self-reference. | Fix `base_sha` to the real starting commit (`git merge-base <candidate> main` is usually what you want) and re-checkpoint. Never "fix" this by making `base_sha` and `candidate_sha` further apart than reality just to dodge the check. |
| `engineer receipt's base_sha (...) differs from directive's base_sha (...) with no base_sha_note` | Your candidate is legitimately built on a different starting point than the directive names (e.g. tooling on your branch requires it — see §4.1), but you didn't disclose why. | Add a `base_sha_note` field explaining the real reason. Don't just copy the directive's `base_sha` to make this pass if it isn't actually true — that reopens the exact self-reporting gap this check exists to close. |
| `engineer receipt changed_files mismatch with git-derived list — receipt omits: ...` / `receipt reports extra: ...` | Your receipt's `changed_files` doesn't exactly match `git diff candidate_sha^..candidate_sha` (your candidate commit's own diff against its immediate parent — **not** the directive's `base_sha`, see §4.1's diff-scope note). Easy to trip on a shared branch: listing files from an *earlier*, separately-committed piece of work is the single most common cause. | Report only what your own commit actually changed. If your candidate legitimately spans more than one commit, squash it into one before checkpointing — multi-commit candidates aren't correctly captured by this check. |
| `could not derive changed files from git (candidate^..candidate)` | `candidate_sha` doesn't exist in this repo, or has no parent (e.g. it's a repo's very first commit). | Check the SHA is real and reachable (`git cat-file -e <sha>`) from wherever you're running the gate. |
| `cited evidence missing from evidence/index.json` | A receipt names an evidence ID that `collect-evidence.js` never actually wrote. | You either forgot to run `collect-evidence.js` for a claimed command, or typo'd the ID in the receipt. Check `evidence/index.json` directly. |
| `docs-scribe touched non-documentation path(s): ...` | A4's `docs-receipt.changed_files` includes something outside `CHANGELOG.md`/`README.md`/`docs/**`/`.agent/README.md`. | A4 (or whoever drafted its receipt) tried to touch real code or the control plane under cover of a "docs" change. Investigate before anything else — same severity as A1 touching a forbidden path. |
| `receipt(s) failed schema validation` | Missing/malformed required field. | Run `node .agent/scripts/validate-receipt.js <type> <path>` directly — it lists every specific error. |

**None of these are recoverable by editing `release-warden.js` to make your specific case pass.**
If the freeze reveals the *policy itself* needs to change (like `.helios-baseline` did), that's
§6.3 — a separate, human-directed, tested-both-ways change, not something to bolt on mid-run to
unblock yourself.

---

## 8. Command cheat sheet

```bash
# Checkpoint current git state under a label
node .agent/scripts/checkpoint.js create <runDir> <label>

# Assert the current git state matches a previously-recorded SHA (used when a fresh worktree
# isn't practical for A2 — see §4.3)
node .agent/scripts/checkpoint.js assert-sha <runDir> <expectedSha>

# Run a command for real, capture+hash its output, register it as evidence
node .agent/scripts/collect-evidence.js <runDir> <phaseId> <evidenceId> -- <command...>

# Validate one receipt against its schema
node .agent/scripts/validate-receipt.js engineer-receipt|verifier-receipt|warden-receipt|docs-receipt <path>

# Run the deterministic gate (the only thing that decides PASS/BLOCK/FREEZE)
node .agent/scripts/release-warden.js <runDir> <phaseId>
# exit 0=PASS 1=BLOCK 2=FREEZE

# Optional: drive a role's receipt authoring from a local Ollama model
node .agent/scripts/model-runner.js <model> <prompt...>
```

---

## 9. Worked example: `P2-01`, condensed

Full detail lives in `.agent/runs/p2-01/` (gitignored — local only) and this repo's git history.
Shape, for reference when running your own real directive:

1. Directive prepared in advance (`directives/P2-01-esm-static-import.json`), gated on
   `P2-EXPERIMENT-001` having already proven `PASS`/`FAIL→REWORK`/`FREEZE` on a throwaway task.
2. `base_sha` re-verified against `main` immediately before starting; found to have moved
   conceptually (the `.agent/` tooling itself wasn't on `main` yet) — disclosed as a
   `base_sha_note`, not silently ignored.
3. A1 implemented, tested, committed, checkpointed, wrote a receipt disclosing (not hiding) that
   the self-integrity baseline would trigger a forbidden-path check.
4. A2 (separate subagent, fresh worktree) tried nine distinct evasion angles beyond A1's own
   tests, found one real (pre-existing, not new) bypass, returned `PASS`.
5. A3 froze — correctly — on the disclosed baseline interaction.
6. A human picked a resolution (§6.3): a mechanically-verified carve-out, not a manual-only
   process and not a blanket removal of the check. Implemented, proven both directions, committed
   separately from the security fix itself.
7. A3 re-run: `PASS`.
8. New information surfaced (`module.register()` deprecated) — A1_REWORK, unprompted by any FAIL
   (§5). New candidate, iteration-1 receipts preserved, new checkpoint label.
9. A second, separate A2 subagent verified the reworked candidate independently — found a
   genuinely new capability (cross-CJS/ESM correlation) neither prior receipt had claimed.
10. A3 re-run against the final candidate: `PASS`, `sync_required: true`.
11. A4 played for real for the first time: read the final `warden-receipt.json`, drafted the
    `CHANGELOG.md` entry and updated `README.md`/`docs/THREAT-COVERAGE.md` from receipt fields,
    wrote `docs-receipt.json`, re-ran A3 — still `PASS`, `docs.present: true`.
12. Human review/merge from there — this graph never merges or publishes anything itself.
