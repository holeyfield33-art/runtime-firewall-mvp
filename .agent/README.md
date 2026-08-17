# `.agent/` — Aletheia Firewall Phase 2 Orchestration Prototype

**Status:** prototype, proven on `P2-EXPERIMENT-001` and on `P2-01` (the first real,
non-throwaway directive run through this graph — see the `P2-01` section below).

**Operating this graph:** see [`RUNBOOK.md`](RUNBOOK.md) — how to start a run, how each role
actually gets played (human / subagent / local model), how to switch out roles and prompts, how
the rework loop works, and how to read a `FREEZE`. This document (`README.md`) is the what/why;
`RUNBOOK.md` is the how.

**Scope of this directory:** a local three-agent development-loop contract for the
`runtime-firewall-mvp` repository (package name on npm: `aletheia-firewall`). This is an
orchestration contract/prototype, **not** a general-purpose autonomous agent platform, and it
does not modify, wrap, or depend on MRN-CRS in any way — MRN-CRS does not exist in this
repository.

## Why this exists

Before trusting an agent loop to modify actual firewall enforcement code (starting with `P2-01`,
the ESM static-import interception gap), the loop itself has to be proven safe: no agent may
promote its own work, no model output may override a deterministic security gate, and no
registry modification may occur before independent verification passes. `P2-EXPERIMENT-001`
exists to prove exactly that, on a throwaway task, before any real security surface is touched.

## Architecture

```
HUMAN DIRECTIVE (.agent/directives/*.json)
      |
      v
A1 -- Boundary Engineer        (.agent/agents/boundary-engineer.md)
      |
      v
CHECKPOINT                     (.agent/scripts/checkpoint.js)
      |
      v
A2 -- Red-Team Verifier        (.agent/agents/red-team-verifier.md)
      |
  +---+---+
 FAIL     PASS
  |         |
A1 REWORK  A3 -- Release Warden   (.agent/agents/release-warden.md, .agent/scripts/release-warden.js)
              |
              v
        RELEASE CANDIDATE
              |
              +-------------------------+
              |                         |
              v                         v
        HUMAN APPROVAL            A4 -- Docs Scribe   (.agent/agents/docs-scribe.md)
  <-- always a person,                  |
      never automated                   v
      by this directory            CHANGELOG.md / docs/*.md draft
                                    (re-validated by release-warden.js;
                                     out-of-scope path => FREEZE)
```

A4 is additive, not gating: it can only run after A3 already returned `PASS`, it never blocks
`HUMAN APPROVAL`, and its absence changes nothing. If it does run, `release-warden.js`
re-validates its receipt on the next invocation and mechanically confines it to documentation
paths — same trust discipline as A1, just a different allowlist.

Full state machine detail: `rules/state-machine.md`. Deterministic gate conditions:
`rules/security-gates.md`. Sync-required determination: `rules/sync-gate-rule.md`.

## Directory layout

```
.agent/
├── README.md                       this file
├── directives/                     one JSON file per scoped task (human-authored)
├── agents/                         role definitions (prompts/procedures) for A1/A2/A3
├── contracts/                      JSON Schemas every receipt must validate against
├── rules/                          state machine, security gates, sync-gate rule (prose)
├── scripts/                        the actual enforcement code (checkpoint, evidence, gate,
│                                    schema validation, optional Ollama client)
└── runs/                           per-attempt working directories (gitignored except .gitkeep)
```

## The trust boundary (the most important part)

**The model is not trusted. Neither is Agent 1, Agent 2, or Agent 3, as LLM-driven roles.** The
trusted layer is exclusively:

- the JSON Schema contracts in `contracts/`,
- the git state captured by `checkpoint.js` (candidate SHA provenance),
- the raw command output hashed and stored by `collect-evidence.js`,
- the deterministic logic in `release-warden.js`,
- and, at the very end, a human approving the release.

Any of A1/A2/A3's prose ("this works", "looks good", "verified") has zero authority. Only the
scripts in `scripts/` decide `PASS` / `BLOCK` / `FREEZE`.

## Agent roles

| Agent | File | Allowed | Forbidden (highlights) |
|---|---|---|---|
| A1 Boundary Engineer | `agents/boundary-engineer.md` | read/search repo, modify `packages/fw-agent` \& `packages/fw-control` src, add/run tests, branch, commit | registry/publish, push to `main`, delete/weaken tests, edit `.agent/` control plane itself, declare own work verified |
| A2 Red-Team Verifier | `agents/red-team-verifier.md` | fresh checkout of candidate SHA, run tests + attacks, run matrix | trusting A1's claims, verifying anything other than the exact candidate SHA |
| A3 Release Warden | `agents/release-warden.md` | run `release-warden.js`, report its output verbatim | overriding the script's verdict, deciding `sync_required` by "judgment" |
| A4 Docs Scribe | `agents/docs-scribe.md` | run only after A3 `PASS`; append to `CHANGELOG.md`'s `[Unreleased]` section, update directly-affected `docs/*.md` \& package `README.md`s, branch, commit | running before A3 `PASS`, touching anything outside the doc allowlist, editing `.agent/` control plane, bumping version/date, claiming anything not traceable to a receipt field |

## Receipts

Every run directory (`runs/<run-id>/`) accumulates:

- `engineer-receipt.json` — validates against `contracts/engineer-receipt.schema.json`
- `verifier-receipt.json` — validates against `contracts/verifier-receipt.schema.json`
- `warden-receipt.json` — written only by `scripts/release-warden.js`, validates against
  `contracts/warden-receipt.schema.json`
- `docs-receipt.json` — optional, written by Agent 4 only after `warden-receipt.status ===
  'PASS'` exists; validates against `contracts/docs-receipt.schema.json`. Re-checked by
  `release-warden.js` on its next run: any `changed_files` entry outside the documentation
  allowlist is a `FREEZE`.
- `checkpoints.json` — append-only git-state log (`scripts/checkpoint.js`)
- `evidence/` — one `{id}.json` (schema: `contracts/evidence-bundle.schema.json`) plus
  `{id}.stdout.log` / `{id}.stderr.log` per command run, and an `index.json` list of IDs

Validate any receipt manually:

```
node .agent/scripts/validate-receipt.js engineer-receipt   .agent/runs/<run-id>/engineer-receipt.json
node .agent/scripts/validate-receipt.js verifier-receipt   .agent/runs/<run-id>/verifier-receipt.json
node .agent/scripts/validate-receipt.js warden-receipt     .agent/runs/<run-id>/warden-receipt.json
```

Run the gate:

```
node .agent/scripts/release-warden.js .agent/runs/<run-id> <phase_id>
```

Exit codes: `0` = PASS, `1` = BLOCK, `2` = FREEZE.

## Freeze conditions

See `rules/security-gates.md` for the authoritative, mechanically-checked list. Summary:
missing/invalid receipts, candidate SHA mismatch or mutation during verification, forbidden path
touched, or cited evidence missing from the run's evidence index. `BLOCK` (verifier FAIL, P0
regression, or reported regressions) is not fatal — it routes back to `A1_REWORK`. `FREEZE` is:
stop, human required.

## `P2-EXPERIMENT-001`

Purpose: prove the graph mechanics on a trivial, non-functional throwaway task before pointing
it at any real firewall code. Directive: `directives/P2-EXPERIMENT-001.json`.

Three behaviors were demonstrated in this workspace's proof run — see `runs/exp001-pass/`,
`runs/exp001-fail-rework/`, `runs/exp001-freeze-forbidden-path/`, and
`runs/exp001-freeze-sha-mismatch/` for the exact receipts, checkpoints, and evidence:

1. **A1 -> A2 -> A3, PASS.** A trivial passing candidate produced an engineer receipt, a verifier
   receipt with `status: PASS`, and `release-warden.js` exited `0` with `status: PASS`.
2. **A2 FAIL -> A1 REWORK -> A2.** A candidate the verifier legitimately could not confirm
   produced `verifier-receipt.status: FAIL`; `release-warden.js` exited `1` with `status: BLOCK`,
   confirming the loop returns to rework rather than being treated as fatal.
3. **Fatal gate -> FREEZE.** A run whose engineer receipt declared a forbidden path as changed
   (and, separately, a run with a candidate-SHA mismatch between engineer and verifier receipts)
   caused `release-warden.js` to exit `2` with `status: FREEZE`, and no `RELEASE_CANDIDATE` state
   was reached.

Because this container has no local Ollama daemon available (`ollama` is not installed here —
verified with `which ollama` / a direct request to `localhost:11434`), the A1/A2/A3 roles for
this proof run were played manually by the coding agent following `agents/*.md` verbatim, and all
receipts were still pushed through the same schema validation and the same
`release-warden.js` used for real work. `scripts/model-runner.js` is the integration point for
driving a role's receipt authoring from a local Ollama model instead; it is unused by the gate
logic itself (the gate never calls it), so swapping in a real model changes nothing about what is
trusted.

## `P2-01`

Run for real (first non-throwaway directive through this graph) on branch
`fix/p2-01-esm-static-import`, run directory `runs/p2-01/` (gitignored like all real runs — a
local audit trail, not checked-in proof evidence the way `runs/exp001-*` is). Went through two
iterations, both recorded in the run directory (`iteration-1-*.json` preserved before iteration 2
overwrote the active receipts):

- **Iteration 1** (candidate `b102109`): A1 implemented a `module.register()` ESM load hook in a
  separate file (`esm-loader.mjs`) with its own isolated `Detector`. A2 (independent agent, fresh
  `git worktree`, never shown A1's reasoning) tried nine evasion angles, found one real bypass
  (split-string signature smuggling), proved it pre-exists on the original CJS path too — not a
  new gap — and returned `PASS`. A3 then FROZE on a real, previously unexercised finding: fixing
  `index.js` requires regenerating `packages/fw-agent/.helios-baseline`, unconditionally forbidden
  at the time. Resolved with a narrow, mechanically-verified carve-out (see
  `rules/security-gates.md`), proven both positively (this run, now `PASS`) and negatively
  (`runs/exp001-freeze-baseline-tamper/`, a deliberately wrong baseline that still FREEZEs).
- **Iteration 2** (candidate `94388bd`, the FINAL state): A1_REWORK, not triggered by a verifier
  FAIL — triggered by discovering `module.register()` is Stability-0-Deprecated in current Node
  docs. Replaced with `module.registerHooks()` (Stability 1.2, Node ≥22.15.0/≥23.5.0), whose `load`
  hook runs synchronously on the MAIN thread — `esm-loader.mjs` deleted; the hook is now inline in
  `index.js`, directly reusing the same `detector`/`policyMap`/`verifiedCompilationsCache` the CJS
  path uses. A2 (a second independent agent, fresh worktree again) verified this wasn't just a
  deprecation dodge: generated a real signed policy and confirmed ESM modules now get genuine
  BLOCK/QUARANTINE policy overrides (impossible in iteration 1), confirmed same-main-thread
  execution independently (not trusting the engineer receipt's claim), and — beyond either
  receipt's claims — found that behavioral correlation now fires **across the CJS/ESM boundary**
  for a split attack (credential read in one file, egress in the other, different module systems,
  same package), with a clean control proving it's genuine correlation. Verdict `PASS`. A3:
  `PASS`, `sync_required: true` (touches `packages/fw-agent/index.js`) — awaiting human
  review/merge, not yet integrated into `main`.

Boundary matrix after P2-01: ESM static import and dynamic `import()` both report `INTERCEPTED`
(dynamic import() closing is an inherent, documented side effect of the same load hook — Node
does not distinguish the two syntaxes at that hook — disclosed as out of the directive's formal
scope, not hidden); `require()`, nested `require()`, `worker_threads`, `child_process.fork()`,
`child_process.spawn('node', ...)`, and the pre-hook/cache path all report `INTERCEPTED`;
`vm.runInNewContext()` remains `BYPASS` and native `.node` addon load remains `UNSUPPORTED` — both
explicitly out of P2-01 scope, confirmed architecturally unchanged across both iterations.

Version floor note: `module.registerHooks()` requires Node ≥22.15.0/≥23.5.0, narrower than
`fw-agent`'s declared `>=18.0.0` package floor (which covers its CJS functionality). Below that
floor, ESM protection stays an honest, logged `UNSUPPORTED` bypass — never silently claimed as
protected.

## Readiness for MRN integration

This prototype is a **contract**, deliberately dependency-free (no `ajv`, no framework) so it can
be read and re-implemented by MRN's own orchestrator later without dragging along this
repository's specific tooling choices. When MRN becomes the orchestrator, the model-provider
abstraction belongs in MRN (`MRN -> ModelProvider -> OllamaProvider -> Ollama`), not here — this
directory keeps exactly one concrete Ollama client (`scripts/model-runner.js`) and no provider
interface, per the directive's explicit instruction not to add model-provider abstraction to MRN
at this stage.
