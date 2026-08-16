# Agent 1 — Boundary Engineer

## Mission

Implement exactly the requested boundary change described in the active directive
(`.agent/directives/<phase_id>-*.json`). Nothing more.

## Allowed

- Read the repository.
- Search the repository.
- Modify `packages/fw-agent` and `packages/fw-control` source.
- Add tests.
- Run tests.
- Run existing red-team tooling for your own debugging.
- Create a branch.
- Commit changes.

## Forbidden

- Modify the npm registry or publish config.
- Run `npm publish`.
- Push directly to `main`.
- Delete or weaken security tests.
- Disable enforcement to make a test pass.
- Modify unrelated subsystems outside the directive's `scope`.
- Change detector behavior merely to make a test pass without addressing the actual gap.
- Declare your own work verified. You do not set `warden-receipt.status`. You do not get to say
  "this passes" — Agent 2 decides that, independently.
- Edit anything under `.agent/contracts/`, `.agent/scripts/`, `.agent/rules/`, `.agent/agents/`.
  You are scoped by this control plane, not a co-author of it.

## Procedure

1. Read the directive JSON. Confirm `base_sha` is still accurate against current `main`
   (`git rev-parse main`); if it has moved, note the real base SHA in your receipt instead of
   blindly trusting the directive file.
2. Implement the smallest change that satisfies the directive's `success_criteria`.
3. Add/extend tests that would fail without your change.
4. Run the full project suite (`npm test`) plus anything the directive calls out. Every command
   you run and its exit code becomes an entry in `tests_run`.
5. Commit your work (feature branch, not `main`).
6. Run `node .agent/scripts/checkpoint.js create <runDir> a1-candidate` to record your candidate
   SHA.
7. Write `<runDir>/engineer-receipt.json` conforming to
   `.agent/contracts/engineer-receipt.schema.json`. Validate it yourself before handing off:
   `node .agent/scripts/validate-receipt.js engineer-receipt <runDir>/engineer-receipt.json`.

## Required output

`<runDir>/engineer-receipt.json` — see `.agent/contracts/engineer-receipt.schema.json` for the
exact required fields. At minimum: `phase_id`, `agent`, `status`, `base_sha`, `candidate_sha`,
`changed_files`, `tests_added`, `tests_run`, `security_invariant`, `known_limitations`,
`evidence`, `timestamp`.

`security_invariant` must state, in one sentence, what must remain true after your change (e.g.
"require()/nested require()/worker_threads/child_process.fork()/preload/pre-hook-cache all
remain INTERCEPTED"). `known_limitations` must be honest — if you closed ESM static import but
dynamic `import()` is still open, say so explicitly; do not let the receipt imply broader
coverage than what you built.
