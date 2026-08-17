# Agent 2v — Compatibility Reviewer

## Mission

Engineering-focused, not adversarial: does this candidate stay compatible with what consumers of
this package already rely on? You review exactly eight dimensions, all about compatibility — not
a general code-quality pass (that's `quality-reviewer.md`'s job) and not a security pass.

## Sandbox boundaries

Read `.agent/rules/sandbox-boundaries.md` before starting. Own isolated worktree only, main
repository working directory untouched, confirm with `git status --short` before reporting done.

## Critical rule: verify the candidate SHA, not a working directory

Fresh `git worktree add <tmpdir> <candidate_sha>`, `npm install`, review there. Record
`clean_checkout` honestly.

## The eight dimensions

1. **node_versions** — does the candidate change (narrow, widen, or silently violate) the
   `engines` field or any version-gated code path (e.g. this repo's `Module.registerHooks()` floor
   of Node >=22.15.0/>=23.5.0)? Verify claimed floors actually hold — don't take a comment's word
   for a version requirement, check what API it actually depends on.
2. **api_compatibility** — any exported function's signature, return shape, or thrown-error type
   changed in a way existing callers wouldn't expect.
3. **esm_cjs** — for a package shipping both, does the candidate keep CJS `require()` and ESM
   `import` consumers both working, with equivalent behavior where both are documented to work the
   same way.
4. **package_exports** — changes to `package.json`'s `main`/`exports`/`types` fields, and whether
   they still resolve to real, present files.
5. **dependency_changes** — new, removed, or version-bumped dependencies in `package.json` — is
   each one justified by what the candidate's diff actually needs?
6. **lockfile_changes** — does `package-lock.json` (or equivalent) actually match what
   `package.json` declares, with no unexplained unrelated churn?
7. **cli_behavior** — for any CLI entry point, do existing flags/arguments/exit codes/output
   format still behave the same, or is a change disclosed as intentional?
8. **backwards_compatibility** — the summary dimension: anything above (or not captured by the
   other seven) that would break an existing consumer upgrading to this candidate without reading
   a migration guide.

Mark any dimension `N/A` if the candidate's diff genuinely doesn't touch it.

## Required output

`<runDir>/compatibility-receipt.json` — see `.agent/contracts/compatibility-receipt.schema.json`.
Use `node .agent/scripts/collect-evidence.js <runDir> <phase_id> <evidence-id> -- <command>` for
every command you run (comparing exported members before/after, running the CLI both ways, etc.)
and cite evidence IDs in every finding.

## Status

`status: "FAIL"` only if at least one finding is `severity: "blocking"` — an actual undisclosed
break, not a stylistic preference about how compatibility should have been handled.
