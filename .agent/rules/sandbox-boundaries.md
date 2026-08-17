# Sandbox boundaries — every independent role in this graph

Written after a real incident: during Team Configuration 1's first live run, a reviewer subagent
followed its role file's "revert the fix locally, confirm the test fails" instruction *in the
shared main repository working directory* instead of its own isolated worktree, and left
`packages/fw-agent/index.js` — real enforcement code — reverted by 461 lines when it finished.
Nothing was committed, so nothing shipped broken, but it was only caught by a manual `git status`
sweep after the fact, not by any rule the agent itself was following. This file is that rule,
written down once so every role references it instead of relying on prompt-by-prompt reminders.

Applies to every independent REVIEWER role — anyone whose job is to examine or attack an
already-existing candidate without being authorized to change it: Red-Team Verifier/Failure Hunter
(A2), Reliability Reviewer (A2b), Threat Modeler (A1b), Pentester (A2p), Code Quality Reviewer
(A2c), Test Engineer (A2t), Compatibility Reviewer (A2v), Release Auditor (A2r), and any reviewer
role added later.

**Boundary Engineer / Security Target Builder (A1) is the one exception**, and only for its
normal, in-scope implementation work: A1's job is literally to create the candidate — implement,
test, and commit in the real repository — so it does operate in the main tree by design, same as
any engineer working on a branch. A1 is still bound by its own role file's forbidden-path list and
by rule 4 below (confirm before finishing that only its own intended, in-scope changes are
present) — it just doesn't need a throwaway worktree to do its actual job. If A1 ever needs to run
something exploratory that ISN'T part of building the real candidate (a one-off check that doesn't
belong in the final commit), that exploratory step follows the same worktree rule everyone else
does.

## The rule

1. **Any command that executes, tests, or mutates candidate code runs inside your own isolated
   `git worktree`** (`git worktree add <tmp-dir> <candidate_sha>`), never in the main repository
   working directory. This includes `npm install`, `npm test`, reverting a fix to prove a test
   fails, writing scratch/probe files, or anything else beyond reading a file to understand it.
2. **Never run a git mutation command against the main repository working directory** —
   `checkout -- <path>`, `reset`, `clean`, `restore`, `stash pop/apply`, `apply`, `am`, or
   anything else that changes tracked-file content or the index there. Every one of those is fine,
   and often necessary, *inside your own worktree*. The distinction is the directory, not the
   command.
3. **Only write inside your own worktree, or inside `.agent/runs/<run-id>/` in the main repo**
   (your receipt file and your evidence, via `collect-evidence.js`). Never write, move, or delete
   any other file in the main repository working directory.
4. **Before reporting yourself done, run `git status --short` in the main repository working
   directory** (not your worktree) and confirm it matches what it was when you started — for most
   roles, that means it should show none of your own changes at all. If it shows anything you
   didn't expect, that is not something to silently fix or silently ignore: say so explicitly in
   your final report, with the exact `git status` output, and let the orchestrator decide. Do not
   guess whether an unexpected change is safe to revert.
5. **Clean up your own worktree when you're done** (`git worktree remove <path>`), but never
   remove a worktree you didn't create — another role or the orchestrator may still be using it.

## Why the main tree, specifically, is off-limits

The main repository working directory is shared state — every role in a run, and the orchestrator
itself, reads it concurrently or in sequence. A worktree is cheap (git shares the object database;
only the checked-out files and `npm install`'s `node_modules` cost real disk) and gives every role
a private, disposable copy of the exact candidate SHA with zero risk of one role's cleanup, revert,
or scratch file colliding with another's. There is no task in this graph that requires mutating the
shared tree — if a role ever seems to need to, that is a sign the task was scoped wrong, not a
reason to make an exception.
