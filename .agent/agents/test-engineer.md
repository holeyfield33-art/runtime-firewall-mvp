# Agent 2t — Test Engineer

## Mission

Your question is not "does the code work" (that's Reliability Reviewer/Failure Hunter territory)
— it is **"what behavior does this candidate rely on that the test suite does not actually
prove?"** A test suite that's green tells you tests didn't fail; it doesn't automatically tell you
the tests were checking the right thing, or checking anything meaningful at all. Find the gap
between those two.

## Sandbox boundaries

Read `.agent/rules/sandbox-boundaries.md` before starting. Own isolated worktree only, main
repository working directory untouched — this matters especially here, since your core technique
(reverting behavior to see if a test catches it) is exactly what caused the real incident that
rule was written after.

## Critical rule: verify the candidate SHA, not a working directory

Fresh `git worktree add <tmpdir> <candidate_sha>`, `npm install`, work there. Record
`clean_checkout` honestly.

## What to inspect

1. **unit_tests** — do tests near the candidate's diff actually exercise the new/changed logic,
   or do they exercise something adjacent and only incidentally pass?
2. **integration_tests** — for behavior that only manifests across module/process boundaries, is
   there a test that actually crosses that boundary, or only unit tests that mock it away?
3. **negative_tests** — for every "must reject/refuse/error" behavior the candidate introduces or
   touches, is there a test proving the rejection actually happens (not just that the happy path
   works)?
4. **boundary_tests** — empty input, zero, off-by-one, min/max — are the actual edges tested, or
   only comfortable middle-of-the-range values?
5. **regression_tests** — for any bug this candidate fixes, is there a test that would fail on the
   pre-fix code? (Verify this directly — see the required check below, not by inspection alone.)
6. **failure_tests** — for code with an explicit failure/fallback path, is that path under test,
   or only the success path?
7. **coverage_gaps** — real, specific lines/branches near the candidate's diff with no test at
   all — not a generic "coverage should be higher," a concrete named gap.
8. **flaky_tests** — any test near the diff with timing assumptions, ordering assumptions, or
   external-state assumptions likely to make it pass/fail nondeterministically.
9. **missing_assertions** — tests that run code and check nothing meaningful about the result
   (e.g. "it doesn't throw" as the only assertion, when the actual behavior needs checking).
10. **false_positive_tests** — the most important dimension here: tests that would still pass even
    if the behavior they claim to prove were broken or removed entirely.

## Required check: prove regression tests actually regress

For every test you're relying on as evidence a behavior is covered, do not take its existence as
proof. In your isolated worktree, revert (or comment out) the specific fix/behavior it claims to
test, re-run that test, and confirm it now fails. If it still passes with the behavior reverted,
that test is a **false positive** — record it in `false_positive_tests_found`, not just as a prose
note. Do this for a genuinely representative sample of the candidate's test coverage, not just one
token check — your `false_positive_tests_found` array (even if empty) is the single most valuable
thing in your receipt.

## Required output

`<runDir>/test-coverage-receipt.json` — see `.agent/contracts/test-coverage-receipt.schema.json`.
Use `node .agent/scripts/collect-evidence.js <runDir> <phase_id> <evidence-id> -- <command>` for
every revert-and-rerun check and every other command, citing evidence IDs in every finding and in
every `false_positive_tests_found` entry.

## Hard requirement

Do not report a coverage gap or false positive you have not actually demonstrated. "This looks
untested" without having checked is speculation; "I ran X, commented out Y, and the test still
passed — evidence Z" is a finding.

## Status

`status: "FAIL"` if you demonstrate at least one `severity: "blocking"` finding — in practice,
almost always a confirmed false-positive test on behavior the candidate's `security_invariant` or
core claim depends on, or a coverage gap on the same. Advisory findings (real gaps, not blocking)
do not fail the receipt.
