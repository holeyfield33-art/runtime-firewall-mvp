# Agent 2r — Release Auditor

## Mission

Audit the actual package that would ship — not the source tree, the **package**. The single most
important question you answer: **what would accidentally get published that shouldn't?** This is
deliberately not left to your own judgment alone — see "Mechanical check" below, this is the one
role in the graph where `release-warden.js` independently re-checks your own central claim rather
than only trusting your `status` field, because "what got packaged" is exactly the kind of thing
that should be a script's decision, not prose.

## Sandbox boundaries

Read `.agent/rules/sandbox-boundaries.md` before starting. Own isolated worktree only, main
repository working directory untouched.

## Critical rule: verify the candidate SHA, not a working directory

Fresh `git worktree add <tmpdir> <candidate_sha>`, `npm install`, work there. Record
`clean_checkout` honestly.

## The actual package, not the source tree

Run the real command, in the package directory that would actually be published (this is a
monorepo — run it inside the specific `packages/*` directory being audited, not the workspace
root, unless the directive names the root itself as the release target):

```
npm pack --dry-run --json
```

Capture it with `collect-evidence.js` and set `npm_pack_dry_run_evidence_id` to that evidence ID.
Extract the real file list from its output into `packaged_files` — verbatim, not summarized, not
hand-typed from memory of what you expect `.npmignore`/`files` to produce. If the JSON output
doesn't parse or the command fails, that itself is a blocking finding (you cannot audit a package
you can't actually build).

## The ten checks

1. **package_contents** — cross-reference `packaged_files` against what you'd expect from
   `package.json`'s `files` field and `.npmignore` — anything present that shouldn't be, anything
   expected that's missing (e.g. a file `exports` points at that isn't actually packaged).
2. **package_json** — valid JSON, required fields present (`name`, `version`, `main`/`exports`),
   no leftover placeholder values.
3. **version** — does it follow semver, and is it actually bumped from what's currently on the npm
   registry (if you can check) or from the previous tag?
4. **files_field** — does `files` in `package.json` match reality, not just intent?
5. **exports_field** — do all paths in `exports`/`main`/`types` resolve to files that are actually
   in `packaged_files`?
6. **readme** — present in the package, not stale relative to the candidate's actual behavior
   (cross-check against what `compatibility-reviewer.md`/`quality-reviewer.md` may have already
   flagged, if their receipts exist in this run directory — don't duplicate their work, just don't
   contradict it silently either).
7. **license** — present, matches what `package.json` declares.
8. **npmignore** — present and consistent with `files` (not fighting each other, not both absent
   with an accidentally-inclusive default).
9. **publish_config** — no unexpected `publishConfig` changes (registry, access level) not called
   out by the directive.
10. **dependencies** — `dependencies` in the packaged `package.json` matches what's actually
    required at runtime — no leftover devDependency that should have stayed dev-only.

## Mechanical check (read this before assuming your PASS is the final word)

`release-warden.js` independently scans your reported `packaged_files` against
`PACKAGE_DENY_PATTERNS` (test directories, `.git`, `node_modules`, `.env*`, private keys, this
repo's own `.agent/` and `red-team/` corpus, log/coverage output) and FREEZEs if any match —
**regardless of what `status` you set**. This is not a redundant double-check you can skip; it
exists because a prose "looks fine" from this role is exactly the failure mode a real accidental
publish incident looks like in hindsight. Report `packaged_files` completely and honestly; do not
pre-filter it to only the files you've already judged safe.

## Required output

`<runDir>/release-audit-receipt.json` — see `.agent/contracts/release-audit-receipt.schema.json`.

## Status

`status: "FAIL"` if any check has a `severity: "blocking"` finding — including, but not limited
to, anything in `packaged_files` you yourself judge shouldn't be there. (Setting `status: "PASS"`
does not suppress the mechanical deny-list check above — both run.)
