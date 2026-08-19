# Findings inbox

Scope-creep parking lot: things found while working a phase that are out of that phase's
scope. Not a task list — just a record so they aren't lost or fixed unilaterally.

## data: module identity/policy-key scheme (found during P-C, F-03)

**Where:** `packages/fw-agent/index.js`'s `registerHooks()` load hook (the ESM path) could, in
principle, scan `data:` module sources today — `result.source` is already available for a
`data:` import before the scheme check at line 623 returns early (confirmed: the format/source
guard at line 620 runs first and does not require a `file://` URL).

**Why it's parked, not fixed:** every downstream consumer of that source assumes a real
filesystem path:

- `resolveModuleIdentity(filename)` (index.js:470) calls `path.dirname(filename)` and walks up
  the directory tree looking for `package.json` via `fs.existsSync`/`fs.readFileSync`.
- `packageKeyForFilename(filename)` (index.js:411) string-matches `/node_modules/` in the
  filename to derive the owning npm package for cross-file correlation scoping.
- The load hook itself gets `filename` via `fileURLToPath(url)` (index.js:631), which throws for
  a non-`file:` URL scheme — a `data:` URL has no filesystem path to convert.

None of these have an obvious answer for a `data:` import: there is no directory to walk, no
`node_modules` segment, no package.json, and no stable identity across two `data:` imports with
different inline source but the same importing context. Policy rules are currently written
against package identities (`name@version:relPath`) or package keys (`node_modules` folder
name) — a `data:` import doesn't naturally have either, so giving it one is a policy-surface
design decision (what does "policy for this data: import" even mean — per-importer? per-content
hash? unconfigurable, always-OBSERVE?), not a mechanical wiring change.

**Explicitly not attempted:** inventing a synthetic identity/policy-key scheme for `data:`
imports without a design discussion. Per P-C's phase brief, this is called out because it's easy
to quietly make a security-relevant design decision (what policy applies to a payload with no
package identity) while "just" wiring up a scan.

**Suggested next step:** a future phase that answers, deliberately: (a) what identity string a
`data:` import gets for policy lookup, (b) whether it participates in cross-file behavioral
correlation at all (packageKeyForFilename currently returns `null` for non-`node_modules` code,
which skips cross-file — is a `data:` import "first-party" by default, or does it need its own
bucket?), and (c) whether `http:`/`https:`/`blob:` should share that scheme or need their own
(those additionally require a network fetch before scanning, which P-C's brief also excluded).

## node -e / execution-surface matrix generator (not attempted this phase)

`docs/THREAT-COVERAGE.md`'s execution-path table now documents the `node -e` inline-payload
BYPASS by hand (P-C step 1). Reflecting it in `scripts/execution-surface-matrix.js`'s actual row
definitions (so `npm run test:matrix` asserts it, not just describes it in prose) is a larger,
separate change to the matrix generator itself — out of scope for P-C per its own brief, but
worth a dedicated phase.
