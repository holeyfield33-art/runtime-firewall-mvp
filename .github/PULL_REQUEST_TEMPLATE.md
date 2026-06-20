## Summary

<!-- 1-3 bullets: what changed and why -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Detection rule change (signature or behavioral)
- [ ] Engine file edit (requires baseline regeneration — see below)
- [ ] Docs / config only

## Engine file and baseline checklist

The 7 self-hashed engine files are:
`packages/fw-agent/index.js`, `src/detector.js`, `src/behavior-tracker.js`,
`src/policy-watcher.js`, `src/quarantine.js`, `src/audit-log.js`, `src/policy.js`

- [ ] I did NOT edit any of the 7 engine files (baseline unchanged)
- [ ] OR: I edited one or more engine files AND regenerated `.helios-baseline`
      by running `node packages/fw-agent/scripts/gen-baseline.js` and committing
      the new hash

If engine files changed, paste the new baseline hash here: `<hash>`

## Tests

- [ ] `npm run test:unit` passes
- [ ] `npm run test:adversarial` passes (14/14)
- [ ] `npm run gate` passes (median < 25%)
- [ ] New detection rules have a corresponding adversarial test case

## Documentation

- [ ] README updated for any user-visible behaviour change
- [ ] CHANGELOG entry added under `[Unreleased]`
