# Sync Gate Rule

The Release Warden decides `sync_required` **deterministically**, from the engineer receipt's
`changed_files` list alone. No model opinion can set or override this field — see
`scripts/release-warden.js`'s `SYNC_TRIGGER_PATTERNS`.

## Rule

```
sync_required = true  iff  changed_files contains any path matching:

  packages/fw-agent/src/detector.js
  packages/fw-agent/src/behavior-tracker.js
  packages/fw-agent/src/aho-corasick.js
  packages/fw-agent/src/ast-scan.js
  packages/fw-agent/src/policy.js
  packages/fw-agent/index.js
```

Otherwise `sync_required = false`.

## Rationale

These six files are the actual enforcement core — the hook installation point (`index.js`) and
the detection engine (`detector.js`, `behavior-tracker.js`, `aho-corasick.js`, `ast-scan.js`,
`policy.js`). A
change to any of them changes the firewall's real security behavior, which is exactly the class
of change that would need review before being propagated to wherever else the enforcement logic
is consumed (e.g. a future MRN-CRS integration, once that integration exists — this rule does not
reference or touch MRN-CRS itself).

A change confined to `.agent/`, `docs/`, tests, or scaffolding never sets `sync_required`.

## What `sync_required: true` means operationally

It does **not** mean "do it automatically." It means: a human release step must explicitly
confirm that any downstream consumer of `packages/fw-agent`'s enforcement logic has been made
aware of the change before that consumer is treated as up to date. The `.agent/` graph has no
authority to perform that sync itself — see the directive's explicit prohibition on registry
modification.
