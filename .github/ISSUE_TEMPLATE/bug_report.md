---
name: Bug report
about: Something behaves incorrectly or a threat is not detected when it should be
title: '[Bug] '
labels: bug
assignees: ''
---

## Describe the bug

A clear description of what is wrong and what you expected to happen.

## Reproduction

```bash
# Minimal command or code that reproduces the issue
FW_ENABLE_DETECTION=1 node --require aletheia-firewall app.js
```

## Environment

- Node version (`node --version`):
- aletheia-firewall version:
- OS / arch:
- `FW_ENABLE_BEHAVIORAL` setting (default `1`):

## Audit log output

Paste the relevant lines from the audit log (default `/var/log/helios/audit.log`
or `$TMPDIR/helios/audit.log`):

```
<paste here>
```

## Additional context

Any other context, policy file contents, or module source that helps reproduce.
