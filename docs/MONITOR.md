# Aletheia Research Monitor — Run Manual

`monitor.js` is a **standalone, logging-only** research tool that reuses the
firewall's detection engine (`packages/fw-agent/src/detector.js`) to
continuously scan a project's `node_modules` and report threats. Unlike the
firewall itself (`packages/fw-agent`), it never blocks anything — it only
walks files, scans their content, and appends findings to a log. Use it to
dogfood the detector against real-world dependency trees without putting
the firewall in the require path.

This doc is a copy-paste walkthrough from a fresh clone.

## Prerequisites

- Node.js >= 18
- A local clone of this monorepo (the monitor loads the detector via a
  relative path — `require('./packages/fw-agent/src/detector')` — so it
  must be run from the `runtime-firewall-mvp` repo root)

## Usage

```bash
# Scan the current directory's node_modules
node monitor.js

# Scan a different project's node_modules
node monitor.js /path/to/target-project
```

The single optional argument is the **target project root**, not the
`node_modules` path itself — the monitor appends `node_modules` for you.
If omitted, it defaults to `process.cwd()`.

## What happens on startup

1. **Full scan.** The monitor recursively walks `<target>/node_modules`,
   collecting every file with a `.js`, `.cjs`, `.mjs`, `.ts`, `.jsx`, or
   `.tsx` extension. Directories named `bin`, `dist`, `build`, or `docs` are
   skipped during the walk.
2. Each file is read and passed to
   `detector.scanModuleSync(filePath, content, filePath)` — the same
   synchronous scan path the runtime firewall uses at `require()` time.
3. **Live watch.** Once the initial scan completes, the monitor calls
   `fs.watch(node_modules, { recursive: true })` and rescans any changed or
   newly created file matching the extension list above. It keeps running
   until you stop it (`Ctrl+C`); there is no fixed end state.

## What gets logged

Only detections with severity `CRITICAL` or `HIGH` are logged — the same
tier that would cause the firewall to `QUARANTINE`/block a module.
`WARN`-tier detections (e.g. the indicative-pattern signatures like
`buffer.from`, `eval(`, or `child_process.spawn` that are common in
legitimate code) are scanned but never written to the log, so the monitor
does not flood `research.log` with borderline signals.

A threat entry looks like this:

```json
{"timestamp":"2026-07-14T12:46:04.937Z","file":"/node_modules/.evil-test.js","action":"QUARANTINE","threats":[{"type":"crypto-miner","severity":"CRITICAL","matched":"stratum"}]}
```

| Field | Meaning |
|-------|---------|
| `timestamp` | ISO-8601 time the threat was logged |
| `file` | Scanned path with the target project root stripped, so log lines are portable across machines |
| `action` | The detector's verdict — `QUARANTINE` (a CRITICAL/HIGH detection fired) or `OBSERVE` (would not normally reach the log; see below) |
| `threats` | Array of `{ type, severity, matched }` for each CRITICAL/HIGH detection found in that file |

Logs are appended (never overwritten) to `research.log` at the repo root,
next to `monitor.js` — **not** relative to the scanned target project.

## Deduplication

The monitor keeps an in-memory `Set` keyed on `<file path>:<comma-joined threat types>`.
If the same file re-triggers the same set of threat types (e.g. `fs.watch`
firing more than once for a single edit, which is common on some
filesystems), it is scanned again but only logged once. Restarting the
monitor clears this cache, so a full rescan after a restart will re-log
files it already reported in a previous run.

## Example: catching a crypto-miner

```bash
# From the repo root
echo "const p='stratum+tcp://x.evil:3333';" > node_modules/.evil-test.js

node monitor.js
# [MONITOR] Threat found: crypto-miner in .evil-test.js

cat research.log
# {"timestamp":"...","file":"/node_modules/.evil-test.js","action":"QUARANTINE","threats":[{"type":"crypto-miner","severity":"CRITICAL","matched":"stratum"}]}

# Clean up
rm node_modules/.evil-test.js
```

Ordinary dependencies (`lodash`, `express`, `axios`, etc.) do not appear in
`research.log` — they only trip `WARN`-tier signatures (if any), which are
scanned but intentionally not logged.

## Stopping the monitor

`Ctrl+C`. The process has no graceful-shutdown hook (unlike the firewall
agent) — it simply exits; nothing is buffered in memory that needs
flushing beyond the already-appended `research.log` lines.

## Troubleshooting

**`[Monitor] Error: Could not find detector module.`**
You are not running `node monitor.js` from the `runtime-firewall-mvp` repo
root. `cd` into the repo root and re-run.

**`research.log` never gets any entries.**
Confirm the target project actually has a populated `node_modules`
(`node monitor.js` prints `[MONITOR] Found N files to scan.` — if `N` is
`0`, there is nothing to scan) and that any expected threat file has a
matching extension (`.js`, `.cjs`, `.mjs`, `.ts`, `.jsx`, `.tsx`).

**The monitor never exits.**
This is expected — after the initial full scan it switches to a permanent
`fs.watch` loop. Stop it with `Ctrl+C` when you're done.
