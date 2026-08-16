#!/usr/bin/env node
// scripts/execution-surface-matrix-esm-entry.mjs
// Dedicated ESM entry point for the "ESM static import" matrix row. A genuine static `import`
// declaration must live in a real ES module file, at the top level, unconditional, and outside
// any try/catch — that is what distinguishes it from dynamic import() (exercised separately by
// the CJS child under row "dynamic-import"). Static import bindings are resolved during module
// linking, BEFORE this file's own body runs, so if the target throws (the agent's ESM load hook
// in packages/fw-agent/index.js via Module.registerHooks() blocking it), this file's body below
// never executes at all — the whole process crashes with an uncaught exception instead. That crash,
// with a "[Firewall]" message on stderr, IS the positive interception signal for this row; see
// execution-surface-matrix.js's runRow() for how the coordinator classifies it (this file cannot
// write MATRIX_OUTFILE in that case — it never gets the chance to run).
import fs from 'node:fs';
import sentinel from '../red-team/corpus/fixtures/sentinel-block.mjs';

const rowId = process.argv[2] || 'esm-static-import';
const outFile = process.env.MATRIX_OUTFILE;

function report(verdict, detail) {
  const payload = JSON.stringify({ rowId, verdict, detail });
  if (outFile) {
    fs.writeFileSync(outFile, payload, 'utf8');
  } else {
    process.stdout.write(payload + '\n');
  }
}

// Reaching this line at all means the static import above completed without the loader hook
// throwing — the malicious module ran.
if (sentinel && sentinel.ran && globalThis.__SENTINEL_RAN__) {
  report('BYPASS', 'ESM static import of the sentinel completed and evaluated cleanly — not intercepted.');
} else {
  report('UNSUPPORTED', 'ESM static import completed but sentinel marker was not observed.');
}
