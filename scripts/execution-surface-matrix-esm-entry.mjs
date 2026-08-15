#!/usr/bin/env node
// scripts/execution-surface-matrix-esm-entry.mjs
// Dedicated ESM entry point for the "ESM static import" matrix row. A static `import`
// declaration must live in a real ES module file (top-level, cannot be expressed inside the
// shared CJS child script), so this tiny file exists solely to host it.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sentinelUrl = new URL('../red-team/corpus/fixtures/sentinel-block.mjs', import.meta.url);

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

let sentinel;
let importError = null;
try {
  // Static import (top-level `import` is required for this to count as a genuine static import;
  // dynamic import() is exercised separately by the shared CJS child under row "dynamic-import").
  sentinel = await import(sentinelUrl.href);
} catch (e) {
  importError = e;
}

if (importError) {
  const msg = String((importError && importError.message) || importError);
  if (msg.includes('[Firewall]')) {
    report('INTERCEPTED', 'ESM static import threw a [Firewall] error: ' + msg);
  } else {
    report('UNSUPPORTED', 'ESM static import threw an unrelated error: ' + msg);
  }
} else if (sentinel && sentinel.ran && globalThis.__SENTINEL_RAN__) {
  report('BYPASS', 'ESM static import loaded the sentinel cleanly; Module.prototype._compile is never invoked for ESM evaluation, so the firewall hook cannot see this module.');
} else {
  report('UNSUPPORTED', 'ESM static import completed but sentinel marker was not observed.');
}
