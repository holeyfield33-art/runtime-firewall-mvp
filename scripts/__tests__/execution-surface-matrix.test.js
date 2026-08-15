// scripts/__tests__/execution-surface-matrix.test.js
// Plain node+assert test (repo convention, no jest) for the P0-1 execution-surface harness.
// Runs the real coordinator as a child process (spawnSync), then asserts on its stdout table
// and on the JSON file it writes to results/execution-surface-matrix.json.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO_ROOT = path.join(__dirname, '..', '..');
const COORDINATOR = path.join(REPO_ROOT, 'scripts', 'execution-surface-matrix.js');
const OUT_JSON = path.join(REPO_ROOT, 'results', 'execution-surface-matrix.json');
const VALID_VERDICTS = new Set(['INTERCEPTED', 'BYPASS', 'UNSUPPORTED']);

let passed = 0;
function check(name, fn) {
  try {
    fn();
    console.log('  ✓ ' + name);
    passed++;
  } catch (e) {
    console.error('  ✗ ' + name + '\n    ' + e.message);
    process.exit(1);
  }
}

const res = spawnSync(process.execPath, [COORDINATOR], {
  cwd: REPO_ROOT,
  encoding: 'utf8',
  timeout: 120000,
});

check('coordinator runs to completion (no crash)', () => {
  assert.ok(res.status !== null, 'coordinator process did not exit cleanly: ' + res.signal);
});

check('coordinator prints a 10-row human table to stdout', () => {
  const lines = (res.stdout || '').split('\n');
  const rowLines = lines.filter(l => /INTERCEPTED|BYPASS|UNSUPPORTED/.test(l));
  assert.strictEqual(rowLines.length, 10, `expected 10 verdict lines, got ${rowLines.length}:\n${res.stdout}`);
});

check('coordinator writes results/execution-surface-matrix.json in the required shape', () => {
  assert.ok(fs.existsSync(OUT_JSON), 'results/execution-surface-matrix.json was not written');
  const data = JSON.parse(fs.readFileSync(OUT_JSON, 'utf8'));
  assert.ok(data.generatedAt, 'missing generatedAt');
  assert.strictEqual(data.target, 'packages/fw-agent');
  assert.ok(Array.isArray(data.rows), 'rows must be an array');
  assert.strictEqual(data.rows.length, 10, `expected 10 rows, got ${data.rows.length}`);
  for (const row of data.rows) {
    assert.ok(row.path, 'row missing path');
    assert.ok(VALID_VERDICTS.has(row.verdict), `row "${row.path}" has invalid verdict "${row.verdict}" (UNKNOWN is never allowed)`);
    assert.ok(typeof row.detail === 'string' && row.detail.length > 0, `row "${row.path}" missing a detail string`);
  }

  const require_ = data.rows.find(r => r.path.includes('require() [control]'));
  const nestedRequire = data.rows.find(r => r.path.toLowerCase().includes('nested require'));
  assert.ok(require_, 'require() [control] row not found');
  assert.ok(nestedRequire, 'nested require() [control] row not found');
  assert.strictEqual(require_.verdict, 'INTERCEPTED', 'require() [control] row must be INTERCEPTED');
  assert.strictEqual(nestedRequire.verdict, 'INTERCEPTED', 'nested require() [control] row must be INTERCEPTED');
});

check('coordinator exits 0 when both control rows are INTERCEPTED', () => {
  assert.strictEqual(res.status, 0, `expected exit 0, got ${res.status}. stderr:\n${res.stderr}`);
});

console.log(`\n${passed} execution-surface-matrix harness checks passed.`);
