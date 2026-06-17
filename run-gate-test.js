// run-gate-test.js
// Runs both honest benchmarks. bench-honest is transparency-only (not gated;
// its high per-module % is expected). bench.js is the gate and sets exit code.
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

function run(label, scriptRelPath) {
  const scriptPath = path.join(__dirname, scriptRelPath);
  console.log(`\n=== ${label} ===`);
  console.log(`(${scriptRelPath})\n`);
  const res = spawnSync(process.execPath, [scriptPath], { stdio: 'inherit' });
  if (res.error) {
    console.error(`\n[gate] ${label} failed to spawn: ${res.error.message}`);
    return { ok: false };
  }
  if (res.signal) {
    console.error(`\n[gate] ${label} killed by signal ${res.signal} (timeout/OOM).`);
    return { ok: false };
  }
  return { ok: res.status === 0, status: res.status };
}

console.log('Runtime Firewall performance audit - both scopes.');

const honest = run(
  'Per-module honest benchmark (transparency, NOT gated)',
  path.join('packages', 'fw-agent', 'test', 'bench-honest.js')
);

const gate = run(
  'Realistic-app compilation gate (median<5%, P95<20%)',
  path.join('packages', 'fw-control', 'test', 'bench.js')
);

console.log('\n========================================');
console.log(`Per-module benchmark ran: ${honest.ok ? 'clean' : 'ERROR'}`);
console.log(`Realistic-app gate:       ${gate.ok ? 'PASS' : 'FAIL'}`);
console.log('========================================');

if (!honest.ok) {
  console.error('\nGate result: ERROR - per-module benchmark did not complete.');
  process.exit(2);
}
if (!gate.ok) {
  console.error('\nGate result: FAIL - realistic-app overhead exceeded budget.');
  process.exit(1);
}
console.log('\nGate result: PASS - realistic-app overhead within budget.');
process.exit(0);
