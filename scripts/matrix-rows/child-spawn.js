// scripts/matrix-rows/child-spawn.js
// Row: child_process.spawn('node', ...). Spawns grandchild-require.js as a fresh node process
// (via spawnSync) and inspects its stdout marker.
'use strict';
const { outfileReport } = require('./_shared');

const report = outfileReport(process.argv[2] || 'child-spawn');

function parseGrandchildStdout(stdout) {
  const m = /MATRIX_GRANDCHILD_RESULT: (ran|blocked)(.*)/.exec(stdout || '');
  if (!m) return { status: 'unknown', raw: stdout };
  return { status: m[1], detail: m[2].trim() };
}

const { spawnSync } = require('child_process');
const path = require('path');

const res = spawnSync(process.execPath, [path.join(__dirname, 'grandchild-require.js')], {
  encoding: 'utf8',
  env: process.env,
  timeout: 15000,
});
const parsed = parseGrandchildStdout(res.stdout);
if (parsed.status === 'ran') {
  report('BYPASS', "child_process.spawn('node', ...) ran the sentinel unhindered; spawned children do not inherit --require execArgv, only env (NODE_OPTIONS).");
} else if (parsed.status === 'blocked' && parsed.detail.includes('[Firewall]')) {
  report('INTERCEPTED', "Spawned child's require() threw a [Firewall] error: " + parsed.detail);
} else {
  report('UNSUPPORTED', 'Spawned child produced no parseable result: ' + JSON.stringify(res.stdout));
}
