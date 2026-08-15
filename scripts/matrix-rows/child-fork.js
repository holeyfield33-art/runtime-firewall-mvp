// scripts/matrix-rows/child-fork.js
// Row: child_process.fork(). Forks grandchild-require.js and inspects its stdout marker.
'use strict';
const { outfileReport } = require('./_shared');

const report = outfileReport(process.argv[2] || 'child-fork');

function parseGrandchildStdout(stdout) {
  const m = /MATRIX_GRANDCHILD_RESULT: (ran|blocked)(.*)/.exec(stdout || '');
  if (!m) return { status: 'unknown', raw: stdout };
  return { status: m[1], detail: m[2].trim() };
}

(async () => {
  const { fork } = require('child_process');
  const path = require('path');
  let stdout = '';
  try {
    const child = fork(path.join(__dirname, 'grandchild-require.js'), [], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    await new Promise((resolve) => child.on('exit', resolve));
  } catch (e) {
    report('UNSUPPORTED', 'child_process.fork() probe failed to run: ' + (e && e.message));
    return;
  }
  const parsed = parseGrandchildStdout(stdout);
  if (parsed.status === 'ran') {
    report('BYPASS', 'child_process.fork() child ran the sentinel unhindered; forked children do not inherit --require execArgv, only env (NODE_OPTIONS).');
  } else if (parsed.status === 'blocked' && parsed.detail.includes('[Firewall]')) {
    report('INTERCEPTED', 'Forked child\'s require() threw a [Firewall] error: ' + parsed.detail);
  } else {
    report('UNSUPPORTED', 'Forked child produced no parseable result: ' + JSON.stringify(stdout));
  }
})();
