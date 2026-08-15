// scripts/matrix-rows/worker-thread.js
// Row: worker_threads -> new Worker. Spawns a file-based Worker that requires the sentinel.
'use strict';
const { FIXTURES_DIR, outfileReport } = require('./_shared');
const path = require('path');

const report = outfileReport(process.argv[2] || 'worker-thread');
const SENTINEL_WORKER = path.join(FIXTURES_DIR, 'sentinel-worker.js');

(async () => {
  const { Worker } = require('worker_threads');
  try {
    const result = await new Promise((resolve, reject) => {
      const w = new Worker(SENTINEL_WORKER);
      const timer = setTimeout(() => reject(new Error('worker timed out')), 15000);
      w.on('message', (msg) => { clearTimeout(timer); resolve(msg); });
      w.on('error', (err) => { clearTimeout(timer); reject(err); });
      w.on('exit', () => { clearTimeout(timer); });
    });
    if (result.status === 'ran') {
      report('BYPASS', 'new Worker() ran the sentinel unhindered; Worker threads do not inherit the parent\'s hooked Module.prototype._compile unless execArgv explicitly re-preloads the agent.');
    } else if (result.status === 'blocked' && result.message && result.message.includes('[Firewall]')) {
      report('INTERCEPTED', 'Worker thread require() threw a [Firewall] error: ' + result.message);
    } else {
      report('UNSUPPORTED', 'Worker reported an unexpected result: ' + JSON.stringify(result));
    }
  } catch (e) {
    report('UNSUPPORTED', 'Worker probe threw an unrelated error: ' + (e && e.message));
  }
})();
