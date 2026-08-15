// scripts/matrix-rows/require-control.js
// Row: require() [control]. Direct top-level require() of the sentinel — expected INTERCEPTED.
'use strict';
const path = require('path');
const { FIXTURES_DIR, outfileReport, isFirewallError } = require('./_shared');

const report = outfileReport(process.argv[2] || 'require-control');
const SENTINEL_CJS = path.join(FIXTURES_DIR, 'sentinel-block.js');

try {
  require(SENTINEL_CJS);
  report('BYPASS', 'require() completed without a firewall error; sentinel executed.');
} catch (e) {
  if (isFirewallError(e)) {
    report('INTERCEPTED', 'require() threw a [Firewall] error: ' + e.message);
  } else {
    report('UNSUPPORTED', 'require() threw an unrelated error: ' + (e && e.message));
  }
}
