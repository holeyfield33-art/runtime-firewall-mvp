// scripts/matrix-rows/nested-require.js
// Row: nested require() [control]. Requires the sentinel through one intermediate module
// (sentinel-nested-wrapper.js) — expected INTERCEPTED.
'use strict';
const path = require('path');
const { FIXTURES_DIR, outfileReport, isFirewallError } = require('./_shared');

const report = outfileReport(process.argv[2] || 'nested-require');
const SENTINEL_NESTED = path.join(FIXTURES_DIR, 'sentinel-nested-wrapper.js');

try {
  require(SENTINEL_NESTED);
  report('BYPASS', 'nested require() completed without a firewall error; sentinel executed.');
} catch (e) {
  if (isFirewallError(e)) {
    report('INTERCEPTED', 'nested require() threw a [Firewall] error: ' + e.message);
  } else {
    report('UNSUPPORTED', 'nested require() threw an unrelated error: ' + (e && e.message));
  }
}
