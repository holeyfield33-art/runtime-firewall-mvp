// scripts/matrix-rows/pre-hook-cache.js
// Row: module loaded BEFORE firewall required (pre-hook/cache). Requires the sentinel, then
// loads the agent programmatically (dev-mode, not preloaded), then requires the SAME sentinel
// file again — Node's require() cache returns the cached export by resolved filename without
// re-invoking Module.prototype._compile, so the already-loaded module is never rescanned.
'use strict';
const { FIXTURES_DIR, AGENT_PATH, outfileReport, isFirewallError } = require('./_shared');
const path = require('path');

const report = outfileReport(process.argv[2] || 'pre-hook-cache');
const SENTINEL_CJS = path.join(FIXTURES_DIR, 'sentinel-block.js');

let firstError = null;
try {
  require(SENTINEL_CJS);
} catch (e) {
  firstError = e;
}

try {
  require(AGENT_PATH);
} catch (e) {
  // Non-fatal for this probe: even if the agent's own startup throws, we still care whether
  // the ALREADY-CACHED sentinel module gets rescanned below.
}

let secondError = null;
try {
  require(SENTINEL_CJS);
} catch (e) {
  secondError = e;
}

if (!firstError && !secondError) {
  report('BYPASS', 'Sentinel was require()\'d before the agent loaded, then again afterward; Node\'s require() cache (keyed by resolved filename) returned the cached export both times without re-invoking Module.prototype._compile, so the already-loaded module is never scanned.');
} else if (secondError && isFirewallError(secondError)) {
  report('INTERCEPTED', 'Unexpectedly re-scanned on the second require() and threw a [Firewall] error: ' + secondError.message);
} else {
  report('UNSUPPORTED', 'Unexpected error during pre-hook/cache probe: first=' + (firstError && firstError.message) + ' second=' + (secondError && secondError.message));
}
