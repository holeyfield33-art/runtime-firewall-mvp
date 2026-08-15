// scripts/matrix-rows/dynamic-import.js
// Row: dynamic import(). Node's ESM loader never calls Module.prototype._compile, so this is
// expected to BYPASS today.
'use strict';
const { pathToFileURL } = require('url');
const { FIXTURES_DIR, outfileReport, isFirewallError } = require('./_shared');
const path = require('path');

const report = outfileReport(process.argv[2] || 'dynamic-import');
const SENTINEL_MJS = path.join(FIXTURES_DIR, 'sentinel-block.mjs');

(async () => {
  const sentinelUrl = pathToFileURL(SENTINEL_MJS).href;
  try {
    const mod = await import(sentinelUrl);
    if (mod && mod.ran && globalThis.__SENTINEL_RAN__) {
      report('BYPASS', 'dynamic import() loaded the ESM sentinel cleanly; Module.prototype._compile is never invoked for ESM evaluation, so the firewall hook cannot see this module.');
    } else {
      report('UNSUPPORTED', 'dynamic import() completed but sentinel marker was not observed.');
    }
  } catch (e) {
    if (isFirewallError(e)) {
      report('INTERCEPTED', 'dynamic import() threw a [Firewall] error: ' + e.message);
    } else {
      report('UNSUPPORTED', 'dynamic import() threw an unrelated error: ' + (e && e.message));
    }
  }
})();
