// scripts/matrix-rows/vm-context.js
// Row: vm.runInNewContext(). Compiles the sentinel source directly via V8, bypassing
// Module.prototype._compile entirely — expected BYPASS.
'use strict';
const fs = require('fs');
const { FIXTURES_DIR, outfileReport, isFirewallError } = require('./_shared');
const path = require('path');

const report = outfileReport(process.argv[2] || 'vm-context');
const SENTINEL_CJS = path.join(FIXTURES_DIR, 'sentinel-block.js');

const vm = require('vm');
const src = fs.readFileSync(SENTINEL_CJS, 'utf8');
const sandbox = {};
vm.createContext(sandbox);
try {
  vm.runInContext(src, sandbox);
  if (sandbox.__SENTINEL_RAN__) {
    report('BYPASS', 'vm.runInNewContext() executed the sentinel source directly via V8, never calling require()/Module.prototype._compile, so the firewall hook never runs.');
  } else {
    report('UNSUPPORTED', 'vm context ran without throwing but the sentinel marker was not observed.');
  }
} catch (e) {
  if (isFirewallError(e)) {
    report('INTERCEPTED', 'vm context threw a [Firewall] error: ' + e.message);
  } else {
    report('UNSUPPORTED', 'vm context threw an unrelated error: ' + (e && e.message));
  }
}
