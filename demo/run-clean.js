// demo/run-clean.js
//
// Loads a legitimate module through the firewall. The require() call is expected
// to succeed: the firewall observes the network call but does not block. Exits
// non-zero if the clean module is wrongly blocked (a false positive).

const path = require('path');

require(path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js'));

console.log('=== Clean workload (expect ALLOWED) ===');
process.stdout.write('\n[demo] loading nice-analytics (benign metrics) ... ');

try {
  const analytics = require('./modules/nice-analytics.js');
  console.log('ALLOWED');
  analytics.track('demo.pageview', { page: '/home' });
  console.log('        module loaded and executed normally.');
  console.log('\n[demo] OK: legitimate module was allowed.');
  process.exit(0);
} catch (err) {
  console.log('BLOCKED  <-- FALSE POSITIVE (should have been allowed)');
  console.error(`        reason: ${err.message}`);
  console.error('\n[demo] FAIL: legitimate module was wrongly blocked.');
  process.exit(1);
}
