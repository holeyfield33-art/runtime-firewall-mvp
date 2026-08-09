/* meta-test.js - verify package metadata resolution for the agent package */
const path = require('path');
const pj = require(path.join(__dirname, '..', '..', 'fw-agent', 'package.json'));
if (!pj || !pj.name || !pj.version) {
  console.error('META_TEST_FAIL: missing package.json fields');
  process.exit(2);
}
if (pj.name !== 'aletheia-firewall') {
  console.error('META_TEST_FAIL: unexpected package name: ' + pj.name);
  process.exit(2);
}
if (pj.version !== '0.3.0') {
  console.error('META_TEST_FAIL: unexpected package version: ' + pj.version);
  process.exit(2);
}
console.log('META_TEST_PASS');
