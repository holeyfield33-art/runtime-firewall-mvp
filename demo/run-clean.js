// A normal app: one ordinary analytics dependency that reads env + calls HTTPS.
const path = require('path');
function attempt(label, file) {
  process.stdout.write('\n>> Loading dependency: ' + label + '\n');
  try {
    require(path.join(__dirname, 'modules', file));
    console.log('   [ALLOWED]  loaded and ran');
  } catch (e) {
    console.log('   [BLOCKED]  ' + String(e.message).split('\n')[0]);
  }
}
console.log('=== App B: a normal app (no malware) ===');
attempt('analytics-sdk (reads env + HTTPS)', 'nice-analytics.js');
