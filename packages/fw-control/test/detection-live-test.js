// packages/fw-control/test/detection-live-test.js
const path = require('path');
const fs = require('fs');

console.log('[Live Detection Test] Initializing agent with ACTIVE detection enabled...\n');

// Enable detection for this test
process.env.FW_ENABLE_DETECTION = '1';

// Load the agent - activates detection engine
require(path.join(__dirname, '../../fw-agent/index.js'));

// Create test modules
const testDir = path.join(__dirname, 'live-test-modules');
if (fs.existsSync(testDir)) {
  fs.rmSync(testDir, { recursive: true, force: true });
}
fs.mkdirSync(testDir, { recursive: true });

// Module 1: Crypto-miner (should be detected)
const filler = ' /* pad >512B for pre-filter bypass test realism */ '.repeat(12);
fs.writeFileSync(path.join(testDir, 'miner.js'), `
const pool = 'stratum://pool.hashvault.pro:8080';
module.exports = { pool };
` + filler);

// Module 2: Obfuscated code — base64-decode a blob then eval it. Blocked by the
// OBFUSCATED_CODE_EXECUTION behavioral rule (F-31). The prior fixture used
// Buffer.from('aWYo') with no 'base64' arg, so .toString() returned 'aWYo' unchanged
// and eval threw a ReferenceError at runtime instead of being intercepted at compile
// time — the module was never actually "blocked", so this test could never reach
// Blocked: 2. This payload decodes to `module.exports={pwned:true}` and is caught.
fs.writeFileSync(path.join(testDir, 'obfuscated.js'), `
const blob = 'bW9kdWxlLmV4cG9ydHM9e3B3bmVkOnRydWV9';
const code = Buffer.from(blob, 'base64').toString();
eval(code);
` + filler);

// Module 3: Clean module (should NOT be detected)
fs.writeFileSync(path.join(testDir, 'clean.js'), `
module.exports = { name: 'clean', version: '1.0.0' };
` + filler);

console.log('[Live Detection Test] Test modules created\n');
console.log('[Live Detection Test] Waiting 1 second for setup...\n');

setTimeout(() => {
  console.log('[Live Detection Test] Loading CLEAN module...');
  try {
    require(path.join(testDir, 'clean.js'));
    console.log('[Live Detection Test] ✅ Clean module loaded\n');
  } catch (err) {
    console.error('[Live Detection Test] Error:', err.message, '\n');
  }

  console.log('[Live Detection Test] Loading CRYPTO-MINER module...');
  try {
    require(path.join(testDir, 'miner.js'));
    console.log('[Live Detection Test] ✅ Miner module loaded\n');
  } catch (err) {
    console.error('[Live Detection Test] Error:', err.message, '\n');
  }

  console.log('[Live Detection Test] Loading OBFUSCATED module...');
  try {
    require(path.join(testDir, 'obfuscated.js'));
    console.log('[Live Detection Test] ✅ Obfuscated module loaded\n');
  } catch (err) {
    console.error('[Live Detection Test] Error:', err.message, '\n');
  }

  console.log('[Live Detection Test] Waiting 3 seconds for background detection to complete...');
  setTimeout(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('[Live Detection Test] ✅ Test complete\n');
    process.exit(0);
  }, 3000);
}, 1000);
