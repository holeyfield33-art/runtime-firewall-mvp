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
fs.writeFileSync(path.join(testDir, 'miner.js'), `
const pool = 'stratum://pool.hashvault.pro:8080';
module.exports = { pool };
`);

// Module 2: Obfuscated code (should be detected)
fs.writeFileSync(path.join(testDir, 'obfuscated.js'), `
const b64 = Buffer.from('aWYo');
eval(b64.toString());
module.exports = {};
`);

// Module 3: Clean module (should NOT be detected)
fs.writeFileSync(path.join(testDir, 'clean.js'), `
module.exports = { name: 'clean', version: '1.0.0' };
`);

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
