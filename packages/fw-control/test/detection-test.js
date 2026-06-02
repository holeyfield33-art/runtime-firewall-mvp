// packages/fw-control/test/detection-test.js
const path = require('path');
const fs = require('fs');

console.log('[Detection Test] Initializing agent with detection engine...\n');

// Require the agent - this starts the detector
require(path.join(__dirname, '../../fw-agent/index.js'));

// Create a temporary malicious module for testing
const testDir = path.join(__dirname, 'test-modules');
if (!fs.existsSync(testDir)) {
  fs.mkdirSync(testDir, { recursive: true });
}

// Write a test module with crypto-miner signature
const filler = ' /* ensure >512 bytes to pass pre-filter in detector */ '.repeat(12);
const cryptoMinerModule = path.join(testDir, 'crypto-test.js');
fs.writeFileSync(cryptoMinerModule, `
// This is a test module with crypto-miner signature
const config = {
  pool: 'stratum://pool.hashvault.pro:8080',
  wallet: 'malicious-wallet'
};
module.exports = { config };
` + filler);

// Write a clean test module
const cleanModule = path.join(testDir, 'clean-test.js');
fs.writeFileSync(cleanModule, `
// This is a clean test module
module.exports = { data: 'clean' };
` + filler);

console.log('[Detection Test] Test modules created at:', testDir);
console.log('[Detection Test] Waiting 1 second for initial setup...\n');

setTimeout(() => {
  console.log('[Detection Test] Loading clean module first...');
  try {
    require(cleanModule);
    console.log('[Detection Test] ✅ Clean module loaded successfully\n');
  } catch (err) {
    console.error('[Detection Test] ❌ Clean module failed:', err.message, '\n');
  }

  console.log('[Detection Test] Now loading module with crypto-miner signature...');
  try {
    require(cryptoMinerModule);
    console.log('[Detection Test] ❌ Malicious module loaded (should have been detected)\n');
  } catch (err) {
    console.error('[Detection Test] Malicious module error:', err.message, '\n');
  }

  console.log('[Detection Test] Cleanup and exit in 2 seconds...');
  setTimeout(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    console.log('[Detection Test] ✅ Test complete. Cleaning up...');
    process.exit(0);
  }, 2000);
}, 1000);
