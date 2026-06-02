// packages/fw-control/test/detector-unit-test.js
const path = require('path');
const { Detector } = require(path.join(__dirname, '../../fw-agent/src/detector'));

console.log('[Detector Unit Test] Starting detector validation...\n');

const detector = new Detector(new Map());

// Test 1: Crypto-miner detection
const filler = ' /* pad to >512B so pre-filter + chunk logic is exercised in unit tests */ '.repeat(15);
const cryptoContent = `
const config = {
  pool: 'stratum://pool.hashvault.pro:8080',
  wallet: 'malicious-wallet'
};
module.exports = { config };
` + filler;

async function runTests() {
  console.log('[Test 1] Scanning crypto-miner signature...');
  const result1 = await detector.scanModule('test-crypto', cryptoContent);
  console.log(`Result: ${JSON.stringify(result1, null, 2)}\n`);

  // Test 2: Clean module
  const cleanContent = `
module.exports = { data: 'clean' };
` + filler;

  console.log('[Test 2] Scanning clean module...');
  const result2 = await detector.scanModule('test-clean', cleanContent);
  console.log(`Result: ${JSON.stringify(result2, null, 2)}\n`);

  // Test 3: Obfuscation detection
  const obfuscatedContent = `
const encoded = Buffer.from('aWYo');
eval(encoded.toString());
` + filler;

  console.log('[Test 3] Scanning obfuscated module...');
  const result3 = await detector.scanModule('test-obfuscated', obfuscatedContent);
  console.log(`Result: ${JSON.stringify(result3, null, 2)}\n`);

  // Test 4: Dynamic code execution
  const dynamicContent = `
new Function('eval(Buffer.from("malicious").toString())')();
` + filler;

  console.log('[Test 4] Scanning dynamic code execution...');
  const result4 = await detector.scanModule('test-dynamic', dynamicContent);
  console.log(`Result: ${JSON.stringify(result4, null, 2)}\n`);

  console.log('[Detector Unit Test] ✅ All detection tests complete.');
}

runTests();
