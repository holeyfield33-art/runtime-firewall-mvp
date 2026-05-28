/**
 * Direct Module._load Hook Microbenchmark
 * 
 * Measures the actual cost of the fw-agent hook on Module._load
 * without subprocess startup/GC/OS scheduler noise.
 * 
 * Methodology:
 * - Load fw-agent into process
 * - Require many modules while timing hook invocations
 * - Calculate mean latency per require() call
 * - Compare to baseline (same module loads without agent)
 */

const Module = require('module');
const path = require('path');
const fs = require('fs');

const BENCH_DIR = path.join(__dirname, 'hook-bench');
const MODULE_COUNT = 500; // Load 500 modules per iteration

// Clean setup
if (fs.existsSync(BENCH_DIR)) {
  fs.rmSync(BENCH_DIR, { recursive: true, force: true });
}
fs.mkdirSync(BENCH_DIR, { recursive: true });

// Generate isolated modules
function generateModules() {
  for (let i = 0; i < MODULE_COUNT; i++) {
    const filePath = path.join(BENCH_DIR, `mod_${i}.js`);
    fs.writeFileSync(filePath, `module.exports = { id: ${i}, value: "test_${i}" };`, 'utf8');
  }
}

console.log('📊 Direct Module._load Hook Microbenchmark\n');

// Test 1: Baseline (no agent)
console.log('=== BASELINE (No Firewall Agent) ===');
generateModules();

const baselineIterations = 3;
const baselineResults = [];

for (let iter = 0; iter < baselineIterations; iter++) {
  // Clear require cache between iterations
  Object.keys(require.cache).forEach(key => {
    if (key.includes(BENCH_DIR)) {
      delete require.cache[key];
    }
  });

  const startBase = process.hrtime.bigint();
  for (let i = 0; i < MODULE_COUNT; i++) {
    const modPath = path.join(BENCH_DIR, `mod_${i}.js`);
    require(modPath);
  }
  const endBase = process.hrtime.bigint();
  
  const totalMs = Number(endBase - startBase) / 1e6;
  const perModuleUs = (totalMs * 1000) / MODULE_COUNT;
  
  baselineResults.push(perModuleUs);
  console.log(`Iteration ${iter + 1}: ${totalMs.toFixed(2)}ms total | ${perModuleUs.toFixed(3)}µs per module`);
}

const baselineMean = baselineResults.reduce((a, b) => a + b) / baselineResults.length;

// Test 2: With agent
console.log('\n=== WITH FIREWALL AGENT ===');
generateModules();

// Load the agent
require('../../fw-agent/index.js');

const agentIterations = 3;
const agentResults = [];

for (let iter = 0; iter < agentIterations; iter++) {
  // Clear require cache between iterations
  Object.keys(require.cache).forEach(key => {
    if (key.includes(BENCH_DIR)) {
      delete require.cache[key];
    }
  });

  const startAgent = process.hrtime.bigint();
  for (let i = 0; i < MODULE_COUNT; i++) {
    const modPath = path.join(BENCH_DIR, `mod_${i}.js`);
    require(modPath);
  }
  const endAgent = process.hrtime.bigint();
  
  const totalMs = Number(endAgent - startAgent) / 1e6;
  const perModuleUs = (totalMs * 1000) / MODULE_COUNT;
  
  agentResults.push(perModuleUs);
  console.log(`Iteration ${iter + 1}: ${totalMs.toFixed(2)}ms total | ${perModuleUs.toFixed(3)}µs per module`);
}

const agentMean = agentResults.reduce((a, b) => a + b) / agentResults.length;

// Analysis
console.log('\n=== ANALYSIS ===');
console.log(`Baseline mean: ${baselineMean.toFixed(3)}µs per module`);
console.log(`Agent mean:    ${agentMean.toFixed(3)}µs per module`);
const overhead = ((agentMean - baselineMean) / baselineMean) * 100;
console.log(`Overhead:      ${overhead.toFixed(2)}%`);

// Gate
if (overhead > 10) {
  console.log(`\n❌ FAILED: Hook overhead ${overhead.toFixed(2)}% exceeds 10% budget`);
  process.exit(1);
} else if (overhead > 0) {
  console.log(`\n⚠️  MARGINAL: Hook overhead ${overhead.toFixed(2)}% within budget but not zero-cost`);
  process.exit(0);
} else {
  console.log(`\n✅ PASSED: Hook is negative overhead (agent actually faster)`);
  process.exit(0);
}
