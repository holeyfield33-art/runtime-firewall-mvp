const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const BENCH_DIR = path.join(__dirname, 'relative-bench');

// Clean cleanup if a previous run crashed
if (fs.existsSync(BENCH_DIR)) {
  fs.rmSync(BENCH_DIR, { recursive: true, force: true });
}
fs.mkdirSync(BENCH_DIR, { recursive: true });

// Generate a cleanly chained, nested module architecture
function generateChain(suffix) {
  let firstFile = '';
  const totalModules = 300; // Increase module count to dampen subprocess startup variance
  
  for (let i = 0; i < totalModules; i++) {
    const currentPath = path.join(BENCH_DIR, `mod_${suffix}_${i}.js`);
    if (i === 0) firstFile = currentPath;
    
    const nextImport = i === (totalModules - 1) 
      ? '' 
      : `require('./mod_${suffix}_${i + 1}.js');`;
      
    fs.writeFileSync(currentPath, `${nextImport}\nmodule.exports = { id: ${i} };`, 'utf8');
  }
  return firstFile;
}

console.log('⏱️  Running Statistical Dual-Process Performance Gate (30 iterations)...\n');

const iterations = 30;
const results = [];

for (let i = 0; i < iterations; i++) {
  // Recreate BENCH_DIR for each iteration
  if (fs.existsSync(BENCH_DIR)) {
    fs.rmSync(BENCH_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(BENCH_DIR, { recursive: true });

  const baseEntry = generateChain(`base_${i}`);
  const instEntry = generateChain(`inst_${i}`);

  // Pass 1: Baseline Native Process Execution
  const startBase = process.hrtime.bigint();
  execSync(`node ${baseEntry}`, { stdio: 'ignore' });
  const endBase = process.hrtime.bigint();
  const tBase = Number(endBase - startBase) / 1e6;

  // Pass 2: Agent-Instrumented Isolated Process Execution
  const agentPath = path.join(__dirname, '../../fw-agent/index.js');
  const startInst = process.hrtime.bigint();
  execSync(`node -r ${agentPath} ${instEntry}`, { stdio: 'ignore' });
  const endInst = process.hrtime.bigint();
  const tInst = Number(endInst - startInst) / 1e6;

  // Clean up sandbox for this iteration
  fs.rmSync(BENCH_DIR, { recursive: true, force: true });

  const overheadPercent = ((tInst - tBase) / tBase) * 100;
  results.push(overheadPercent);
  
  console.log(`[Iteration ${i + 1}] Baseline: ${tBase.toFixed(2)}ms | Agent: ${tInst.toFixed(2)}ms | Overhead: ${overheadPercent.toFixed(2)}%`);
}

// Statistical Analysis
results.sort((a, b) => a - b);
const median = results[Math.floor(results.length / 2)];
const p95Index = Math.floor(results.length * 0.95);
const p95 = results[p95Index];
const mean = results.reduce((a, b) => a + b, 0) / results.length;

console.log(`\n[Statistics] Mean: ${mean.toFixed(2)}% | Median: ${median.toFixed(2)}% | P95: ${p95.toFixed(2)}%`);
console.log(`[Distribution] Min: ${results[0].toFixed(2)}% | Max: ${results[results.length - 1].toFixed(2)}%`);

if (p95 > 10.0) {
  console.error(`\n❌ BUILD FAILED: P95 performance overhead exceeds strict 10% budget boundary.`);
  process.exit(1);
}

console.log('\n✅ BUILD PASSED: Statistical overhead is within strict guardrails.');
