const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { execSync, spawnSync } = require('child_process');

const ITER = 60;
const MEDIAN_OF = 5;
const CHAIN_LEN = 10;        // depth of each chain (10 levels)
const NUM_CHAINS = 90;       // 90 chains * 10 deep = 900 modules total (same as flat test)

async function generateDeepCorpus(baseDir) {
  console.log(`[Gen] Deep nesting corpus (${NUM_CHAINS} chains, depth ${CHAIN_LEN}) in ${baseDir}`);
  await fs.mkdir(baseDir, { recursive: true });

  for (let c = 0; c < NUM_CHAINS; c++) {
    const chainDir = path.join(baseDir, `chain_${c}`);
    await fs.mkdir(chainDir, { recursive: true });

    // Create modules from depth 0 (leaf) up to depth CHAIN_LEN-1 (root)
    // Leaf (deepest) has no require
    for (let d = CHAIN_LEN - 1; d >= 0; d--) {
      const fileName = `mod_${d}.js`;
      const filePath = path.join(chainDir, fileName);
      let content = `// depth ${d}\n`;
      if (d === CHAIN_LEN - 1) {
        content += `module.exports = { depth: ${d}, id: 'leaf_${c}' };\n`;
      } else {
        // Require the deeper module (d+1) – same directory
        content += `const deeper = require('./mod_${d+1}.js');\n`;
        content += `module.exports = { depth: ${d}, child: deeper };\n`;
      }
      await fs.writeFile(filePath, content);
    }
    // Also create an entry point that requires depth 0
    const entryPath = path.join(chainDir, 'index.js');
    await fs.writeFile(entryPath, `module.exports = require('./mod_0.js');\n`);
  }

  // Create a master entry that loads all chains (to force traversal)
  let masterContent = '';
  for (let c = 0; c < NUM_CHAINS; c++) {
    masterContent += `require('./chain_${c}/index.js');\n`;
  }
  await fs.writeFile(path.join(baseDir, 'master.js'), masterContent);
  console.log(`[Gen] Done.`);
}

async function runBench() {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'fw-bench-k2-'));
  const agentPath = path.resolve(__dirname, '../../fw-agent/index.js');

  console.log(`\n⏱️ Running K=2 Deep Nesting Benchmark (${ITER} iters, median-of-${MEDIAN_OF})`);
  console.log(`Temp dir: ${tmpDir}`);
  console.log(`Agent: ${agentPath}`);
  console.log(`Corpus: ${NUM_CHAINS} chains, depth ${CHAIN_LEN}\n`);

  await generateDeepCorpus(tmpDir);

  const results = { baseline: [], agent: [] };

  for (let iter = 1; iter <= ITER; iter++) {
    // Baseline: agent loaded but FW=0 (hook disabled)
    const baselineTimes = [];
    for (let m = 0; m < MEDIAN_OF; m++) {
      const start = Date.now();
      spawnSync('node', ['-r', agentPath, path.join(tmpDir, 'master.js')], {
        env: { ...process.env, FW_ENABLE_DETECTION: '0' },
        stdio: 'ignore',
      });
      baselineTimes.push(Date.now() - start);
    }
    const baselineMed = median(baselineTimes);

    // Agent: FW enabled
    const agentTimes = [];
    for (let m = 0; m < MEDIAN_OF; m++) {
      const start = Date.now();
      spawnSync('node', ['-r', agentPath, path.join(tmpDir, 'master.js')], {
        env: { ...process.env, FW_ENABLE_DETECTION: '1' },
        stdio: 'ignore',
      });
      agentTimes.push(Date.now() - start);
    }
    const agentMed = median(agentTimes);

    const delta = agentMed - baselineMed;
    const pct = (delta / baselineMed) * 100;
    results.baseline.push(baselineMed);
    results.agent.push(agentMed);

    if (iter % 10 === 0 || iter === 1 || iter === ITER) {
      console.log(`[Iter ${iter.toString().padStart(3)}] Baseline: ${baselineMed.toFixed(2)}ms | Agent: ${agentMed.toFixed(2)}ms | Delta: ${delta.toFixed(2)}ms | Overhead: ${pct.toFixed(2)}%`);
    }
  }

  // Stats
  const overheads = results.baseline.map((b, i) => ((results.agent[i] - b) / b) * 100);
  const mean = overheads.reduce((a,b)=>a+b,0)/overheads.length;
  const medianOv = median(overheads);
  const sorted = [...overheads].sort((a,b)=>a-b);
  const p95 = sorted[Math.floor(sorted.length * 0.95)];

  console.log(`\n[Absolute Metrics] Mean Baseline: ${meanArray(results.baseline).toFixed(2)}ms | Mean Agent: ${meanArray(results.agent).toFixed(2)}ms | Mean Delta: ${(meanArray(results.agent)-meanArray(results.baseline)).toFixed(2)}ms`);
  console.log(`[Statistics] Mean: ${mean.toFixed(2)}% | Median: ${medianOv.toFixed(2)}% | P95: ${p95.toFixed(2)}%`);
  console.log(`[Distribution] Min: ${Math.min(...overheads).toFixed(2)}% | Max: ${Math.max(...overheads).toFixed(2)}%`);

  const pass = medianOv < 5 && p95 < 20;
  if (pass) {
    console.log(`\n✅ K=2 PASS: Median ${medianOv.toFixed(2)}% <5%, P95 ${p95.toFixed(2)}% <20%`);
  } else {
    console.log(`\n❌ K=2 FAIL: Median ${medianOv.toFixed(2)}% (max 5%) or P95 ${p95.toFixed(2)}% (max 20%) exceeded`);
  }

  await fs.rm(tmpDir, { recursive: true, force: true });
}

function median(arr) {
  const sorted = [...arr].sort((a,b)=>a-b);
  const mid = Math.floor(sorted.length/2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid-1]+sorted[mid])/2;
}

function meanArray(arr) {
  return arr.reduce((a,b)=>a+b,0)/arr.length;
}

runBench().catch(console.error);