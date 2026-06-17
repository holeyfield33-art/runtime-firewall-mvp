// test/bench-honest.js
//
// Honest module-load overhead benchmark for aletheia-firewall.
//
// WHY THIS EXISTS
// ---------------
// Earlier benchmarks reported the agent as "below noise floor" or even
// FASTER than no agent. Both were artifacts:
//   (a) the benchmark required (preloaded) the very modules it then timed,
//       so the firewall's scan ran against an already-warm require cache;
//   (b) whole-app wall-clock was dominated by process-spawn jitter.
//
// The firewall's real cost is a ONE-TIME, per-file signature scan inside the
// Module.prototype._compile hook (see index.js). It runs once per module the
// first time that module is compiled, then verifiedCompilationsCache
// short-circuits it. So the honest thing to measure is:
//
//   fresh process  ->  load N user modules the agent did NOT preload
//                  ->  compare firewall-on vs firewall-off
//
// This script is the ORCHESTRATOR. It spawns fresh child processes (cold
// caches) for each arm, runs several trials, and reports median per-module
// overhead. It writes a provenance line + results to stdout so the caller can
// tee it into a results file.

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const AGENT_ENTRY = path.resolve(__dirname, '..', 'index.js');
const MODULE_COUNT = 200;   // user modules generated per run
const TRIALS = 7;           // fresh-process trials per arm; median is reported

// ── Generate a tree of distinct, non-trivial user modules in a temp dir ───────
// Distinct content per file defeats any single-file cache and gives the
// signature scanner realistic, varied input to chew on.
function makeModuleTree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-bench-'));
  for (let i = 0; i < MODULE_COUNT; i++) {
    // ~40 lines of benign, varied code per module.
    const lines = [`// generated module ${i}`];
    for (let j = 0; j < 40; j++) {
      lines.push(`const v${j}_${i} = ${i} * ${j} + Math.sqrt(${j + 1});`);
    }
    lines.push(`module.exports = { id: ${i}, sum: ${i * 40} };`);
    fs.writeFileSync(path.join(dir, `mod${i}.js`), lines.join('\n'));
  }
  return dir;
}

// ── The child worker, written as a self-contained script run in a fresh proc ──
// It requires the firewall FIRST (when enabled), then times requiring the N
// user modules. The user modules are NOT preloaded by us, so the scan cost is
// paid for real, on a cold cache.
// The agent prints an "[Helios] Exit 0 ..." summary to stdout on exit, so we
// cannot use stdout to return the timing. The child writes JSON to a file.
function childSource(moduleDir, enabled, outFile) {
  return `
'use strict';
const path = require('path');
const fs = require('fs');
${enabled ? `process.env.FW_ENABLE_DETECTION = '1'; require(${JSON.stringify(AGENT_ENTRY)});` : ``}
const dir = ${JSON.stringify(moduleDir)};
const n = ${MODULE_COUNT};
const start = process.hrtime.bigint();
for (let i = 0; i < n; i++) {
  require(path.join(dir, 'mod' + i + '.js'));
}
const end = process.hrtime.bigint();
const totalMs = Number(end - start) / 1e6;
fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ totalMs, perModuleMs: totalMs / n }));
`;
}

function runArm(moduleDir, enabled) {
  const outFile = path.join(os.tmpdir(), `fw-bench-out-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  const src = childSource(moduleDir, enabled, outFile);
  const res = spawnSync(process.execPath, ['-e', src], { encoding: 'utf8' });
  if (res.status !== 0) {
    throw new Error(
      `child failed (enabled=${enabled}): ${res.stderr || res.stdout || 'unknown'}`
    );
  }
  const parsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  fs.rmSync(outFile, { force: true });
  return parsed;
}

function median(nums) {
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

function main() {
  // Provenance: anyone reading the results must know where they came from.
  console.log(
    `# aletheia-firewall bench-honest | node ${process.version} | ` +
    `${process.platform} ${process.arch} | ${os.cpus()[0].model} | ` +
    `${MODULE_COUNT} modules x ${TRIALS} trials | ${new Date().toISOString()}`
  );

  const moduleDir = makeModuleTree();
  try {
    const baseline = [];
    const instrumented = [];
    // Interleave arms so any thermal/scheduler drift hits both equally.
    for (let t = 0; t < TRIALS; t++) {
      baseline.push(runArm(moduleDir, false).perModuleMs);
      instrumented.push(runArm(moduleDir, true).perModuleMs);
    }

    const bMed = median(baseline);
    const iMed = median(instrumented);
    const deltaMs = iMed - bMed;
    const pct = (deltaMs / bMed) * 100;

    console.log(`baseline    median: ${bMed.toFixed(4)} ms/module`);
    console.log(`firewall-on median: ${iMed.toFixed(4)} ms/module`);
    console.log(`overhead          : +${deltaMs.toFixed(4)} ms/module (+${pct.toFixed(1)}%)`);
    console.log(`note: one-time per-module startup cost (scan runs once per file, then cached)`);
  } finally {
    fs.rmSync(moduleDir, { recursive: true, force: true });
  }
}

main();
