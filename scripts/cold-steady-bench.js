#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const SAMPLES = Number(process.env.COLD_STEADY_SAMPLES) || 20;
const WARMUPS = Number(process.env.COLD_STEADY_WARMUPS) || 5;
const moduleCounts = [10, 100, 900];
const outDir = path.join(process.cwd(), 'results', 'benchmarks');
fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, `cold-steady-${Date.now()}.json`);

function stats(samples) {
  const numeric = samples.filter(x => typeof x === 'number' && !Number.isNaN(x)).slice().sort((a,b)=>a-b);
  const n = numeric.length;
  const sum = numeric.reduce((a,v)=>a+v,0);
  const mean = n ? sum/n : 0;
  const min = n ? numeric[0] : 0;
  const max = n ? numeric[n-1] : 0;
  const median = n ? (n%2 ? numeric[(n-1)/2] : (numeric[n/2-1] + numeric[n/2])/2) : 0;
  const quantile = p => {
    if (!n) return 0;
    const rank = Math.ceil((p/100)*n);
    return numeric[Math.max(0, Math.min(n-1, rank-1))];
  };
  return { count: n, mean, median, p95: quantile(95), p99: quantile(99), min, max };
}

const agentPath = path.join(process.cwd(), 'packages', 'fw-agent', 'index.js');

function sanitizeEnv(envExtras) {
  const env = Object.assign({}, process.env);
  if (envExtras) {
    for (const [key, value] of Object.entries(envExtras)) {
      if (value === undefined) {
        delete env[key];
      } else {
        env[key] = value;
      }
    }
  }
  return env;
}

function runChild(mode, count, iterations, warmups, envExtras, preloadAgent) {
  const childPath = path.join(__dirname, 'cold-steady-bench-child.js');
  const childOut = path.join(os.tmpdir(), `cold-steady-${process.pid}-${mode}-${count}-${Date.now()}.json`);
  const env = sanitizeEnv(Object.assign({ COLD_STEADY_BENCH_OUTFILE: childOut }, envExtras));
  const args = [];
  if (preloadAgent) {
    args.push(`--require=${agentPath}`);
  }
  args.push(childPath, mode, String(count));
  if (mode === 'steady') {
    args.push(String(iterations));
    args.push(String(warmups));
  }
  const res = spawnSync(process.execPath, args, { encoding: 'utf8', env, timeout: 120000 });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`child exit ${res.status} stderr=${res.stderr}`);
  }
  try {
    const raw = fs.readFileSync(childOut, 'utf8');
    return JSON.parse(raw);
  } finally {
    try { fs.unlinkSync(childOut); } catch (e) {}
  }
}

function collectCold(mode, count, envExtras, preloadAgent) {
  const samples = [];
  for (let i = 0; i < SAMPLES; i += 1) {
    const t0 = process.hrtime.bigint();
    const child = runChild('cold', count, 0, 0, envExtras, preloadAgent);
    const t1 = process.hrtime.bigint();
    const elapsed = Number(t1 - t0) / 1e6;
    samples.push(elapsed);
  }
  return { samples, statistics: stats(samples) };
}

function collectSteady(count, envExtras, preloadAgent) {
  const child = runChild('steady', count, SAMPLES, WARMUPS, envExtras, preloadAgent);
  return child;
}

function makeMetadata() {
  const gitSha = (() => {
    try { const g = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }); return g.status===0 ? g.stdout.trim() : null; } catch (e) { return null; }
  })();
  const packageJson = require(path.join(process.cwd(), 'packages', 'fw-agent', 'package.json'));
  return {
    benchmarkVersion: 'cold-steady-v1',
    gitSha,
    package: { name: packageJson.name, version: packageJson.version },
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpu: (() => { try { const cp = os.cpus(); return { model: cp[0].model, cores: cp.length }; } catch (e) { return null; } })(),
    memoryBytes: os.totalmem(),
    timestamp: new Date().toISOString(),
    env: {
      COLD_STEADY_SAMPLES: SAMPLES,
      COLD_STEADY_WARMUPS: WARMUPS,
    }
  };
}

const metadata = makeMetadata();
const cold_start = {};
const steady_state = {};
const workloads = {};

for (const count of moduleCounts) {
  const baselineCold = collectCold('cold', count, { FW_ENABLE_DETECTION: undefined }, false);
  const agentCold = collectCold('cold', count, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, true);
  const baselineSteady = collectSteady(count, { FW_ENABLE_DETECTION: undefined }, false);
  const agentSteady = collectSteady(count, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, true);

  function sampleArray(measurement) {
    return measurement.samples || measurement.rawSamplesMs || [];
  }

  function computeOverhead(baseline, agent) {
    const baselineSamples = sampleArray(baseline);
    const agentSamples = sampleArray(agent);
    const raw = agentSamples.map((v, i) => {
      const b = baselineSamples[i];
      return b > 0 ? ((v - b) / b) * 100 : null;
    });
    const numeric = raw.filter(x => typeof x === 'number');
    const sorted = numeric.slice().sort((a,b)=>a-b);
    const n = sorted.length;
    const pct = x => sorted[Math.max(0, Math.min(n-1, Math.ceil((x/100)*n)-1))];
    return {
      raw,
      statistics: {
        mean: numeric.reduce((a,v)=>a+v,0)/n,
        median: pct(50),
        p95: pct(95),
        p99: pct(99),
        min: sorted[0],
        max: sorted[n-1],
      }
    };
  }

  cold_start[count] = {
    baseline: baselineCold,
    agent: agentCold,
    overhead: computeOverhead(baselineCold, agentCold),
  };
  steady_state[count] = {
    baseline: baselineSteady,
    agent: agentSteady,
    overhead: computeOverhead(baselineSteady, agentSteady),
  };
  workloads[count] = {
    moduleCount: count,
    inputBytes: agentCold.samples.length ? null : null,
  };
}

const result = { metadata, cold_start, steady_state, workloads };
fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf8');
console.log('Wrote benchmark artifact to', outFile);
