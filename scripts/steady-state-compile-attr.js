#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const counts = [100, 900];
const iterations = Number(process.env.STEADY_STATE_ATTR_ITERATIONS) || 20;
const warmups = Number(process.env.STEADY_STATE_ATTR_WARMUPS) || 5;
const outDir = path.join(process.cwd(), 'results', 'benchmarks');
fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, `steady-state-compile-attr-${Date.now()}.json`);
const childScript = path.join(__dirname, 'steady-state-compile-attr-child.js');
const agentPath = path.join(process.cwd(), 'packages', 'fw-agent', 'index.js');

function sanitizeEnv(envExtras) {
  const env = Object.assign({}, process.env);
  Object.assign(env, envExtras);
  return env;
}

function runChild(mode, count) {
  const tmpFile = path.join(os.tmpdir(), `steady-state-compile-attr-${process.pid}-${mode}-${count}-${Date.now()}.json`);
  const env = sanitizeEnv({
    STEADY_STATE_ATTR_OUTFILE: tmpFile,
    FW_ALLOW_DEV_POLICY_KEY: '1',
    FW_ENABLE_DETECTION: mode === 'baseline' ? undefined : '1',
  });

  const args = [];
  if (mode !== 'baseline') {
    args.push(`--require=${agentPath}`);
  }
  args.push(childScript, mode, String(count), String(iterations), String(warmups));

  const res = spawnSync(process.execPath, args, { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`child exit ${res.status} stdout=${res.stdout} stderr=${res.stderr}`);
  }

  try {
    const raw = fs.readFileSync(tmpFile, 'utf8');
    return JSON.parse(raw);
  } finally {
    try { fs.unlinkSync(tmpFile); } catch (e) {}
  }
}

function stats(samples) {
  const numeric = samples.filter(x => typeof x === 'number' && !Number.isNaN(x)).slice().sort((a,b)=>a-b);
  if (!numeric.length) return { count: 0 };
  const n = numeric.length;
  const mean = numeric.reduce((sum,v)=>sum+v,0)/n;
  const median = n%2 ? numeric[(n-1)/2] : (numeric[n/2-1]+numeric[n/2])/2;
  const quantile = p => numeric[Math.max(0, Math.min(n-1, Math.ceil((p/100)*n)-1))];
  return { count: n, mean, median, p95: quantile(95), p99: quantile(99), min: numeric[0], max: numeric[n-1] };
}

function collectWorkload(count) {
  const baseline = runChild('baseline', count);
  const hookOnly = runChild('hook-only', count);
  const hookScan = runChild('hook-scan', count);

  const overhead = (base, target) => {
    if (!base || !target || !base.rawSamplesMs || !target.rawSamplesMs) return null;
    const baseSamples = base.rawSamplesMs;
    const targetSamples = target.rawSamplesMs;
    const paired = Math.min(baseSamples.length, targetSamples.length);
    const raw = [];
    for (let i = 0; i < paired; i += 1) {
      const b = baseSamples[i];
      const t = targetSamples[i];
      if (typeof b === 'number' && typeof t === 'number' && b > 0) {
        raw.push((t - b) / b * 100);
      }
    }
    return { raw, statistics: stats(raw) };
  };

  return {
    count,
    baseline,
    hookOnly,
    hookScan,
    overheadHook: overhead(baseline, hookOnly),
    overheadScan: overhead(hookOnly, hookScan),
    overheadTotal: overhead(baseline, hookScan),
  };
}

function main() {
  const results = { metadata: {}, workloads: [], timestamp: new Date().toISOString(), nodeVersion: process.version };
  results.metadata = {
    benchmarkVersion: 'steady-state-compile-attr-v1',
    gitSha: (() => { try { const out = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }); return out.status === 0 ? out.stdout.trim() : null; } catch (e) { return null; } })(),
    platform: process.platform,
    arch: process.arch,
    cpu: (() => { try { const cpus = require('os').cpus(); return cpus && cpus[0] ? { model: cpus[0].model, cores: cpus.length } : null; } catch (e) { return null; } })(),
    iterations,
    warmups,
  };

  for (const count of counts) {
    results.workloads.push(collectWorkload(count));
  }

  fs.writeFileSync(outFile, JSON.stringify(results, null, 2), 'utf8');
  console.log('Wrote steady-state compile attribution artifact to', outFile);
}

main();
