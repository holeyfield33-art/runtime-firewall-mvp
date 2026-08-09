#!/usr/bin/env node
// Coordinator harness that runs lightweight probes and writes a single JSON artifact.
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const SAMPLES = Number(process.env.PROBE_SAMPLES) || 20;
const WARMUPS = 2;
const timestamp = Date.now();
const outDir = path.join(process.cwd(), 'results', 'benchmarks', 'probes');
try { fs.mkdirSync(outDir, { recursive: true }); } catch (e) {}
const outFile = path.join(outDir, `probe-${timestamp}.json`);

function runChild(probe, arg) {
  const args = [path.join(__dirname, 'probe-child.js'), probe];
  if (arg) args.push(arg);
  // write child JSON to a temp file to avoid stdout/stderr mixing with agent logs
  const outFile = path.join(os.tmpdir(), `probe-out-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const env = Object.assign({}, process.env, { PROBE_OUTFILE: outFile });
  const res = spawnSync(process.execPath, args, { encoding: 'utf8', env, timeout: 120000 });
  let fileOut = null;
  try { fileOut = fs.readFileSync(outFile, 'utf8').trim(); } catch (e) { fileOut = null; }
  try { fs.unlinkSync(outFile); } catch (e) {}
  return { status: res.status, stdout: res.stdout && res.stdout.trim(), stderr: res.stderr && res.stderr.trim(), fileOut };
}

function parseChildOut(o) {
  if (!o) return { status: 'error', reason: 'no-output' };
  const firstLine = o.split(/\r?\n/)[0];
  try { return JSON.parse(firstLine); } catch (e) { return { status: 'error', reason: 'bad-json', raw: firstLine }; }
}

function statsFromSamples(samples) {
  const numeric = samples.filter(x => typeof x === 'number' && !Number.isNaN(x)).slice().sort((a,b)=>a-b);
  const n = numeric.length;
  if (!n) return { count: 0 };
  const sum = numeric.reduce((s,v)=>s+v,0);
  const mean = sum / n;
  const min = numeric[0];
  const max = numeric[n-1];
  const median = (n%2)? numeric[Math.floor(n/2)] : (numeric[n/2-1]+numeric[n/2])/2;
  const percentile = (p) => {
    const rank = Math.ceil((p/100)*n);
    return numeric[Math.max(0, Math.min(n-1, rank-1))];
  };
  const p95 = percentile(95);
  const p99 = percentile(99);
  const variance = numeric.reduce((acc,v)=>acc+Math.pow(v-mean,2),0)/n;
  const stddev = Math.sqrt(variance);
  return { count: n, mean, median, p95, p99, min, max, stddev };
}

const probeDefs = [
  { id: 'node-startup' },
  { id: 'agent-preload' },
  { id: 'agent-initialization' },
  { id: 'integrity-verification' },
  { id: 'policy-verification' },
  { id: 'detector-construction' },
  { id: 'hook-installation' },
  { id: 'audit-initialization' },
  { id: 'telemetry-initialization' },
  // module-scan will be handled specially per sample type
  { id: 'module-scan', variants: ['tiny','med','large'] },
  { id: 'process-shutdown' }
];

const results = { metadata: {}, probes: {} };

// metadata
results.metadata = {
  benchmarkVersion: 'probe-v1',
  gitSha: (() => { try { const g = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }); return g.status===0? g.stdout.trim(): null;} catch(e){return null;} })(),
  package: (() => { try { const pj = require(path.join(process.cwd(), 'packages', 'fw-agent', 'package.json')); return { name: pj.name || null, version: pj.version || null }; } catch(e){ return { name: null, version: null }; } })(),
  nodeVersion: process.version,
  npmVersion: (() => { try { const n = spawnSync('npm', ['--version'], { encoding: 'utf8' }); return n.status===0? n.stdout.trim(): null; } catch(e){ return null; } })(),
  platform: process.platform,
  arch: process.arch,
  cpu: (() => { try { const c = os.cpus(); return { model: c[0].model, cores: c.length }; } catch(e){ return null; } })(),
  memoryBytes: os.totalmem(),
  timestamp: new Date().toISOString()
};

// run helper for a probe id
function collectProbe(probeId) {
  const rec = { status: 'measured', samplesMs: [], raw: [], statistics: {} };
  // Special-case node-startup: measure spawn time in parent
  if (probeId === 'node-startup') {
    for (let w = 0; w < WARMUPS; w++) {
      spawnSync(process.execPath, ['-e', 'process.exit(0)'], { encoding: 'utf8', timeout: 10000 });
    }
    for (let i = 0; i < SAMPLES; i++) {
      const t0 = process.hrtime.bigint();
      const r = spawnSync(process.execPath, ['-e', 'process.exit(0)'], { encoding: 'utf8', timeout: 10000 });
      const t1 = process.hrtime.bigint();
      const elapsed = Number(t1 - t0) / 1e6;
      rec.raw.push({ status: 'measured', elapsedMs: elapsed });
      rec.samplesMs.push(elapsed);
    }
    rec.statistics = statsFromSamples(rec.samplesMs);
    return rec;
  }

  // warmups
  for (let w = 0; w < WARMUPS; w++) runChild(probeId);
  for (let i = 0; i < SAMPLES; i++) {
    const r = runChild(probeId);
    const parsed = parseChildOut(r.fileOut || r.stderr || r.stdout);
    rec.raw.push(parsed);
    if (parsed && parsed.status === 'measured' && typeof parsed.elapsedMs === 'number') {
      rec.samplesMs.push(parsed.elapsedMs);
    } else if (parsed && parsed.status === 'measured' && typeof parsed.elapsedMs === 'string') {
      const n = Number(parsed.elapsedMs);
      if (!Number.isNaN(n)) rec.samplesMs.push(n);
    } else {
      rec.status = parsed && parsed.status || 'error';
    }
  }
  rec.statistics = statsFromSamples(rec.samplesMs);
  return rec;
}

// module-scan variants
const filter = process.env.PROBE_FILTER ? process.env.PROBE_FILTER.split(',').map(s=>s.trim()) : null;
for (const def of probeDefs) {
  if (def.id === 'module-scan') continue;
  if (filter && !filter.includes(def.id)) continue;
  results.probes[def.id] = collectProbe(def.id);
}

// handle module-scan per variant
results.probes['module-scan'] = {};
for (const v of ['tiny','med','large']) {
  // warmups
  if (filter && !filter.includes('module-scan')) continue;
  for (let w=0; w<WARMUPS; w++) runChild('module-scan', v);
  const samples = [];
  const raw = [];
  for (let i=0;i<SAMPLES;i++) {
    const out = runChild('module-scan', v);
    const parsed = parseChildOut(out.stderr);
    raw.push(parsed);
    if (parsed && parsed.status==='measured' && typeof parsed.elapsedMs==='number') samples.push(parsed.elapsedMs);
  }
  results.probes['module-scan'][v] = { status: 'measured', samplesMs: samples, raw: raw, statistics: statsFromSamples(samples) };
}

// For any probe that produced no numeric samples, mark not-measurable
for (const [k, v] of Object.entries(results.probes)) {
  if (!v) continue;
  if (v.status === 'measured' && (!v.samplesMs || v.samplesMs.length === 0)) {
    v.status = 'not-measurable';
    v.reason = 'no-numeric-samples';
  }
}

try {
  fs.writeFileSync(outFile, JSON.stringify(results, null, 2), 'utf8');
  console.log('[Probe] Wrote results to', outFile);
} catch (e) {
  console.error('[Probe] Failed to write results:', e && e.message);
  process.exit(2);
}
