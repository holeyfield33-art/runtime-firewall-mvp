#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const Module = require('module');
const crypto = require('crypto');

function nowNs() { return process.hrtime.bigint(); }
function hrToMs(start, end) { return Number(end - start) / 1e6; }
function stats(samples) {
  const numeric = samples.filter(x => typeof x === 'number' && !Number.isNaN(x)).slice().sort((a, b) => a - b);
  const n = numeric.length;
  if (!n) return { count: 0, mean: 0, median: 0, p95: 0, p99: 0, min: 0, max: 0, stddev: 0 };
  const mean = numeric.reduce((s, v) => s + v, 0) / n;
  const median = n % 2 ? numeric[(n - 1) / 2] : (numeric[n / 2 - 1] + numeric[n / 2]) / 2;
  const quantile = p => numeric[Math.max(0, Math.min(n - 1, Math.ceil((p / 100) * n) - 1))];
  const variance = numeric.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / n;
  return { count: n, mean, median, p95: quantile(95), p99: quantile(99), min: numeric[0], max: numeric[n - 1], stddev: Math.sqrt(variance) };
}

function buildSource(index) {
  const tiny = 'const x=1;module.exports=x;\n';
  const med = 'const x=1;const y=x+2;const z=y*3;module.exports={x,y,z};\n';
  const large = ('1+2+3+4+5+6+7+8+9+10;'.repeat(80) + '\n') +
    'const x=1;const y=x+2;const z=y*3;const w=z+4;const v=w*w;module.exports={x,y,z,w,v};\n';
  if (index % 3 === 0) return tiny;
  if (index % 3 === 1) return med;
  return large;
}

function buildSources(count) {
  const sources = [];
  for (let i = 0; i < count; i += 1) {
    sources.push({ filename: path.join('bench', `m${i}.js`), content: buildSource(i) });
  }
  return sources;
}

function makeMetadata() {
  return {
    benchmarkVersion: 'hook-cost-profile-v1',
    gitSha: (() => { try { const g = require('child_process').spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }); return g.status === 0 ? g.stdout.trim() : null; } catch (e) { return null; } })(),
    package: (() => { try { const pj = require(path.join(process.cwd(), 'packages', 'fw-agent', 'package.json')); return { name: pj.name, version: pj.version }; } catch (e) { return { name: null, version: null }; } })(),
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpu: (() => { try { const cpus = os.cpus(); return cpus && cpus[0] ? { model: cpus[0].model, cores: cpus.length } : null; } catch (e) { return null; } })(),
    memoryBytes: os.totalmem(),
    timestamp: new Date().toISOString(),
  };
}

function writeJson(out) {
  const outDir = path.join(process.cwd(), 'results', 'benchmarks');
  try { fs.mkdirSync(outDir, { recursive: true }); } catch (e) {}
  const outFile = path.join(outDir, `hook-cost-profile-${Date.now()}.json`);
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2), 'utf8');
  console.log('Wrote artifact:', outFile);
}

async function main() {
  const count = Number(process.argv[2] || '900');
  const iterations = Number(process.argv[3] || '20');
  const warmups = Number(process.argv[4] || '5');
  if (!Number.isInteger(count) || count <= 0) throw new Error('Invalid module count');
  if (!Number.isInteger(iterations) || iterations <= 0) throw new Error('Invalid iterations');
  if (!Number.isInteger(warmups) || warmups < 0) throw new Error('Invalid warmups');

  const sources = buildSources(count);
  const bytes = sources.reduce((sum, s) => sum + Buffer.byteLength(s.content, 'utf8'), 0);

  const stageNames = ['totalHook', 'reset', 'hash', 'scan', 'audit', 'originalCompile'];
  const iterationsData = [];
  let currentIteration = null;
  let stageAccumulators = null;

  const originalNodeCompile = Module.prototype._compile;
  Module.prototype._compile = function () {
    const t0 = nowNs();
    const result = originalNodeCompile.apply(this, arguments);
    const t1 = nowNs();
    if (currentIteration !== null) {
      stageAccumulators.originalCompile += hrToMs(t0, t1);
    }
    return result;
  };

  const Detector = require(path.join(process.cwd(), 'packages', 'fw-agent', 'src', 'detector')).Detector;
  const DetTrack = require(path.join(process.cwd(), 'packages', 'fw-agent', 'src', 'behavior-tracker')).BehaviorTracker;
  const AuditLog = require(path.join(process.cwd(), 'packages', 'fw-agent', 'src', 'audit-log')).AuditLog;

  if (Detector.prototype.scanModuleSync) {
    const detectorScan = Detector.prototype.scanModuleSync;
    Detector.prototype.scanModuleSync = function () {
      const t0 = nowNs();
      const result = detectorScan.apply(this, arguments);
      const t1 = nowNs();
      if (currentIteration !== null) stageAccumulators.scan += hrToMs(t0, t1);
      return result;
    };
  }
  
  if (DetTrack.prototype.reset) {
    const behaviorReset = DetTrack.prototype.reset;
    DetTrack.prototype.reset = function () {
      const t0 = nowNs();
      const result = behaviorReset.apply(this, arguments);
      const t1 = nowNs();
      if (currentIteration !== null) stageAccumulators.reset += hrToMs(t0, t1);
      return result;
    };
  }
  
  if (AuditLog.prototype.write) {
    const auditWrite = AuditLog.prototype.write;
    AuditLog.prototype.write = function () {
      const t0 = nowNs();
      const result = auditWrite.apply(this, arguments);
      const t1 = nowNs();
      if (currentIteration !== null) stageAccumulators.audit += hrToMs(t0, t1);
      return result;
    };
  }

  const originalCreateHash = crypto.createHash;
  crypto.createHash = function (algorithm, options) {
    const hash = originalCreateHash.call(this, algorithm, options);
    const originalUpdate = hash.update.bind(hash);
    const originalDigest = hash.digest.bind(hash);
    hash.update = function () {
      const t0 = nowNs();
      const result = originalUpdate.apply(this, arguments);
      const t1 = nowNs();
      if (currentIteration !== null) stageAccumulators.hash += hrToMs(t0, t1);
      return result;
    };
    hash.digest = function () {
      const t0 = nowNs();
      const result = originalDigest.apply(this, arguments);
      const t1 = nowNs();
      if (currentIteration !== null) stageAccumulators.hash += hrToMs(t0, t1);
      return result;
    };
    return hash;
  };

  require(path.join(process.cwd(), 'packages', 'fw-agent', 'index.js'));
  const agentHook = Module.prototype._compile;
  Module.prototype._compile = function () {
    const t0 = nowNs();
    const result = agentHook.apply(this, arguments);
    const t1 = nowNs();
    if (currentIteration !== null) stageAccumulators.totalHook += hrToMs(t0, t1);
    return result;
  };

  function compileSources(label) {
    for (let i = 0; i < sources.length; i += 1) {
      const { content } = sources[i];
      const filename = path.join('bench', `${label}-m${i}.js`);
      const mod = new Module(filename, module);
      mod.filename = filename;
      mod.paths = Module._nodeModulePaths(path.dirname(filename));
      mod._compile(content, filename);
    }
  }

  for (let i = 0; i < warmups; i += 1) {
    compileSources(`warmup-${i}`);
  }

  for (let i = 0; i < iterations; i += 1) {
    currentIteration = i;
    stageAccumulators = stageNames.reduce((acc, stage) => { acc[stage] = 0; return acc; }, {});
    compileSources(`iter-${i}`);
    iterationsData.push({ ...stageAccumulators });
    currentIteration = null;
    stageAccumulators = null;
  }

  const totalHookSamples = iterationsData.map(d => d.totalHook);
  const stageStats = {};
  for (const stage of stageNames) {
    stageStats[stage] = stats(iterationsData.map(d => d[stage]));
  }
  const summary = {
    metadata: makeMetadata(),
    workload: { count, bytes, iterations, warmups },
    stages: stageStats,
    totalHook: stats(totalHookSamples),
    raw: iterationsData,
  };
  writeJson(summary);
  console.log('Hook cost summary:');
  console.log('  totalHook median', summary.totalHook.median.toFixed(3), 'ms');
  for (const stage of stageNames) {
    const st = stageStats[stage];
    const pct = summary.totalHook.median ? (st.median / summary.totalHook.median) * 100 : 0;
    console.log(`  ${stage.padEnd(15)} median=${st.median.toFixed(3)}ms p95=${st.p95.toFixed(3)}ms pct=${pct.toFixed(1)}%`);
  }
}

main().catch(err => {
  console.error(err && err.stack ? err : err);
  process.exit(1);
});