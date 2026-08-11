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

async function main() {
  const count = Number(process.argv[2] || '900');
  const iterations = Number(process.argv[3] || '20');
  const warmups = Number(process.argv[4] || '5');
  const sources = buildSources(count);

  const metrics = { replace: [], matchAll: [], regexTest: [], behaviorAnalysis: [], totalHook: [] };
  let currentIteration = null;
  let currentStage = null;

  const originalReplace = String.prototype.replace;
  String.prototype.replace = function () {
    const t0 = currentIteration !== null ? nowNs() : null;
    const result = originalReplace.apply(this, arguments);
    if (t0) metrics.replace.push(hrToMs(t0, nowNs()));
    return result;
  };

  const originalMatchAll = String.prototype.matchAll;
  String.prototype.matchAll = function () {
    const t0 = currentIteration !== null ? nowNs() : null;
    const result = originalMatchAll.apply(this, arguments);
    if (t0) metrics.matchAll.push(hrToMs(t0, nowNs()));
    return result;
  };

  const originalRegExpTest = RegExp.prototype.test;
  RegExp.prototype.test = function () {
    const t0 = currentIteration !== null ? nowNs() : null;
    const result = originalRegExpTest.apply(this, arguments);
    if (t0) metrics.regexTest.push(hrToMs(t0, nowNs()));
    return result;
  };

  const BehaviorTracker = require(path.join(process.cwd(), 'packages', 'fw-agent', 'src', 'behavior-tracker')).BehaviorTracker;
  const originalAnalyzeModule = BehaviorTracker.prototype.analyzeModule;
  BehaviorTracker.prototype.analyzeModule = function () {
    const t0 = currentIteration !== null ? nowNs() : null;
    const result = originalAnalyzeModule.apply(this, arguments);
    if (t0) metrics.behaviorAnalysis.push(hrToMs(t0, nowNs()));
    return result;
  };

  process.env.FW_ENABLE_DETECTION = '1';
  process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
  require(path.join(process.cwd(), 'packages', 'fw-agent', 'index.js'));

  const agentHook = Module.prototype._compile;
  Module.prototype._compile = function () {
    const t0 = nowNs();
    const result = agentHook.apply(this, arguments);
    const t1 = nowNs();
    if (currentIteration !== null) metrics.totalHook.push(hrToMs(t0, t1));
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

  for (let i = 0; i < warmups; i += 1) compileSources(`warmup-${i}`);

  for (let i = 0; i < iterations; i += 1) {
    currentIteration = i;
    compileSources(`iter-${i}`);
    currentIteration = null;
  }

  const summary = {
    replace: stats(metrics.replace),
    matchAll: stats(metrics.matchAll),
    regexTest: stats(metrics.regexTest),
    behaviorAnalysis: stats(metrics.behaviorAnalysis),
    totalHook: stats(metrics.totalHook),
  };

  console.log(JSON.stringify(summary, null, 2));
}

main().catch(err => { console.error(err && err.stack ? err : err); process.exit(1); });
