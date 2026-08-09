#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const Module = require('module');

function nowNs() { return process.hrtime.bigint(); }
function hrToMs(start, end) { return Number(end - start) / 1e6; }

function makeSource(index) {
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
    sources.push({ filename: path.join('bench', `m${i}.js`), content: makeSource(i) });
  }
  return sources;
}

function compileSources(sources) {
  for (const { filename, content } of sources) {
    const mod = new Module(filename, module);
    mod.filename = filename;
    mod.paths = Module._nodeModulePaths(path.dirname(filename));
    mod._compile(content, filename);
  }
}

function stats(samples) {
  const sorted = samples.slice().sort((a,b)=>a-b);
  const n = sorted.length;
  const mean = sorted.reduce((s,v)=>s+v,0)/n;
  const median = n%2 ? sorted[(n-1)/2] : (sorted[n/2-1]+sorted[n/2])/2;
  const quantile = p => sorted[Math.max(0, Math.min(n-1, Math.ceil((p/100)*n)-1))];
  return { count: n, mean, median, p95: quantile(95), p99: quantile(99), min: sorted[0], max: sorted[n-1] };
}

function writeJson(out) {
  const outFile = process.env.STEADY_STATE_ATTR_OUTFILE;
  const payload = JSON.stringify(out, null, 2);
  if (outFile) {
    try { fs.writeFileSync(outFile, payload, 'utf8'); return; } catch (e) {}
  }
  process.stdout.write(payload);
}

function isAgentPatched() {
  try {
    return Module.prototype._compile.toString().includes('detector.scanModuleSync');
  } catch (e) {
    return false;
  }
}

async function main() {
  const mode = process.argv[2];
  const count = Number(process.argv[3] || '0');
  const iterations = Number(process.argv[4] || '20');
  const warmups = Number(process.argv[5] || '5');
  if (!['baseline','hook-only','hook-scan'].includes(mode) || !count || !Number.isInteger(count)) {
    console.error('Usage: node steady-state-compile-attr-child.js <baseline|hook-only|hook-scan> <moduleCount> [iterations] [warmups]');
    process.exit(1);
  }
  if (!Number.isInteger(iterations) || iterations <= 0) { console.error('Invalid iterations'); process.exit(1); }
  if (!Number.isInteger(warmups) || warmups < 0) { console.error('Invalid warmups'); process.exit(1); }

  const sources = buildSources(count);
  const bytes = sources.reduce((sum, s) => sum + Buffer.byteLength(s.content, 'utf8'), 0);
  const sourceHash = require('crypto').createHash('sha256').update(sources.map(s => s.content).join('')).digest('hex');

  const compileFunctionSource = Module.prototype._compile.toString();
  const isPreloaded = compileFunctionSource.includes('detector.scanModuleSync');
  const compileOriginal = Module.prototype._compile;
  let compileCalls = 0;
  Module.prototype._compile = function(content, filename) {
    compileCalls += 1;
    return compileOriginal.apply(this, arguments);
  };

  if (mode === 'hook-only') {
    try {
      const agentDetector = require(path.join(process.cwd(), 'packages', 'fw-agent', 'src', 'detector.js'));
      agentDetector.Detector.prototype.scanModuleSync = function() { return { action: 'OBSERVE', detections: [] }; };
    } catch (e) {
      console.error('Failed to patch Detector prototype:', e && e.stack ? e.stack : e);
      process.exit(1);
    }
  }

  for (let i = 0; i < warmups; i += 1) {
    compileSources(sources);
  }

  const samples = [];
  for (let i = 0; i < iterations; i += 1) {
    const t0 = nowNs();
    compileSources(sources);
    const t1 = nowNs();
    samples.push(hrToMs(t0, t1));
  }

  writeJson({
    status: 'ok',
    mode, moduleCount: count, bytes, bytesPerModule: bytes / count, warmups, iterations,
    isAgentPreloaded: isPreloaded,
    sourceHash,
    moduleCompileCalls: compileCalls,
    perIterationExpectedCompiles: count,
    rawSamplesMs: samples,
    statistics: stats(samples),
    compilePathSourceHash: require('crypto').createHash('sha256').update(compileFunctionSource).digest('hex'),
    compilePathSourceSnippet: compileFunctionSource.slice(0, 400),
  });
  process.exit(0);
}

main().catch(err => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});