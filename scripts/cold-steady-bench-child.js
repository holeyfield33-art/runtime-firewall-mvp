#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const Module = require('module');

function nowNs() {
  return process.hrtime.bigint();
}

function hrToMs(start, end) {
  return Number(end - start) / 1e6;
}

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
    sources.push({
      filename: path.join('bench', `m${i}.js`),
      content: makeSource(i),
    });
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
  const sum = sorted.reduce((a,v)=>a+v,0);
  const mean = sum / n;
  const median = n % 2 ? sorted[(n-1)/2] : (sorted[n/2-1] + sorted[n/2]) / 2;
  const percentile = p => {
    const rank = Math.ceil((p/100)*n);
    return sorted[Math.max(0, Math.min(n-1, rank-1))];
  };
  return {
    count: n,
    mean,
    median,
    p95: percentile(95),
    p99: percentile(99),
    min: sorted[0],
    max: sorted[n-1],
    stddev: Math.sqrt(sorted.reduce((acc,v)=>acc+Math.pow(v-mean,2),0)/n),
  };
}

function writeJson(out) {
  const outFile = process.env.COLD_STEADY_BENCH_OUTFILE;
  const payload = JSON.stringify(out, null, 2);
  if (outFile) {
    try {
      fs.writeFileSync(outFile, payload, 'utf8');
      return;
    } catch (e) {
      // fallback to stdout if file write fails
    }
  }
  process.stdout.write(payload);
}

async function main() {
  const mode = process.argv[2];
  const count = Number(process.argv[3] || '0');
  if (!mode || !count || !Number.isInteger(count)) {
    console.error('Usage: node cold-steady-bench-child.js <cold|steady> <moduleCount> [iterations] [warmups]');
    process.exit(1);
  }

  const sources = buildSources(count);
  const bytes = sources.reduce((sum, item) => sum + Buffer.byteLength(item.content, 'utf8'), 0);

  if (mode === 'cold') {
    compileSources(sources);
    writeJson({ status: 'ok', mode: 'cold', moduleCount: count, bytes });
    process.exit(0);
    return;
  }

  if (mode === 'steady') {
    const iterations = Number(process.argv[4] || '20');
    const warmups = Number(process.argv[5] || '5');
    if (!Number.isInteger(iterations) || iterations <= 0) {
      console.error('Invalid iterations count');
      process.exit(1);
    }
    if (!Number.isInteger(warmups) || warmups < 0) {
      console.error('Invalid warmups count');
      process.exit(1);
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

    const result = {
      status: 'ok',
      mode: 'steady',
      moduleCount: count,
      bytes,
      warmups,
      iterations,
      rawSamplesMs: samples,
      statistics: stats(samples),
    };
    writeJson(result);
    process.exit(0);
    return;
  }

  console.error('Unknown mode:', mode);
  process.exit(1);
}

main().catch(err => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
