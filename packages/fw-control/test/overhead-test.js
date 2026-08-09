/* overhead-test.js - deterministic tests for per-iteration overhead calculation */
function computeOverheads(baseline, agent) {
  const raw = [];
  for (let i = 0; i < baseline.length; i++) {
    const b = baseline[i];
    const a = agent[i];
    if (b === 0) raw.push(null);
    else raw.push(((a - b) / b) * 100);
  }
  return raw;
}

function statsFromSamples(samples) {
  const numeric = samples.filter(x => typeof x === 'number' && !Number.isNaN(x)).slice().sort((a, b) => a - b);
  const n = numeric.length;
  const sum = n ? numeric.reduce((a, b) => a + b, 0) : 0;
  const mean = n ? sum / n : 0;
  const min = n ? numeric[0] : 0;
  const max = n ? numeric[n - 1] : 0;
  const median = n ? (n % 2 ? numeric[Math.floor(n / 2)] : (numeric[n / 2 - 1] + numeric[n / 2]) / 2) : 0;
  const percentile = (p) => {
    if (!n) return 0;
    const rank = Math.ceil((p / 100) * n);
    return numeric[Math.max(0, Math.min(n - 1, rank - 1))];
  };
  const p95 = percentile(95);
  const p99 = percentile(99);
  const variance = n ? numeric.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / n : 0;
  const stddev = Math.sqrt(variance);
  return { min, median, p95, p99, max, mean, stddev };
}

function assert(cond, msg) { if (!cond) throw new Error(msg || 'Assertion failed'); }

// Test 1: simple with a zero baseline
const baseline = [100, 200, 0];
const agent = [110, 180, 10];
const raw = computeOverheads(baseline, agent);
assert(raw.length === 3, 'raw length');
assert(raw[0] === 10, 'first overhead');
assert(raw[1] === -10, 'second overhead');
assert(raw[2] === null, 'third should be null');

const stats = statsFromSamples(raw);
// numericOverheads = [-10, 10] -> mean 0, median 0, p95 -> rank = ceil(0.95*2)=2 => 10
assert(Math.abs(stats.mean - 0) < 1e-12, 'mean expected 0');
assert(Math.abs(stats.median - 0) < 1e-12, 'median expected 0');
assert(stats.p95 === 10, 'p95 expected 10');

// Test 2: all zeros baseline -> no numeric samples
const baseline2 = [0,0];
const agent2 = [0,0];
const raw2 = computeOverheads(baseline2, agent2);
assert(raw2[0] === null && raw2[1] === null, 'all nulls');
const stats2 = statsFromSamples(raw2);
assert(stats2.mean === 0 && stats2.median === 0 && stats2.p95 === 0, 'stats empty => zeros');

console.log('OVERHEAD_TESTS_PASS');
