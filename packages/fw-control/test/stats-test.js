/* stats-test.js - deterministic tests for statsFromSamples used by bench.js */
function statsFromSamples(samples) {
  const s = samples.slice().sort((a, b) => a - b);
  const n = s.length;
  const sum = s.reduce((a, b) => a + b, 0);
  const mean = n ? sum / n : 0;
  const min = n ? s[0] : 0;
  const max = n ? s[n - 1] : 0;
  const median = n ? (n % 2 ? s[Math.floor(n / 2)] : (s[n / 2 - 1] + s[n / 2]) / 2) : 0;
  const percentile = (p) => {
    if (!n) return 0;
    const rank = Math.ceil((p / 100) * n);
    return s[Math.max(0, Math.min(n - 1, rank - 1))];
  };
  const p95 = percentile(95);
  const p99 = percentile(99);
  const variance = n ? s.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / n : 0;
  const stddev = Math.sqrt(variance);
  return { min, median, p95, p99, max, mean, stddev };
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'Assertion failed');
}

// Tests
let r;
// Empty
r = statsFromSamples([]);
assert(r.min === 0 && r.median === 0 && r.mean === 0 && r.stddev === 0, 'empty failed');
// One sample
r = statsFromSamples([42]);
assert(r.min === 42 && r.median === 42 && Math.abs(r.mean - 42) < 1e-12 && Math.abs(r.stddev - 0) < 1e-12, 'one sample failed');
// Two samples
r = statsFromSamples([2, 4]);
assert(r.min === 2 && r.max === 4 && Math.abs(r.mean - 3) < 1e-12 && Math.abs(r.stddev - 1) < 1e-12 && r.p95 === 4, 'two sample stats failed');
// Three samples
r = statsFromSamples([1, 2, 3]);
assert(r.min === 1 && r.max === 3 && Math.abs(r.mean - 2) < 1e-12 && Math.abs(r.stddev - Math.sqrt(2 / 3)) < 1e-12 && r.p95 === 3, 'three sample stats failed');
// Percentile behavior
r = statsFromSamples([1,2,3,4,5]);
assert(r.p95 === 5 && r.p99 === 5, 'percentiles failed');

console.log('STATS_TESTS_PASS');
