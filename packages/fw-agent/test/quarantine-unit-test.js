// packages/fw-agent/test/quarantine-unit-test.js
// Unit tests for QuarantineStub: proxy behaviour, rate-limiting, no process.exit.
'use strict';

const assert = require('assert');
const { QuarantineStub } = require('../src/quarantine');

// ── Test 1: proxy is inert and returns null ──────────────────────────────────
{
  const stub = new QuarantineStub('test-pkg', null);
  const proxy = stub.createProxy();

  // Property access returns a callable function
  const fn = proxy.someMethod;
  assert.strictEqual(typeof fn, 'function', 'Property access must return a function');

  // Method call returns null (graceful degradation, not throw)
  const result = fn('arg1', 'arg2');
  assert.strictEqual(result, null, 'Method call must return null');

  // `in` operator returns false (pretend property absent)
  assert.strictEqual('someMethod' in proxy, false, '`in` must return false');

  // Assignment silently succeeds (returns true from set trap)
  assert.doesNotThrow(() => { proxy.anything = 'value'; });

  console.log('  ✓ QuarantineStub proxy is inert and returns null');
}

// ── Test 2: rate-limit fires without crashing the process ─────────────────────
{
  const logs = [];
  const origWarn = console.warn;
  console.warn = (...args) => logs.push(args.join(' '));

  const stub = new QuarantineStub('test-pkg', null);
  // Simulate the threshold condition: put interceptCount above 100, reset initTime
  // so that the elapsed delta stays near-zero when record() checks it.
  stub.interceptCount = 105;
  stub.initTime = process.hrtime.bigint();

  stub.record('test_op', {});

  console.warn = origWarn;

  // Must NOT have called process.exit (we're still running)
  assert.strictEqual(stub.rateLimitCount, 1, 'rateLimitCount should be 1');
  assert.ok(logs.length > 0, 'Expected at least one rate-limit warning');
  assert.ok(logs[0].includes('Rapid-fire') || logs[0].includes('Rate-limiting'),
    'Log message should describe the rate-limit event');

  console.log('  ✓ Rate-limit fires without process.exit');
}

// ── Test 3: rate-limit suppresses logs (log once per 10 hits) ────────────────
{
  const stub = new QuarantineStub('test-pkg', null);

  let logCount = 0;
  const origWarn = console.warn;
  console.warn = () => { logCount++; };

  // Each iteration: reset initTime so delta is near-zero, keep interceptCount > 100
  for (let i = 0; i < 20; i++) {
    stub.interceptCount = 105; // keep above threshold (record() will increment it)
    stub.initTime = process.hrtime.bigint();
    stub.record('op');
  }

  console.warn = origWarn;

  // rateLimitCount % 10 === 1 fires on call 1 and call 11 → 2 logs total
  assert.strictEqual(logCount, 2, `Expected 2 log calls (1 per 10 hits), got ${logCount}`);
  assert.strictEqual(stub.rateLimitCount, 20);

  console.log('  ✓ Rate-limit logs once per 10 suppressed events');
}

console.log('All quarantine unit tests passed.');

// ── Test 4: proxy is not an accidental thenable (F-17) ───────────────────────
// If `then` resolves to a function, Promise.resolve(proxy) / await proxy hangs forever.
// The fix returns undefined for `then`, Symbol.toPrimitive, and Symbol.iterator.
(async () => {
  const stub = new QuarantineStub('test-pkg', null);
  const proxy = stub.createProxy();

  // `then` must be undefined so JS does not treat the proxy as a thenable
  assert.strictEqual(proxy.then, undefined, '`then` must be undefined (not a thenable)');
  assert.strictEqual(proxy[Symbol.toPrimitive], undefined, 'Symbol.toPrimitive must be undefined');
  assert.strictEqual(proxy[Symbol.iterator], undefined, 'Symbol.iterator must be undefined');

  // Promise.resolve must settle (no infinite hang) — race against a 500ms timeout
  let settled = false;
  await Promise.race([
    Promise.resolve(proxy).then(() => { settled = true; }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timed out — proxy is an accidental thenable')), 500)),
  ]);
  assert.ok(settled, 'Promise.resolve(quarantinedProxy) must settle (F-17)');

  console.log('  ✓ Quarantine proxy is not an accidental thenable (F-17)');
  console.log('All quarantine unit tests passed (with F-17 thenable guard).');
})().catch(err => { console.error(err.message); process.exit(1); });
