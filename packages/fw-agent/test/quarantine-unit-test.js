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

// ── Test 3b: remaining proxy traps (delete / ownKeys / descriptor) ───────────
{
  const stub = new QuarantineStub('trap-pkg', null);
  const proxy = stub.createProxy();

  // deleteProperty trap → returns true (pretend deletion succeeded)
  assert.doesNotThrow(() => { delete proxy.foo; });

  // ownKeys trap → returns [] (module exposes nothing)
  assert.deepStrictEqual(Object.keys(proxy), [], 'ownKeys must report no keys');

  // getOwnPropertyDescriptor trap → undefined
  assert.strictEqual(Object.getOwnPropertyDescriptor(proxy, 'bar'), undefined, 'descriptor must be undefined');

  assert.ok(stub.interceptCount > 0, 'trap accesses must be recorded');
  console.log('  ✓ delete / ownKeys / getOwnPropertyDescriptor traps are inert and logged');
}

// ── Test 3c: telemetry.emit + first-breach console log paths ─────────────────
{
  const emitted = [];
  const telemetry = { emit: (type, payload) => emitted.push({ type, payload }) };
  const origWarn = console.warn;
  let warnedFirstBreach = false;
  console.warn = (msg) => { if (String(msg).includes('Quarantine Intercept')) warnedFirstBreach = true; };

  const stub = new QuarantineStub('emit-pkg', telemetry);
  const proxy = stub.createProxy();
  proxy.doThing(); // property_access + method_call → 2 records, both emit

  console.warn = origWarn;

  assert.ok(emitted.length >= 1, 'telemetry.emit must be called with a forensic object');
  assert.strictEqual(emitted[0].type, 'quarantine_event', 'emit event type');
  assert.ok(emitted[0].payload.hash && /^[0-9a-f]{64}$/.test(emitted[0].payload.hash), 'forensic hash attached');
  assert.ok(warnedFirstBreach, 'first breach must log a [Quarantine Intercept] line');
  console.log('  ✓ telemetry.emit + first-breach console path covered');
}

// ── Test 3d: defineProperty trap is pretend-success, never forwards to target (F-63) ─────────
{
  const stub = new QuarantineStub('define-pkg', null);
  const proxy = stub.createProxy();

  // Previously untrapped: forwarded to the real (empty) target via default Reflect.defineProperty,
  // which then made ownKeys/getOwnPropertyDescriptor's "report no keys" answer invalid (Proxy
  // invariant violation) and threw a raw TypeError on the very next enumeration call.
  assert.doesNotThrow(() => {
    Object.defineProperty(proxy, 'x', { value: 1 });
  }, 'defineProperty on the quarantine proxy must not throw');

  assert.deepStrictEqual(Object.keys(proxy), [], 'ownKeys must still report no *enumerable* keys after defineProperty');
  // `prototype` is a real, non-configurable own key on the callable target (F-5.1) — the
  // Proxy invariants require ownKeys to include it, so it is the one key that legitimately
  // survives enumeration (Object.keys excludes it above because it is non-enumerable).
  assert.deepStrictEqual(Reflect.ownKeys(proxy), ['prototype'], 'Reflect.ownKeys must report the target\'s one non-configurable key');
  assert.doesNotThrow(() => {
    const descriptors = Object.getOwnPropertyDescriptors(proxy);
    assert.deepStrictEqual(Object.keys(descriptors), ['prototype'], 'getOwnPropertyDescriptors must report only the non-configurable key');
    assert.strictEqual(descriptors.prototype.configurable, false, 'reported prototype descriptor must be non-configurable, matching the real target');
  }, 'getOwnPropertyDescriptors must not throw after defineProperty');

  assert.ok(stub.interceptCount > 0, 'defineProperty must be recorded');
  console.log('  ✓ defineProperty trap is pretend-success and does not break subsequent enumeration (F-63)');
}

// ── Test 3e: preventExtensions/isExtensible remain untrapped and correct (F-63 non-regression) ──
{
  // F-63 explicitly does NOT add preventExtensions/isExtensible traps with the same
  // "pretend" pattern -- that was tested directly and confirmed to throw, because a proxy's
  // reported extensibility must genuinely match its target's actual extensibility unless
  // preventExtensions was really called on the target. These two traps stay untrapped, and the
  // default forwarding behavior is already correct (the target genuinely is extensible).
  const stub = new QuarantineStub('extensible-pkg', null);
  const proxy = stub.createProxy();

  assert.strictEqual(Object.isExtensible(proxy), true, 'quarantine proxy must be extensible by default (no trap override)');
  assert.doesNotThrow(() => { Object.preventExtensions(proxy); }, 'preventExtensions must work via default forwarding');
  assert.strictEqual(Object.isExtensible(proxy), false, 'isExtensible must reflect the real preventExtensions() call');

  console.log('  ✓ preventExtensions/isExtensible remain untrapped and correct (F-63 non-regression)');
}

// ── Test 3f: proxy() is callable and does not crash the host (F-5.1) ─────────
// Before the fix, the proxy target was `{}` — a plain object has no [[Call]] internal
// method, so calling the proxy threw a native, uncatchable-by-the-firewall
// "proxy is not a function" TypeError for any function/class-shaped quarantined
// dependency, regardless of the apply trap defined below (traps are never consulted
// unless the target itself supports the operation). This is the audit's sole
// explicit NO-SHIP condition.
{
  const stub = new QuarantineStub('callable-pkg', null);
  const proxy = stub.createProxy();

  assert.strictEqual(typeof proxy, 'function', 'quarantine proxy must report as callable');

  let result;
  assert.doesNotThrow(() => { result = proxy('real-arg'); }, 'calling the quarantine proxy must not throw');
  assert.strictEqual(result, null, 'calling the proxy must gracefully degrade to null, never execute real code');
  assert.ok(stub.interceptCount > 0, 'the call must be recorded for forensics');

  console.log('  ✓ proxy() is callable, does not execute real code, and does not crash the host (F-5.1)');
}

// ── Test 3g: new proxy() is constructible and does not crash the host (F-5.1) ─
{
  const stub = new QuarantineStub('constructible-pkg', null);
  const proxy = stub.createProxy();

  let instance;
  assert.doesNotThrow(() => { instance = new proxy('real-arg'); }, 'constructing the quarantine proxy must not throw');
  // The Proxy invariant only requires an Object (functions are objects too — the constructed
  // instance is itself another callable/constructible quarantine proxy, per design below).
  assert.ok(instance !== null && (typeof instance === 'object' || typeof instance === 'function'),
    'construct trap must return an Object per Proxy invariants');
  assert.ok(stub.interceptCount > 0, 'the construct call must be recorded for forensics');

  // The constructed instance is itself inert — real quarantined constructors never run,
  // so any method the caller invokes on the "instance" degrades gracefully too.
  assert.doesNotThrow(() => {
    const methodResult = instance.someMethod();
    assert.strictEqual(methodResult, null, 'methods on the constructed instance must gracefully degrade to null');
  }, 'using the constructed instance must not throw or execute real code');

  console.log('  ✓ new proxy() is constructible, does not execute real code, and does not crash the host (F-5.1)');
}

// ── Test 3h: `prototype` Proxy invariants are honored, not just papered over (F-5.1) ─
// The callable target has one real, non-configurable own key: `prototype`. Lying about its
// presence (as the pre-fix `ownKeys: () => []` pattern would for a callable target) violates
// the Proxy spec's invariants and throws a raw TypeError straight out of the engine.
{
  const stub = new QuarantineStub('prototype-invariant-pkg', null);
  const proxy = stub.createProxy();

  assert.strictEqual('prototype' in proxy, true, '`prototype` is a real non-configurable own key and must not be reported absent');
  assert.strictEqual('someOtherProp' in proxy, false, 'forgeable, non-existent keys must still be reported absent');

  assert.strictEqual(Reflect.deleteProperty(proxy, 'prototype'), false, 'a non-configurable own key must not be reportable as deleted');
  assert.doesNotThrow(() => { delete proxy.someOtherProp; }, 'deleting a forgeable key must still succeed silently');

  assert.doesNotThrow(() => { Object.keys(proxy); }, 'enumerating the proxy must never throw a raw invariant-violation TypeError');
  assert.doesNotThrow(() => { Reflect.ownKeys(proxy); }, 'Reflect.ownKeys must never throw a raw invariant-violation TypeError');
  assert.doesNotThrow(() => { Object.getOwnPropertyDescriptors(proxy); }, 'getOwnPropertyDescriptors must never throw a raw invariant-violation TypeError');

  console.log('  ✓ `prototype` Proxy invariants are honored without crashing the host (F-5.1)');
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
