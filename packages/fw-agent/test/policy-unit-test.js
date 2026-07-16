// packages/fw-agent/test/policy-unit-test.js
// Unit tests for src/policy.js — canonical hashing + forensic object construction.
// policy.js had no dedicated test; this exercises every branch for engine-core coverage.
const assert = require('assert');
const {
  createCanonicalObject,
  hashMemoryObject,
  verifyPolicyIntegrity,
  createForensicObject,
} = require('../src/policy');

let passed = 0;
function check(name, fn) {
  return fn().then(() => { console.log('  ✓ ' + name); passed++; })
    .catch((e) => { console.error('  ✗ ' + name + '\n    ' + e.message); process.exit(1); });
}
function sync(name, fn) { return check(name, async () => fn()); }

(async () => {
  // ── createCanonicalObject ────────────────────────────────────────────────
  await sync('createCanonicalObject fills defaults', () => {
    const o = createCanonicalObject({});
    assert.strictEqual(o.category, 'security_policy');
    assert.strictEqual(o.key, 'active_policy');
    assert.strictEqual(o.source, 'fw-control-plane');
    assert.deepStrictEqual(o.relationships, []);
    assert.deepStrictEqual(o.value, {});
    assert.ok(o.created_at, 'created_at should be populated');
  });

  await sync('createCanonicalObject honors provided fields and objectType', () => {
    const o = createCanonicalObject(
      { created_at: '2026-01-01T00:00:00.000Z', key: 'k', relationships: ['a'], source: 's', rules: { x: 'BLOCK' } },
      'custom_type'
    );
    assert.strictEqual(o.category, 'custom_type');
    assert.strictEqual(o.created_at, '2026-01-01T00:00:00.000Z');
    assert.strictEqual(o.key, 'k');
    assert.deepStrictEqual(o.relationships, ['a']);
    assert.strictEqual(o.source, 's');
    assert.deepStrictEqual(o.value, { x: 'BLOCK' });
  });

  await sync('createCanonicalObject prefers value over rules', () => {
    const o = createCanonicalObject({ value: { v: 1 }, rules: { r: 2 } });
    assert.deepStrictEqual(o.value, { v: 1 });
  });

  // ── hashMemoryObject ─────────────────────────────────────────────────────
  await sync('hashMemoryObject is deterministic (64-hex SHA-256)', () => {
    const a = hashMemoryObject({ b: 2, a: 1 });
    const b = hashMemoryObject({ a: 1, b: 2 });
    assert.match(a, /^[0-9a-f]{64}$/);
    assert.strictEqual(a, b, 'key order must not change the hash');
  });

  await sync('hashMemoryObject differs for different content', () => {
    assert.notStrictEqual(hashMemoryObject({ a: 1 }), hashMemoryObject({ a: 2 }));
  });

  // ── verifyPolicyIntegrity ────────────────────────────────────────────────
  await check('verifyPolicyIntegrity false on missing/empty policy', async () => {
    assert.strictEqual(await verifyPolicyIntegrity(null), false);
    assert.strictEqual(await verifyPolicyIntegrity({}), false);
  });

  await check('verifyPolicyIntegrity true when hash matches', async () => {
    const policy = { rules: { pkg: 'BLOCK' } };
    const canonical = createCanonicalObject(policy, 'security_policy');
    policy.helios_hash = hashMemoryObject(canonical);
    assert.strictEqual(await verifyPolicyIntegrity(policy), true);
  });

  await check('verifyPolicyIntegrity false when hash mismatches', async () => {
    const policy = { rules: { pkg: 'BLOCK' }, helios_hash: 'deadbeef' };
    assert.strictEqual(await verifyPolicyIntegrity(policy), false);
  });

  await check('verifyPolicyIntegrity true (graceful) when no hash present', async () => {
    assert.strictEqual(await verifyPolicyIntegrity({ rules: { pkg: 'OBSERVE' } }), true);
  });

  // ── createForensicObject ─────────────────────────────────────────────────
  await sync('createForensicObject shapes a quarantine event', () => {
    const o = createForensicObject('QUARANTINE_BREACH', 'evil.js', 'property_access', { property: 'exec' });
    assert.strictEqual(o.category, 'quarantine_event');
    assert.strictEqual(o.source, 'fw-agent-proxy');
    assert.deepStrictEqual(o.relationships, ['evil.js']);
    assert.strictEqual(o.value.eventType, 'QUARANTINE_BREACH');
    assert.strictEqual(o.value.operation, 'property_access');
    assert.deepStrictEqual(o.value.details, { property: 'exec' });
    assert.match(o.key, /^ev_\d+_[a-z0-9]+$/);
  });

  await sync('createForensicObject keys are unique across calls', () => {
    const a = createForensicObject('X', 'p', 'op', {});
    const b = createForensicObject('X', 'p', 'op', {});
    assert.notStrictEqual(a.key, b.key);
  });

  console.log(`\nAll policy unit tests passed (${passed}).`);
})();
