// packages/fw-agent/test/index-exports-unit-test.js
// F-57 regression: policyMap and quarantinedModules must not be exported as the live
// Map/Set — only read-only query functions (hasPolicy, getPolicyDecision, isQuarantined).
//
// Before this fix, `fw.policyMap` returned the LIVE Map (via a getter that blocked only
// reassignment, not mutation), and `fw.quarantinedModules` was a plain export of the live Set.
// Any allowed code could do `fw.policyMap.set('some-pkg', 'OBSERVE')` and silently downgrade
// enforcement for that package, or `fw.quarantinedModules.delete(path)` to un-quarantine a
// module — from inside the very process the firewall is supposed to be protecting.
//
// This agent globally patches Module.prototype._compile as a side effect of being required, so
// (like package-identity-unit-test.js) it is required directly in-process rather than spawned:
// each test file already runs as its own `node` process via the test:unit script.
'use strict';
process.env.FW_ENABLE_DETECTION = '1';

// F-62: no shared, committed dev private key exists any more (see SECURITY.md). Generate a
// fresh Ed25519 keypair in-memory for this process only, and use FW_POLICY_PUBKEY (the real
// explicit-trusted-key production path) instead of the FW_ALLOW_DEV_POLICY_KEY convenience
// gate. Must be set before the agent (and its policy-watcher) is required below.
const crypto = require('crypto');
const { publicKey: TEST_PUBLIC_KEY, privateKey: TEST_PRIVATE_KEY } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
process.env.FW_POLICY_PUBKEY = TEST_PUBLIC_KEY;

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { signPolicy } = require('../../../scripts/sign-policy');

const DEV_PRIVATE_KEY = TEST_PRIVATE_KEY;

let passed = 0;
function check(name, fn) {
  try {
    fn();
    console.log('  ✓ ' + name);
    passed++;
  } catch (e) {
    console.error('  ✗ ' + name + '\n    ' + (e && e.stack || e));
    process.exit(1);
  }
}

// ── Set up a cwd with a real signed policy + a package to actually quarantine ──────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-index-exports-'));

const signed = signPolicy({
  'left-pad': 'BLOCK',
  'quarantine-target': 'QUARANTINE',
  'weird-pkg': { nested: true },
}, DEV_PRIVATE_KEY);
fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2) + '\n', 'utf8');

const pkgDir = path.join(tmp, 'node_modules', 'quarantine-target');
fs.mkdirSync(pkgDir, { recursive: true });
fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'quarantine-target', version: '1.0.0' }));
fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = "should-never-run";\n');
const targetFile = path.join(pkgDir, 'index.js');

const origCwd = process.cwd();
process.chdir(tmp);
const fw = require(path.join(__dirname, '..', 'index.js'));
process.chdir(origCwd);

// ── Tests ────────────────────────────────────────────────────────────────────────────────────

check('policyMap is not exported at all', () => {
  assert.strictEqual(fw.policyMap, undefined, 'policyMap must not be present on the exports object');
});

check('quarantinedModules is not exported at all', () => {
  assert.strictEqual(fw.quarantinedModules, undefined, 'quarantinedModules must not be present on the exports object');
});

check('regression: the OLD attack (fw.policyMap.set(...)) no longer works', () => {
  // policyMap is undefined, so the classic mutation attack throws instead of silently
  // rewriting live enforcement state.
  assert.throws(() => { fw.policyMap.set('evil-pkg', 'OBSERVE'); }, TypeError);
});

check('regression: the OLD attack (fw.quarantinedModules.delete(...)) no longer works', () => {
  assert.throws(() => { fw.quarantinedModules.delete(targetFile); }, TypeError);
});

check('read-only query functions are exported', () => {
  assert.strictEqual(typeof fw.hasPolicy, 'function');
  assert.strictEqual(typeof fw.getPolicyDecision, 'function');
  assert.strictEqual(typeof fw.isQuarantined, 'function');
});

check('hasPolicy()/getPolicyDecision() reflect real loaded policy state', () => {
  assert.strictEqual(fw.hasPolicy('left-pad'), true);
  assert.strictEqual(fw.getPolicyDecision('left-pad'), 'BLOCK');
  assert.strictEqual(fw.hasPolicy('nonexistent-pkg-xyz'), false);
  assert.strictEqual(fw.getPolicyDecision('nonexistent-pkg-xyz'), undefined);
});

check('getPolicyDecision() returns a frozen deep copy for object-valued rules, not the live reference', () => {
  assert.strictEqual(fw.hasPolicy('weird-pkg'), true);
  const decision = fw.getPolicyDecision('weird-pkg');
  assert.deepStrictEqual(decision, { nested: true });
  assert.ok(Object.isFrozen(decision), 'returned object must be frozen');
  try { decision.nested = false; } catch (e) { /* frozen: assignment may throw in strict mode */ }
  assert.strictEqual(fw.getPolicyDecision('weird-pkg').nested, true, 'live policy state must be unaffected by mutating the returned copy');
});

check('isQuarantined() reflects real quarantine state before and after a require()', () => {
  assert.strictEqual(fw.isQuarantined(targetFile), false, 'must be false before the module is ever loaded');
  const exported = require(targetFile);
  assert.notStrictEqual(exported, 'should-never-run', 'the quarantine stub must replace the real module exports');
  assert.strictEqual(fw.isQuarantined(targetFile), true, 'must be true once the module has been quarantined');
});

// ── F-74: compileMetrics must not be exported as the live mutable object ────────────────────────
check('F-74: compileMetrics is not exported as a live mutable object', () => {
  assert.strictEqual(fw.compileMetrics, undefined, 'compileMetrics must not be present on the exports object');
});

check('F-74: getCompileMetrics() accessor is exported and returns a frozen snapshot', () => {
  assert.strictEqual(typeof fw.getCompileMetrics, 'function');
  const snap = fw.getCompileMetrics();
  assert.ok(snap && typeof snap === 'object', 'getCompileMetrics() must return an object');
  assert.ok(Object.isFrozen(snap), 'the returned snapshot must be frozen');
  for (const k of ['filesCompiled', 'lockdownsEnforced', 'quarantined']) {
    assert.strictEqual(typeof snap[k], 'number', `snapshot must expose numeric ${k}`);
  }
});

check('F-74: mutating a returned snapshot does not corrupt internal metrics state', () => {
  const before = fw.getCompileMetrics().filesCompiled;
  const snap = fw.getCompileMetrics();
  try { snap.filesCompiled = 999999; } catch (e) { /* frozen: assignment may throw in strict mode */ }
  assert.strictEqual(snap.filesCompiled, before, 'the frozen snapshot must ignore writes');
  assert.strictEqual(fw.getCompileMetrics().filesCompiled, before,
    'a subsequent snapshot must reflect real state, unaffected by mutating a prior copy');
});

// ── F-82 (PENTEST-003 finding, F-74 follow-on) ──────────────────────────────────────────────────
// getCompileMetrics() previously called the AMBIENT global Object.freeze directly (no pristine
// capture, unlike crypto.createHash/crypto.verify/JSON.stringify etc. elsewhere in this codebase),
// so allowed code that runs AFTER this module has loaded -- the same threat model F-62/F-71
// already established a fix for -- could monkeypatch Object.freeze to a no-op and defeat the
// snapshot's immutability guarantee entirely. Distinct from the mutation test above (which proves
// the snapshot resists writes under an UNTAMPERED Object.freeze); this proves it resists a
// monkeypatched Object.freeze specifically, installed after require() (pristine capture only ever
// defends post-load tampering -- pre-load tampering is the same disclosed FW_MODE=dev gap every
// other pristine capture in this codebase already carries, not a new claim here).
check('F-82: getCompileMetrics() snapshot stays frozen even with Object.freeze monkeypatched AFTER module load', () => {
  const realFreeze = Object.freeze;
  try {
    Object.freeze = (x) => x; // no-op monkeypatch, installed after fw was already required above
    const snap = fw.getCompileMetrics();
    assert.strictEqual(Object.isFrozen(snap), true,
      'F-82: the returned snapshot must still be genuinely frozen (Object.isFrozen true) despite a monkeypatched global Object.freeze');
    let mutated = false;
    try { snap.filesCompiled = 999999; mutated = (snap.filesCompiled === 999999); } catch (e) { /* frozen: throws in strict mode, also acceptable */ }
    assert.strictEqual(mutated, false, 'F-82: the snapshot must reject mutation even under the monkeypatch');
  } finally {
    Object.freeze = realFreeze;
  }
});

fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\n${passed} index-exports checks passed.`);
