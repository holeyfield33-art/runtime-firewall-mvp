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
process.env.FW_ALLOW_DEV_POLICY_KEY = '1';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { signPolicy } = require('../../../scripts/sign-policy');

const DEV_PRIVATE_KEY = fs.readFileSync(
  path.join(__dirname, '../../../scripts/dev-private-key.pem'), 'utf8'
);

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

fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\n${passed} index-exports checks passed.`);
