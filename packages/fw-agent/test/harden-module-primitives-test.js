// packages/fw-agent/test/harden-module-primitives-test.js
// Opt-in narrow _compile freeze (FW_HARDEN_MODULE_PRIMITIVES=1). Complementary to F-58's
// Module._load hardening, not a substitute: this raises the cost of the classic
// Module.prototype._compile monkeypatch specifically. Default-off, matching FW_FREEZE_PROTOTYPES'
// existing opt-in posture for the same class of change (freezing a foundational Node internal is
// a real compatibility risk for loaders/instrumentation/transpilers).
'use strict';
const assert = require('assert');
const path = require('path');
const { spawnSync } = require('child_process');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
const REPO_ROOT = path.join(__dirname, '..', '..', '..');

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

function runChild(script, envExtra) {
  return spawnSync(process.execPath, ['--require', AGENT_PATH, '-e', script], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 15000,
    env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_MODE: 'dev', FW_ALLOW_DEV_POLICY_KEY: '1' }, envExtra),
  });
}

const PROBE_SCRIPT = `
  const Module = require('module');
  const desc = Object.getOwnPropertyDescriptor(Module.prototype, '_compile');
  const before = Module.prototype._compile;
  let assignThrew = null;
  try { Module.prototype._compile = function() { return 'monkeypatched'; }; }
  catch (e) { assignThrew = e.message; }
  console.log('RESULT:' + JSON.stringify({
    writable: desc.writable,
    configurable: desc.configurable,
    assignThrew,
    stillOriginal: Module.prototype._compile === before,
  }));
`;

function parseResult(stdout) {
  const m = /RESULT:(.*)/.exec(stdout || '');
  if (!m) throw new Error('child produced no RESULT: line. stdout=\n' + stdout);
  return JSON.parse(m[1]);
}

check('default (flag unset): Module.prototype._compile stays writable/configurable, monkeypatch succeeds (byte-identical to pre-PR-6 behavior)', () => {
  const res = runChild(PROBE_SCRIPT, {});
  const result = parseResult(res.stdout);
  assert.strictEqual(result.writable, true, 'default must leave _compile writable');
  assert.strictEqual(result.configurable, true, 'default must leave _compile configurable');
  assert.strictEqual(result.assignThrew, null, 'assignment must not throw by default');
  assert.strictEqual(result.stillOriginal, false, 'the monkeypatch must actually succeed by default');
});

check('FW_HARDEN_MODULE_PRIMITIVES=1: Module.prototype._compile is frozen non-writable/non-configurable', () => {
  const res = runChild(PROBE_SCRIPT, { FW_HARDEN_MODULE_PRIMITIVES: '1' });
  const result = parseResult(res.stdout);
  assert.strictEqual(result.writable, false, 'flag must make _compile non-writable');
  assert.strictEqual(result.configurable, false, 'flag must make _compile non-configurable');
});

check('FW_HARDEN_MODULE_PRIMITIVES=1: a monkeypatch attempt fails silently (no throw in sloppy mode), value unchanged', () => {
  const res = runChild(PROBE_SCRIPT, { FW_HARDEN_MODULE_PRIMITIVES: '1' });
  const result = parseResult(res.stdout);
  assert.strictEqual(result.assignThrew, null, 'assignment to a non-writable property in sloppy mode must not throw');
  assert.strictEqual(result.stillOriginal, true, 'Module.prototype._compile must be unchanged after the failed monkeypatch attempt');
});

check('FW_HARDEN_MODULE_PRIMITIVES=1: normal require() still works (the frozen _compile is still fully functional)', () => {
  const fs = require('fs');
  const os = require('os');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-harden-primitives-'));
  const target = path.join(tmp, 'ok.js');
  fs.writeFileSync(target, 'module.exports = { ok: true };\n');
  const res = spawnSync(process.execPath, ['--require', AGENT_PATH, '-e', `console.log('RESULT:' + JSON.stringify(require(${JSON.stringify(target)})))`], {
    cwd: tmp,
    encoding: 'utf8',
    timeout: 15000,
    env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_MODE: 'dev', FW_HARDEN_MODULE_PRIMITIVES: '1' }),
  });
  const result = parseResult(res.stdout);
  assert.deepStrictEqual(result, { ok: true }, 'a normal, legitimate require() must still work under the freeze');
  fs.rmSync(tmp, { recursive: true, force: true });
});

console.log(`\n${passed} harden-module-primitives (PR6) checks passed.`);
