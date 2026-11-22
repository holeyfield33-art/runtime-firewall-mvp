// packages/fw-agent/test/quarantine-compat-test.js
// SRS-FW-004 P1: pins the Node-version- and format-dependent behavior of a QUARANTINE policy rule
// for a CommonJS require(). Documented in the README ("Policy File" -> QUARANTINE note):
//   - Node WITHOUT module.registerHooks() (< 22.15.0 / < 23.5.0): Module.prototype._compile handles
//     every CJS load -> the module body does NOT run, exports are replaced by a logging Proxy, and
//     require() returns normally.
//   - Node WITH module.registerHooks() (>= 22.15.0 / >= 23.5.0): CJS loads whose format Node knows
//     up front -- a `.cjs` file, or a `.js` file whose nearest package.json declares
//     "type": "commonjs" (which `npm init -y` writes by default on npm >= 11) -- pass through the
//     synchronous ESM load hook, which cannot substitute exports, so QUARANTINE degrades to a HARD
//     BLOCK: require() throws "[Firewall] Compilation denied ..." (audit event has esm: true).
//     A `.js` file with no "type" field still reaches _compile and gets the Proxy.
// In every case the quarantined module body never executes. No loader-hook architecture changed.
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { signPolicy } = require('../src/policy-signing');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
const HOOKS = typeof require('module').registerHooks === 'function';
let passed = 0;
function check(name, fn) {
  try { fn(); console.log('  ✓ ' + name); passed++; }
  catch (e) { console.error('  ✗ ' + name + '\n    ' + ((e && e.stack) || e)); process.exit(1); }
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function scenario(label, pkgJson, file) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-quarantine-compat-'));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkgJson));
  fs.writeFileSync(path.join(dir, file),
    "require('fs').writeFileSync(require('path').join(__dirname, 'BODY-RAN'), 'x');\nmodule.exports = { hello() { return 'real'; } };\n");
  fs.writeFileSync(path.join(dir, 'policy.signed.json'), JSON.stringify(signPolicy({ [file]: 'QUARANTINE' }, privateKey)));
  const script = `let m; try { m = require('./${file}'); } catch (e) { console.log('THROWN: ' + e.message); process.exit(0); }\n` +
    "console.log('RETURNED typeof=' + typeof m);";
  fs.writeFileSync(path.join(dir, 'main.js'), script);
  const env = Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_POLICY_PUBKEY: publicKey, HELIOS_LOG_DIR: path.join(dir, 'audit') });
  delete env.FW_ALLOW_DEV_POLICY_KEY;
  const res = spawnSync(process.execPath, [`--require=${AGENT_PATH}`, 'main.js'], { cwd: dir, encoding: 'utf8', timeout: 20000, env });
  const audit = fs.readFileSync(path.join(dir, 'audit', 'audit.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const q = audit.filter((e) => e.eventType === 'QUARANTINE_ACTIVE');
  const bodyRan = fs.existsSync(path.join(dir, 'BODY-RAN'));
  fs.rmSync(dir, { recursive: true, force: true });
  return { label, res, q, bodyRan };
}

const cases = [
  { s: scenario('.js, no "type" field', { name: 'q1', version: '1.0.0' }, 'untrusted-mod.js'), hardBlock: false },
  { s: scenario('.js under "type": "commonjs"', { name: 'q2', version: '1.0.0', type: 'commonjs' }, 'untrusted-mod.js'), hardBlock: HOOKS },
  { s: scenario('.cjs file', { name: 'q3', version: '1.0.0' }, 'untrusted-mod.cjs'), hardBlock: HOOKS },
];

for (const { s, hardBlock } of cases) {
  check(`${s.label} on Node ${process.version}: ${hardBlock ? 'HARD BLOCK (require() throws)' : 'logging Proxy (require() returns)'}; body never runs`, () => {
    assert.strictEqual(s.res.status, 0, s.res.stderr);
    assert.strictEqual(s.bodyRan, false, 'quarantined module body must not execute');
    assert.strictEqual(s.q.length, 1, 'expected exactly one QUARANTINE_ACTIVE audit event');
    if (hardBlock) {
      assert.ok(/THROWN: \[Firewall\] Compilation denied for module/.test(s.res.stdout), s.res.stdout + s.res.stderr);
      assert.strictEqual(s.q[0].esm, true);
    } else {
      assert.ok(/RETURNED typeof=function/.test(s.res.stdout), s.res.stdout + s.res.stderr);
      assert.notStrictEqual(s.q[0].esm, true);
    }
  });
}

console.log(`\nquarantine-compat-test: ${passed} checks passed`);
