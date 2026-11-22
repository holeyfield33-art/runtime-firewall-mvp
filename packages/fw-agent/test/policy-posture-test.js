// packages/fw-agent/test/policy-posture-test.js
// SRS-FW-004 P1: (a) missing-policy posture is reported once (warning + structured audit event)
// without changing detection behavior; (b) a loaded policy is audited with hash + signedAt;
// (c) verified hot-reloads carry hash + signedAt metadata, and an authentic OLDER policy is still
// accepted (documented replay limitation -- this test pins that behavior, it does not endorse it).
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { publicKey: PUB, privateKey: PRIV } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
process.env.FW_POLICY_PUBKEY = PUB; // before policy-watcher.js is first required

const { PolicyWatcher } = require('../src/policy-watcher');
const { signPolicy } = require('../src/policy-signing');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
let passed = 0;
async function check(name, fn) {
  try { await fn(); console.log('  ✓ ' + name); passed++; }
  catch (e) { console.error('  ✗ ' + name + '\n    ' + ((e && e.stack) || e)); process.exit(1); }
}
function readAudit(dir) {
  const f = path.join(dir, 'audit.log');
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
}
function runAgent(cwd, script, extraEnv = {}) {
  const env = Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', HELIOS_LOG_DIR: path.join(cwd, 'audit') }, extraEnv);
  delete env.FW_ALLOW_DEV_POLICY_KEY;
  return spawnSync(process.execPath, [`--require=${AGENT_PATH}`, '-e', script], { cwd, encoding: 'utf8', timeout: 20000, env });
}
const MALICIOUS = "const cp = require('child_process'); eval('1+1'); cp.exec('true'); module.exports = 'EVIL-RAN';\n";

(async () => {
  await check('no policy file: exactly one DETECTION-ONLY warning + one POLICY_ABSENT_DETECTION_ONLY audit event; detection still blocks', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-posture-absent-'));
    fs.writeFileSync(path.join(dir, 'evil.js'), MALICIOUS);
    const r = runAgent(dir, "try { require('./evil.js'); console.log('NOT-BLOCKED'); } catch (e) { console.log('BLOCKED'); }", { FW_POLICY_PUBKEY: PUB });
    assert.strictEqual(r.status, 0, r.stderr);
    const warnings = r.stderr.split('\n').filter((l) => l.includes('DETECTION-ONLY'));
    assert.strictEqual(warnings.length, 1, 'expected exactly one warning line:\n' + r.stderr);
    assert.ok(warnings[0].includes(path.join(dir, 'policy.signed.json')) && warnings[0].includes('process.cwd()'), warnings[0]);
    assert.ok(/customer-signed rules/.test(warnings[0]) && /policy integrity monitoring are INACTIVE/.test(warnings[0]), warnings[0]);
    assert.ok(/BLOCKED/.test(r.stdout) && !/NOT-BLOCKED/.test(r.stdout), 'runtime detection must be unchanged:\n' + r.stdout);
    const ev = readAudit(path.join(dir, 'audit')).filter((e) => e.eventType === 'POLICY_ABSENT_DETECTION_ONLY');
    assert.strictEqual(ev.length, 1, 'expected exactly one audit event');
    assert.strictEqual(ev[0].policyPathResolvedFrom, 'process.cwd()');
    assert.strictEqual(ev[0].customerRulesActive, false);
    assert.strictEqual(ev[0].policyMonitoringActive, false);
    assert.strictEqual(ev[0].detectionActive, true);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await check('FW_MODE=enforce with no policy file: still starts (no new fail-closed behavior), same single warning', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-posture-enforce-'));
    const r = runAgent(dir, "console.log('RAN')", { FW_POLICY_PUBKEY: PUB, FW_MODE: 'enforce' });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.strictEqual(r.stderr.split('\n').filter((l) => l.includes('DETECTION-ONLY')).length, 1, r.stderr);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await check('valid policy present: no DETECTION-ONLY warning; POLICY_LOADED audited with sha256 + signedAt', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-posture-loaded-'));
    const signed = signPolicy({ 'some-pkg': 'BLOCK' }, PRIV, '2026-11-21T00:00:00.000Z');
    const body = JSON.stringify(signed, null, 2) + '\n';
    fs.writeFileSync(path.join(dir, 'policy.signed.json'), body);
    const r = runAgent(dir, "console.log('RAN')", { FW_POLICY_PUBKEY: PUB });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(!r.stderr.includes('DETECTION-ONLY'), r.stderr);
    const ev = readAudit(path.join(dir, 'audit')).filter((e) => e.eventType === 'POLICY_LOADED');
    assert.strictEqual(ev.length, 1);
    assert.strictEqual(ev[0].signedAt, '2026-11-21T00:00:00.000Z');
    assert.strictEqual(ev[0].policyHash, crypto.createHash('sha256').update(body).digest('hex'));
    assert.strictEqual(ev[0].ruleCount, 1);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await check('invalid signature still locks down (no auto-downgrade to detection-only)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-posture-invalid-'));
    const signed = signPolicy({ 'some-pkg': 'BLOCK' }, PRIV);
    signed.rules['some-pkg'] = 'OBSERVE';
    fs.writeFileSync(path.join(dir, 'policy.signed.json'), JSON.stringify(signed));
    fs.writeFileSync(path.join(dir, 'm.js'), "module.exports = 1;\n");
    const r = runAgent(dir, "try { require('./m.js'); console.log('LOADED'); } catch (e) { console.log('LOCKED'); }", { FW_POLICY_PUBKEY: PUB });
    assert.ok(/EMERGENCY LOCKDOWN/.test(r.stderr), r.stderr);
    assert.ok(!r.stderr.includes('DETECTION-ONLY'), 'must not report detection-only when a policy file exists:\n' + r.stderr);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await check('PolicyWatcher reload passes { reload, policyHash, signedAt, previous* }; an older authentic policy is ACCEPTED (replay limitation)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-posture-reload-'));
    const p = path.join(dir, 'policy.signed.json');
    const B = JSON.stringify(signPolicy({ victim: 'BLOCK' }, PRIV, '2026-11-21T00:00:00.000Z'));
    const A = JSON.stringify(signPolicy({ victim: 'OBSERVE' }, PRIV, '2026-11-01T00:00:00.000Z'));
    fs.writeFileSync(p, B);
    const calls = [];
    let tampered = 0;
    const w = new PolicyWatcher(p, { onValidChange: (rules, meta) => calls.push({ rules, meta }), onTamperDetected: () => tampered++ }, { intervalMs: 40 });
    const origLog = console.log; console.log = () => {};
    try {
      w.start();
      fs.writeFileSync(p, A);
      await new Promise((r) => setTimeout(r, 200));
    } finally { w.stop(); console.log = origLog; }
    assert.strictEqual(tampered, 0);
    assert.strictEqual(calls.length, 2, 'initial load + one reload');
    assert.strictEqual(calls[0].meta.reload, false);
    assert.strictEqual(calls[0].meta.policyHash, crypto.createHash('sha256').update(B).digest('hex'));
    const m = calls[1].meta;
    assert.strictEqual(m.reload, true);
    assert.strictEqual(calls[1].rules.victim, 'OBSERVE', 'older authentic policy is applied (documented replay limitation)');
    assert.strictEqual(m.signedAt, '2026-11-01T00:00:00.000Z');
    assert.strictEqual(m.previousSignedAt, '2026-11-21T00:00:00.000Z');
    assert.strictEqual(m.policyHash, crypto.createHash('sha256').update(A).digest('hex'));
    assert.strictEqual(m.previousPolicyHash, calls[0].meta.policyHash);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  console.log(`\npolicy-posture-test: ${passed} checks passed`);
})();
