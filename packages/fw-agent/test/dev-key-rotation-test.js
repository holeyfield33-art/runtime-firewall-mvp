// packages/fw-agent/test/dev-key-rotation-test.js
// F-62 dev-key rotation regression tests.
//
// scripts/dev-private-key.pem (a shared, committed development private key) was removed from
// HEAD and DEV_PUBLIC_KEY_PEM in policy-watcher.js was rotated to a freshly generated public
// key whose private counterpart has never been committed anywhere -- see SECURITY.md "Key
// revocation record (F-62)". These tests prove, with real process runs (not just reading the
// code), that:
//   1. A signature made with the OLD, now-revoked key is rejected by a freshly-built agent.
//   2. A signature made with a brand-new, never-committed key IS accepted via FW_POLICY_PUBKEY.
//   3. assertProductionKeyConfig() genuinely refuses to start under NODE_ENV=production without
//      an explicit key, and genuinely does NOT refuse once one is supplied.
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { signPolicy } = require('../../../scripts/sign-policy');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
const POLICY_WATCHER_PATH = path.join(__dirname, '..', 'src', 'policy-watcher.js');

// The OLD, now-revoked dev private key (formerly scripts/dev-private-key.pem, deleted from HEAD
// in this same change -- see SECURITY.md "Key revocation record (F-62)"). Recorded here ONLY as
// a known-compromised negative-test fixture. It is already permanently and irrevocably
// recoverable from this repository's git history (a deliberate, documented decision -- history
// was not rewritten), so keeping this literal here does not change its exposure. NEVER sign
// anything real with it.
const REVOKED_OLD_DEV_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMpYHYyh4rAnbkMQriFay7DZ3UwWseP95SlsKp0jQbaz
-----END PRIVATE KEY-----`;

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

function mkTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// A clean env with any key-related overrides stripped, so each test controls exactly what it
// needs rather than inheriting ambient FW_* values from the invoking shell.
function baseEnv(extra) {
  const env = Object.assign({}, process.env);
  delete env.FW_POLICY_PUBKEY;
  delete env.FW_ALLOW_DEV_POLICY_KEY;
  delete env.NODE_ENV;
  return Object.assign(env, extra);
}

function runVerifyChild(cwd, env) {
  const script = `
    const path = require('path');
    const { PolicyWatcher } = require(${JSON.stringify(POLICY_WATCHER_PATH)});
    const w = new PolicyWatcher(path.join(process.cwd(), 'policy.signed.json'), {});
    console.log('RESULT:' + JSON.stringify({ verified: w.verify() }));
  `;
  return spawnSync(process.execPath, ['-e', script], { cwd, encoding: 'utf8', timeout: 15000, env });
}

// ── 1. Signature made with the OLD, now-revoked key is rejected by a freshly-built agent ───────
{
  const tmp = mkTmpDir('fw-devkey-old-');
  const signed = signPolicy({ 'old-key-pkg': 'OBSERVE' }, REVOKED_OLD_DEV_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2) + '\n', 'utf8');

  // Default config: no FW_POLICY_PUBKEY override, so verification falls back to the (rotated)
  // bundled DEV_PUBLIC_KEY_PEM -- the old key must no longer match it.
  const res = runVerifyChild(tmp, baseEnv({}));

  check('a policy signed with the OLD, revoked dev key is REJECTED by a freshly-rotated agent (default DEV_PUBLIC_KEY_PEM, no override)', () => {
    const m = /RESULT:(.*)/.exec(res.stdout || '');
    assert.ok(m, 'child produced no RESULT line. stdout=\n' + res.stdout + '\nstderr=\n' + res.stderr);
    const result = JSON.parse(m[1]);
    assert.strictEqual(result.verified, false, 'the old, revoked key must no longer verify against the rotated DEV_PUBLIC_KEY_PEM');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
}

// ── 2. Signature made with a brand-new, never-committed key IS accepted via FW_POLICY_PUBKEY ───
{
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  // This keypair is generated fresh in-memory for this one test run and is never written to
  // disk or committed anywhere -- the exact scenario the acceptance criteria describe.
  const tmp = mkTmpDir('fw-devkey-new-');
  const signed = signPolicy({ 'new-key-pkg': 'OBSERVE' }, privateKey);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2) + '\n', 'utf8');

  const res = runVerifyChild(tmp, baseEnv({ FW_POLICY_PUBKEY: publicKey }));

  check('a policy signed with a brand-new, never-committed key IS accepted once FW_POLICY_PUBKEY is set to match', () => {
    const m = /RESULT:(.*)/.exec(res.stdout || '');
    assert.ok(m, 'child produced no RESULT line. stdout=\n' + res.stdout + '\nstderr=\n' + res.stderr);
    const result = JSON.parse(m[1]);
    assert.strictEqual(result.verified, true, 'a fresh, never-committed key configured via FW_POLICY_PUBKEY must verify its own signature');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
}

// ── 3. assertProductionKeyConfig() genuinely refuses to start in production without an explicit key ──
// Real spawned `node` processes -- not a mocked call -- so this proves the actual startup path
// (index.js requiring policy-watcher.js and calling assertProductionKeyConfig()) refuses for real.
{
  const tmp = mkTmpDir('fw-devkey-prodcheck-');
  // No policy.signed.json at all in this cwd -- F-33 explicitly runs regardless of policy-file
  // presence, so this isolates the check from PolicyWatcher.start()'s separate, later guard.

  check('real process: NODE_ENV=production + default dev key (no override) refuses to start', () => {
    const res = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(AGENT_PATH)})`], {
      cwd: tmp,
      encoding: 'utf8',
      timeout: 15000,
      env: baseEnv({ FW_ENABLE_DETECTION: '1', NODE_ENV: 'production' }),
    });
    assert.notStrictEqual(res.status, 0, 'expected non-zero exit, got ' + res.status + '\nstderr:\n' + res.stderr);
    assert.ok(/CRITICAL/.test(res.stderr) && /production/i.test(res.stderr), 'expected a production-key CRITICAL message on stderr:\n' + res.stderr);
  });

  check('real process: NODE_ENV=production + FW_POLICY_PUBKEY set to an explicit key does NOT refuse for key-config reasons', () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const res = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(AGENT_PATH)}); console.log('started-ok')`], {
      cwd: tmp,
      encoding: 'utf8',
      timeout: 15000,
      env: baseEnv({ FW_ENABLE_DETECTION: '1', NODE_ENV: 'production', FW_POLICY_PUBKEY: publicKey }),
    });
    assert.strictEqual(res.status, 0, 'expected exit 0, got ' + res.status + '\nstderr:\n' + res.stderr);
    assert.ok(res.stdout.includes('started-ok'), 'expected child script to actually run:\n' + res.stdout);
  });

  check('real process: NODE_ENV=production + FW_ALLOW_DEV_POLICY_KEY=1 explicit opt-in does NOT refuse', () => {
    const res = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(AGENT_PATH)}); console.log('started-ok')`], {
      cwd: tmp,
      encoding: 'utf8',
      timeout: 15000,
      env: baseEnv({ FW_ENABLE_DETECTION: '1', NODE_ENV: 'production', FW_ALLOW_DEV_POLICY_KEY: '1' }),
    });
    assert.strictEqual(res.status, 0, 'expected exit 0, got ' + res.status + '\nstderr:\n' + res.stderr);
    assert.ok(res.stdout.includes('started-ok'), 'expected child script to actually run:\n' + res.stdout);
  });

  check('real process: NODE_ENV=development (not production) + default dev key does NOT refuse', () => {
    const res = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(AGENT_PATH)}); console.log('started-ok')`], {
      cwd: tmp,
      encoding: 'utf8',
      timeout: 15000,
      env: baseEnv({ FW_ENABLE_DETECTION: '1', NODE_ENV: 'development' }),
    });
    assert.strictEqual(res.status, 0, 'expected exit 0, got ' + res.status + '\nstderr:\n' + res.stderr);
    assert.ok(res.stdout.includes('started-ok'), 'expected child script to actually run:\n' + res.stdout);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
}

// ── 4. Direct call: assertProductionKeyConfig()'s exact gating logic, with an injectable exit ──
{
  // Requiring policy-watcher.js here (no FW_POLICY_PUBKEY set anywhere in THIS process) makes
  // USING_DEV_POLICY_KEY true against the default bundled DEV_PUBLIC_KEY_PEM, matching the
  // "fresh agent, no override configured" scenario the function exists to guard.
  const { assertProductionKeyConfig } = require('../src/policy-watcher');

  check('assertProductionKeyConfig: production + dev key + no opt-in => refuses (calls exit(1), returns true)', () => {
    let exitCode = null;
    const refused = assertProductionKeyConfig({ NODE_ENV: 'production' }, (code) => { exitCode = code; });
    assert.strictEqual(refused, true, 'must return true when it refuses');
    assert.strictEqual(exitCode, 1, 'must call exit(1)');
  });

  check('assertProductionKeyConfig: production + dev key + FW_ALLOW_DEV_POLICY_KEY=1 => does not refuse', () => {
    let exitCalled = false;
    const refused = assertProductionKeyConfig({ NODE_ENV: 'production', FW_ALLOW_DEV_POLICY_KEY: '1' }, () => { exitCalled = true; });
    assert.strictEqual(refused, false);
    assert.strictEqual(exitCalled, false);
  });

  check('assertProductionKeyConfig: NODE_ENV=development + dev key => does not refuse', () => {
    let exitCalled = false;
    const refused = assertProductionKeyConfig({ NODE_ENV: 'development' }, () => { exitCalled = true; });
    assert.strictEqual(refused, false);
    assert.strictEqual(exitCalled, false);
  });
}

console.log(`\n${passed} dev-key-rotation checks passed.`);
