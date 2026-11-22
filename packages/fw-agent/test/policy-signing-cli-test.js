// packages/fw-agent/test/policy-signing-cli-test.js
// SRS-FW-004 P0: package-owned key generation / signing CLIs, one authoritative signing
// implementation, enforcement with the produced policy, and key rotation / recovery.
// Real child processes (spawnSync), real files, real Ed25519 keys -- nothing mocked.
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const AGENT_DIR = path.join(__dirname, '..');
const AGENT_PATH = path.join(AGENT_DIR, 'index.js');
const KEYGEN = path.join(AGENT_DIR, 'bin', 'aletheia-policy-keygen.js');
const SIGN = path.join(AGENT_DIR, 'bin', 'aletheia-policy-sign.js');
const REPO_ROOT = path.join(AGENT_DIR, '..', '..');

let passed = 0;
function check(name, fn) {
  try { fn(); console.log('  ✓ ' + name); passed++; }
  catch (e) { console.error('  ✗ ' + name + '\n    ' + ((e && e.stack) || e)); process.exit(1); }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-signing-cli-'));
function node(args, opts = {}) {
  return spawnSync(process.execPath, args, Object.assign({ cwd: tmp, encoding: 'utf8', timeout: 20000 }, opts));
}
function runAgent(script, pubkeyPem, extraEnv = {}) {
  const env = Object.assign({}, process.env, {
    FW_ENABLE_DETECTION: '1', FW_POLICY_PUBKEY: pubkeyPem, HELIOS_LOG_DIR: path.join(tmp, 'audit'),
  }, extraEnv);
  delete env.FW_ALLOW_DEV_POLICY_KEY;
  return spawnSync(process.execPath, [`--require=${AGENT_PATH}`, '-e', script], { cwd: tmp, encoding: 'utf8', timeout: 20000, env });
}

// A local module the policy can target by basename.
fs.writeFileSync(path.join(tmp, 'target-mod.js'), "module.exports = 'TARGET-RAN';\n");
const REQUIRE_TARGET = "try { console.log(require('./target-mod.js')); } catch (e) { console.log('THROWN: ' + e.message); }";

check('package.json declares both CLIs under "bin" and ships bin/ in "files"', () => {
  const pkg = require(path.join(AGENT_DIR, 'package.json'));
  assert.strictEqual(pkg.bin['aletheia-policy-keygen'], 'bin/aletheia-policy-keygen.js');
  assert.strictEqual(pkg.bin['aletheia-policy-sign'], 'bin/aletheia-policy-sign.js');
  assert.ok(pkg.files.includes('bin/'), 'files must include bin/');
  assert.ok(pkg.files.includes('src/'), 'files must include src/ (policy-signing.js lives there)');
  assert.ok(!pkg.dependencies || Object.keys(pkg.dependencies).length === 0, 'no runtime dependencies');
});

check('one authoritative implementation: repo scripts/sign-policy.js re-exports the package module', () => {
  const pkgSigning = require('../src/policy-signing');
  const repoScript = require(path.join(REPO_ROOT, 'scripts', 'sign-policy.js'));
  assert.strictEqual(repoScript.signPolicy, pkgSigning.signPolicy);
  assert.strictEqual(pkgSigning.canonicalPayload, require('../src/policy-watcher').canonicalPayload,
    'signer must use the verifier\'s own canonicalPayload');
});

let pub1;
check('keygen writes a 0600 private key + public key and never prints the private key', () => {
  const res = node([KEYGEN]);
  assert.strictEqual(res.status, 0, res.stderr);
  assert.ok(!/PRIVATE KEY/.test(res.stdout + res.stderr), 'private key material must not be printed:\n' + res.stdout);
  const priv = fs.readFileSync(path.join(tmp, 'aletheia-policy-private.pem'), 'utf8');
  pub1 = fs.readFileSync(path.join(tmp, 'aletheia-policy-public.pem'), 'utf8');
  assert.ok(/BEGIN PRIVATE KEY/.test(priv) && /BEGIN PUBLIC KEY/.test(pub1));
  if (process.platform !== 'win32') {
    assert.strictEqual(fs.statSync(path.join(tmp, 'aletheia-policy-private.pem')).mode & 0o777, 0o600);
  }
  assert.ok(/FW_POLICY_PUBKEY/.test(res.stdout), 'next steps must point at FW_POLICY_PUBKEY');
  assert.ok(!/DEV_PUBLIC_KEY_PEM|policy-watcher\.js/.test(res.stdout), 'must not tell consumers to edit package source');
});

check('keygen refuses to overwrite an existing key file without --force (files unchanged)', () => {
  const before = fs.readFileSync(path.join(tmp, 'aletheia-policy-private.pem'), 'utf8');
  const res = node([KEYGEN]);
  assert.strictEqual(res.status, 1, 'expected exit 1, got ' + res.status);
  assert.ok(/Refusing to overwrite/.test(res.stderr), res.stderr);
  assert.strictEqual(fs.readFileSync(path.join(tmp, 'aletheia-policy-private.pem'), 'utf8'), before);
});

check('sign produces an envelope the agent accepts; BLOCK rule is enforced', () => {
  fs.writeFileSync(path.join(tmp, 'rules.json'), JSON.stringify({ 'target-mod.js': 'BLOCK' }));
  const s = node([SIGN, 'aletheia-policy-private.pem', 'rules.json', 'policy.signed.json']);
  assert.strictEqual(s.status, 0, s.stderr);
  assert.ok(!/PRIVATE KEY/.test(s.stdout + s.stderr));
  const env = JSON.parse(fs.readFileSync(path.join(tmp, 'policy.signed.json'), 'utf8'));
  assert.deepStrictEqual(Object.keys(env).sort(), ['rules', 'signature', 'signedAt', 'version']);
  const r = runAgent(REQUIRE_TARGET, pub1);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.ok(/THROWN: \[Firewall\] Compilation denied for module: "target-mod.js"/.test(r.stdout), r.stdout + r.stderr);
});

check('tampering with the signed rules triggers emergency lockdown', () => {
  const p = path.join(tmp, 'policy.signed.json');
  const good = fs.readFileSync(p, 'utf8');
  fs.writeFileSync(p, good.replace('"BLOCK"', '"OBSERVE"'));
  const r = runAgent(REQUIRE_TARGET, pub1);
  fs.writeFileSync(p, good);
  assert.ok(/EMERGENCY LOCKDOWN/.test(r.stderr), r.stderr);
  assert.ok(!/TARGET-RAN/.test(r.stdout), 'module must not run under lockdown');
});

let pub2;
check('key rotation: new key + re-signed policy works once FW_POLICY_PUBKEY is updated', () => {
  const g = node([KEYGEN, '--private-key', 'k2/private.pem', '--public-key', 'k2/public.pem']);
  assert.strictEqual(g.status, 0, g.stderr);
  pub2 = fs.readFileSync(path.join(tmp, 'k2', 'public.pem'), 'utf8');
  const s = node([SIGN, 'k2/private.pem', 'rules.json', 'policy.signed.json']);
  assert.strictEqual(s.status, 0, s.stderr);
  const r = runAgent(REQUIRE_TARGET, pub2);
  assert.ok(/Compilation denied for module: "target-mod.js"/.test(r.stdout), r.stdout + r.stderr);
});

check('key rotation: agent still trusting the OLD key rejects the new signature (lockdown, not fail-open)', () => {
  const r = runAgent(REQUIRE_TARGET, pub1);
  assert.ok(/EMERGENCY LOCKDOWN/.test(r.stderr), r.stderr);
  assert.ok(!/TARGET-RAN/.test(r.stdout));
});

check('compromise recovery: after rotating FW_POLICY_PUBKEY, a policy signed by the retired key is rejected', () => {
  const s = node([SIGN, 'aletheia-policy-private.pem', 'rules.json', 'old-key-policy.json']);
  assert.strictEqual(s.status, 0, s.stderr);
  fs.copyFileSync(path.join(tmp, 'old-key-policy.json'), path.join(tmp, 'policy.signed.json'));
  const r = runAgent(REQUIRE_TARGET, pub2);
  assert.ok(/EMERGENCY LOCKDOWN/.test(r.stderr), r.stderr);
  assert.ok(!/TARGET-RAN/.test(r.stdout));
});

check('key-loss recovery: keygen --force replaces a lost/compromised pair; re-sign + new pubkey works', () => {
  const g = node([KEYGEN, '--force']);
  assert.strictEqual(g.status, 0, g.stderr);
  const pub3 = fs.readFileSync(path.join(tmp, 'aletheia-policy-public.pem'), 'utf8');
  assert.notStrictEqual(pub3, pub1, '--force must generate a fresh key pair');
  const s = node([SIGN, 'aletheia-policy-private.pem', 'rules.json', 'policy.signed.json']);
  assert.strictEqual(s.status, 0, s.stderr);
  const r = runAgent(REQUIRE_TARGET, pub3);
  assert.ok(/Compilation denied for module: "target-mod.js"/.test(r.stdout), r.stdout + r.stderr);
});

check('repo wrapper scripts/sign-policy.js keeps its CLI contract', () => {
  const s = node([path.join(REPO_ROOT, 'scripts', 'sign-policy.js'), 'aletheia-policy-private.pem', 'rules.json', 'wrapper.json']);
  assert.strictEqual(s.status, 0, s.stderr);
  assert.ok(/Signed policy written to wrapper.json/.test(s.stdout));
  const u = node([path.join(REPO_ROOT, 'scripts', 'sign-policy.js')]);
  assert.notStrictEqual(u.status, 0, 'missing args must fail');
});

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\npolicy-signing-cli-test: ${passed} checks passed`);
