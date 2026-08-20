// packages/fw-agent/test/package-identity-unit-test.js
// P0-2: policy identity is no longer keyed on bare path.basename(filename), where every
// package's index.js collapsed to the same key "index.js". Covers:
//   1. resolveModuleIdentity() key derivation directly (exported helper, no spawning).
//   2. TP/collision: two node_modules packages sharing basename "index.js" resolve to distinct
//      identities, and a policy rule keyed on one package's name never leaks to the other.
//   3. FP/control: a legacy basename-keyed policy rule still resolves via the compat shim.
'use strict';
process.env.FW_ENABLE_DETECTION = '1';

// F-62: no shared, committed dev private key exists any more (see SECURITY.md). Generate a
// fresh Ed25519 keypair in-memory for this process only, and use FW_POLICY_PUBKEY (the real
// explicit-trusted-key production path) instead of the FW_ALLOW_DEV_POLICY_KEY convenience
// gate, for both the in-process require below and every spawned child in this file.
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
const { spawnSync } = require('child_process');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
const DEV_PRIVATE_KEY = TEST_PRIVATE_KEY;
const { signPolicy } = require('../../../scripts/sign-policy');

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

function writePackage(dir, pkgRelDir, name, version, entryContent) {
  const pkgDir = path.join(dir, pkgRelDir);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name, version }));
  fs.writeFileSync(path.join(pkgDir, 'index.js'), entryContent);
  return pkgDir;
}

function runFirewalledChild(cwd, childScript, env) {
  return spawnSync(process.execPath, [`--require=${AGENT_PATH}`, childScript], {
    cwd,
    encoding: 'utf8',
    env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_POLICY_PUBKEY: TEST_PUBLIC_KEY }, env),
    timeout: 15000,
  });
}

function parseResult(stdout) {
  const m = /RESULT:(.*)/.exec(stdout || '');
  if (!m) throw new Error('child produced no RESULT: line. stdout=\n' + stdout);
  return JSON.parse(m[1]);
}

// ── Part 1: resolveModuleIdentity() key derivation (no spawning) ─────────────────────────────
// Requiring the agent in-process (FW_ENABLE_DETECTION=1 above) gives us the exported helper
// directly, matching how detection-test.js already requires the agent in-process elsewhere.
const agent = require(AGENT_PATH);

(function partOne() {
  const tmp = mkTmpDir('fw-identity-unit-');

  check('resolveModuleIdentity() derives name@version:relPath for a node_modules package', () => {
    const pkgADir = writePackage(tmp, path.join('node_modules', 'pkg-a'), 'pkg-a', '1.0.0', 'module.exports = 1;\n');
    const identity = agent.resolveModuleIdentity(path.join(pkgADir, 'index.js'));
    assert.strictEqual(identity, 'pkg-a@1.0.0:index.js');
  });

  check('two different packages sharing the "index.js" basename resolve to distinct identities', () => {
    const pkgBDir = writePackage(tmp, path.join('node_modules', 'pkg-b'), 'pkg-b', '2.0.0', 'module.exports = 2;\n');
    const identityA = agent.resolveModuleIdentity(path.join(tmp, 'node_modules', 'pkg-a', 'index.js'));
    const identityB = agent.resolveModuleIdentity(path.join(pkgBDir, 'index.js'));
    assert.notStrictEqual(identityA, identityB, 'pkg-a and pkg-b must not collide despite both being basename "index.js"');
    assert.strictEqual(identityB, 'pkg-b@2.0.0:index.js');
  });

  check('scoped package name is preserved in the canonical identity', () => {
    const pkgCDir = writePackage(tmp, path.join('node_modules', '@scope', 'pkg-c'), '@scope/pkg-c', '3.0.0', 'module.exports = 3;\n');
    const identity = agent.resolveModuleIdentity(path.join(pkgCDir, 'index.js'));
    assert.strictEqual(identity, '@scope/pkg-c@3.0.0:index.js');
  });

  check('a nested file inside a package resolves relative to that package root', () => {
    const pkgADir = path.join(tmp, 'node_modules', 'pkg-a');
    fs.mkdirSync(path.join(pkgADir, 'lib'), { recursive: true });
    fs.writeFileSync(path.join(pkgADir, 'lib', 'helper.js'), 'module.exports = {};\n');
    const identity = agent.resolveModuleIdentity(path.join(pkgADir, 'lib', 'helper.js'));
    assert.strictEqual(identity, 'pkg-a@1.0.0:lib/helper.js');
  });

  check('negative: a file with no ancestor package.json gets a sane identity and never crashes', () => {
    const orphanDir = mkTmpDir('fw-identity-orphan-');
    const orphanFile = path.join(orphanDir, 'app.js');
    fs.writeFileSync(orphanFile, 'module.exports = {};\n');
    let identity;
    assert.doesNotThrow(() => { identity = agent.resolveModuleIdentity(orphanFile); });
    assert.strictEqual(typeof identity, 'string');
    assert.ok(identity.length > 0);
    fs.rmSync(orphanDir, { recursive: true, force: true });
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

// ── Part 2: TP/collision via a real signed policy + spawned firewalled child ──────────────────
(function partTwo() {
  const tmp = mkTmpDir('fw-identity-collision-');
  writePackage(tmp, path.join('node_modules', 'pkg-a'), 'pkg-a', '1.0.0', 'module.exports = "pkg-a-loaded";\n');
  writePackage(tmp, path.join('node_modules', 'pkg-b'), 'pkg-b', '1.0.0', 'module.exports = "pkg-b-loaded";\n');

  const signed = signPolicy({ 'pkg-a': 'BLOCK' }, DEV_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  const childScript = path.join(tmp, 'child.js');
  fs.writeFileSync(childScript, `
    const path = require('path');
    let pkgAError = null, pkgBError = null, pkgBExports = null;
    try { require(path.join(process.cwd(), 'node_modules', 'pkg-a', 'index.js')); } catch (e) { pkgAError = e.message; }
    try { pkgBExports = require(path.join(process.cwd(), 'node_modules', 'pkg-b', 'index.js')); } catch (e) { pkgBError = e.message; }
    console.log('RESULT:' + JSON.stringify({ pkgAError, pkgBError, pkgBExports }));
  `);

  const res = runFirewalledChild(tmp, childScript);
  check('collision TP: policy rule keyed on "pkg-a" blocks only pkg-a, never pkg-b (both share basename index.js)', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.pkgAError && result.pkgAError.includes('[Firewall]'), 'pkg-a must be blocked: ' + JSON.stringify(result));
    assert.strictEqual(result.pkgBError, null, 'pkg-b must load cleanly: ' + JSON.stringify(result));
    assert.strictEqual(result.pkgBExports, 'pkg-b-loaded', 'pkg-b must actually execute: ' + JSON.stringify(result));
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

// ── Part 3: FP/control — legacy basename-keyed policy still resolves via the compat shim ──────
(function partThree() {
  const tmp = mkTmpDir('fw-identity-legacy-');
  // No package.json anywhere in this tree and not under node_modules: canonical identity falls
  // back to the absolute path and packageKeyForFilename() returns null, so ONLY the basename
  // compat shim (precedence tier c) can match this rule.
  fs.writeFileSync(path.join(tmp, 'somefile.js'), 'module.exports = "somefile-loaded";\n');

  const signed = signPolicy({ 'somefile.js': 'BLOCK' }, DEV_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  const childScript = path.join(tmp, 'child.js');
  fs.writeFileSync(childScript, `
    const path = require('path');
    let error = null;
    try { require(path.join(process.cwd(), 'somefile.js')); } catch (e) { error = e.message; }
    console.log('RESULT:' + JSON.stringify({ error }));
  `);

  const res = runFirewalledChild(tmp, childScript);
  check('legacy compat: a hand-written basename-keyed policy rule ("somefile.js": BLOCK) still resolves', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.error && result.error.includes('[Firewall]'), 'somefile.js must still be blocked via basename compat: ' + JSON.stringify(result));
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

console.log(`\n${passed} package-identity checks passed.`);
process.exit(0);
