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

// ── Part 1b: F-1.2 (P0-2) — manifest identity spoofing cannot override install identity ───────
// A package physically installed under node_modules/<real-folder-name> can self-report an
// arbitrary, different `name` in its own package.json. The canonical identity's name component
// must come from where npm actually put it on disk, never from the (attacker-controlled)
// manifest, or a malicious package could impersonate a trusted one to dodge policy.
(function partOneB() {
  const tmp = mkTmpDir('fw-identity-spoof-unit-');

  check('unscoped package mismatch: install-derived folder name wins over a spoofed manifest name', () => {
    const pkgDir = writePackage(tmp, path.join('node_modules', 'real-folder-name'), 'claimed-fake-name', '1.0.0', 'module.exports = 1;\n');
    const identity = agent.resolveModuleIdentity(path.join(pkgDir, 'index.js'));
    assert.strictEqual(identity, 'real-folder-name@1.0.0:index.js', 'identity must use the install folder name, not the manifest-claimed name');
  });

  check('scoped package mismatch: install-derived scoped folder name wins over a spoofed manifest name', () => {
    const pkgDir = writePackage(tmp, path.join('node_modules', '@real-scope', 'real-name'), '@fake-scope/fake-name', '1.0.0', 'module.exports = 1;\n');
    const identity = agent.resolveModuleIdentity(path.join(pkgDir, 'index.js'));
    assert.strictEqual(identity, '@real-scope/real-name@1.0.0:index.js', 'identity must use the install scope/name, not the manifest-claimed scope/name');
  });

  check('nested node_modules: a transitive dependency spoofing its name still resolves to its own nested install identity', () => {
    const outerDir = writePackage(tmp, path.join('node_modules', 'outer-pkg'), 'outer-pkg', '1.0.0', 'module.exports = 1;\n');
    const innerDir = writePackage(
      tmp,
      path.join('node_modules', 'outer-pkg', 'node_modules', 'inner-real-name'),
      'inner-claimed-name',
      '2.0.0',
      'module.exports = 2;\n'
    );
    const innerIdentity = agent.resolveModuleIdentity(path.join(innerDir, 'index.js'));
    const outerIdentity = agent.resolveModuleIdentity(path.join(outerDir, 'index.js'));
    assert.strictEqual(innerIdentity, 'inner-real-name@2.0.0:index.js', 'nested dependency must resolve to its own (closest) node_modules folder name');
    assert.notStrictEqual(innerIdentity, outerIdentity, 'nested spoofed package must not collide with its parent package identity');
  });

  check('honest package (manifest name matches install folder) resolves exactly as before', () => {
    const pkgDir = writePackage(tmp, path.join('node_modules', 'honest-pkg'), 'honest-pkg', '1.0.0', 'module.exports = 1;\n');
    const identity = agent.resolveModuleIdentity(path.join(pkgDir, 'index.js'));
    assert.strictEqual(identity, 'honest-pkg@1.0.0:index.js', 'no regression for packages whose manifest name matches their install location');
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

// ── Part 2b: F-1.2 (P0-2) TP — a spoofed manifest name cannot bypass a BLOCK rule ──────────────
// Real-world bypass shape this closes: an operator has BOTH (1) a BLOCK rule keyed on the real,
// installed name of a known-malicious package, and (2) an unrelated, less-restrictive
// canonical-identity-level rule pinned for some OTHER, trusted package at an exact version. Before
// this fix, a malicious package installed under the BLOCKed folder name could self-report that
// trusted package's name+version in its own package.json — its canonicalIdentity (manifest-derived)
// would then collide with the trusted package's pinned rule, which is checked at HIGHER precedence
// than the folder/packageKey-level BLOCK rule, so the malicious package's real BLOCK rule was never
// even reached.
(function partTwoB() {
  const tmp = mkTmpDir('fw-identity-spoof-block-');
  // Installed folder name is the one an operator would actually BLOCK.
  writePackage(tmp, path.join('node_modules', 'evil-pkg'), 'trusted-lib', '1.0.0', 'module.exports = "evil-pkg-loaded";\n');

  const signed = signPolicy({
    'evil-pkg': 'BLOCK', // keyed on the real, install-derived identity
    'trusted-lib@1.0.0:index.js': 'OBSERVE', // an unrelated operator-pinned rule for the name being spoofed
  }, DEV_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  const childScript = path.join(tmp, 'child.js');
  fs.writeFileSync(childScript, `
    const path = require('path');
    let error = null, exportsSeen = null;
    try { exportsSeen = require(path.join(process.cwd(), 'node_modules', 'evil-pkg', 'index.js')); } catch (e) { error = e.message; }
    console.log('RESULT:' + JSON.stringify({ error, exportsSeen }));
  `);

  const res = runFirewalledChild(tmp, childScript);
  check('F-1.2 TP: a manifest self-reporting a trusted, differently-policied name cannot bypass the real package\'s BLOCK rule', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.error && result.error.includes('[Firewall]'), 'the malicious package must still be BLOCKed despite the spoofed manifest name: ' + JSON.stringify(result));
    assert.notStrictEqual(result.exportsSeen, 'evil-pkg-loaded', 'the real quarantined/blocked code must never execute: ' + JSON.stringify(result));
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

// ── Part 2c: F-1.2 (P0-2) TP — a spoofed manifest name cannot bypass a QUARANTINE rule ─────────
(function partTwoC() {
  const tmp = mkTmpDir('fw-identity-spoof-quarantine-');
  writePackage(tmp, path.join('node_modules', 'evil-pkg-2'), 'trusted-lib-2', '1.0.0', 'module.exports = "evil-pkg-2-loaded";\n');

  const signed = signPolicy({
    'evil-pkg-2': 'QUARANTINE',
    'trusted-lib-2@1.0.0:index.js': 'OBSERVE',
  }, DEV_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  const childScript = path.join(tmp, 'child.js');
  fs.writeFileSync(childScript, `
    const path = require('path');
    let error = null, exportsSeen = null;
    try { exportsSeen = require(path.join(process.cwd(), 'node_modules', 'evil-pkg-2', 'index.js')); } catch (e) { error = e.message; }
    console.log('RESULT:' + JSON.stringify({ error, exportsType: typeof exportsSeen, exportsSeen: typeof exportsSeen === 'string' ? exportsSeen : '(non-string, quarantine stub)' }));
  `);

  const res = runFirewalledChild(tmp, childScript);
  check('F-1.2 TP: a manifest self-reporting a trusted, differently-policied name cannot bypass the real package\'s QUARANTINE rule', () => {
    const result = parseResult(res.stdout);
    assert.strictEqual(result.error, null, 'QUARANTINE never throws (F-5.1) -- require() must resolve, not error: ' + JSON.stringify(result));
    assert.notStrictEqual(result.exportsType, 'string', 'the real evil-pkg-2 export string must never surface -- module.exports must be the inert quarantine stub: ' + JSON.stringify(result));
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
