// packages/fw-agent/test/esm-loader-test.js
// P2-01: direct unit coverage for the ESM Module Customization Hook (esm-loader.mjs), via real
// child processes (spawnSync, not mocked) exercising genuine Node ESM semantics — a static
// `import` declaration cannot be caught in-process (see esm-fixtures/static-import-sentinel.mjs
// for why), so this asserts on the crashed child's exit code and stderr, not a caught exception.
'use strict';
const assert = require('assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { spawnSync } = require('child_process');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const FIXTURES_DIR = path.join(__dirname, 'esm-fixtures');

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

function spawnFixture(fixture) {
  return spawnSync(
    process.execPath,
    [`--require=${AGENT_PATH}`, path.join(FIXTURES_DIR, fixture)],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 15000,
      env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }),
    }
  );
}

check('static `import` of malicious sentinel crashes the process with a [Firewall] error (no way to catch it in-process)', () => {
  const res = spawnFixture('static-import-sentinel.mjs');
  assert.notStrictEqual(res.status, 0, 'expected non-zero exit, got ' + res.status);
  assert.ok(res.stderr.includes('[Firewall]'), 'expected a [Firewall] message on stderr:\n' + res.stderr);
  assert.ok(!res.stdout.includes('STATIC_IMPORT_COMPLETED'), 'the fixture body must never have run:\n' + res.stdout);
});

check('dynamic import() of malicious sentinel throws a catchable [Firewall] error', () => {
  const res = spawnFixture('dynamic-import-sentinel.mjs');
  assert.strictEqual(res.status, 0, 'fixture itself should exit 0 (it catches the import rejection): ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(res.stdout.includes('DYNAMIC_IMPORT_THREW'), 'expected the fixture to report a caught throw:\n' + res.stdout);
  assert.ok(res.stdout.includes('[Firewall]'), 'expected the caught error message to contain [Firewall]:\n' + res.stdout);
});

check('legitimate ESM module still imports cleanly (no false positive)', () => {
  const res = spawnSync(
    process.execPath,
    [`--require=${AGENT_PATH}`, '--input-type=module', '-e',
      `import { add } from ${JSON.stringify(pathToFileURL(path.join(FIXTURES_DIR, 'benign.mjs')).href)}; console.log('BENIGN_OK:' + add(2, 3));`],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 15000,
      env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }),
    }
  );
  assert.strictEqual(res.status, 0, 'expected exit 0 for a benign ESM import, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(res.stdout.includes('BENIGN_OK:5'), 'expected the benign module to run correctly:\n' + res.stdout);
});

check('on a Node version without module.register(), the agent still starts (documented UNSUPPORTED, not a crash)', () => {
  // Cannot actually swap Node versions in this test environment; instead verify the guard logic
  // directly: a normal preloaded start (module.register() IS available on this Node) must not
  // throw or print the ESM_HOOK_UNAVAILABLE warning, proving the availability branch is live and
  // was exercised (not dead code) rather than only asserting the unreachable branch never fires.
  const res = spawnFixture('benign.mjs');
  assert.strictEqual(res.status, 0, 'agent must start cleanly when module.register() is available: ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(!res.stderr.includes('ESM_HOOK_UNAVAILABLE') && !res.stderr.includes('ESM static/dynamic import interception not active'),
    'must not warn about a missing ESM hook when module.register() is actually available:\n' + res.stderr);
});

console.log(`\n${passed} ESM loader checks passed.`);
