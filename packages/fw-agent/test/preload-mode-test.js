// packages/fw-agent/test/preload-mode-test.js
// P0-3: preload fail-closed semantics via real child-process exit codes (spawnSync, not
// mocked). Verifies FW_MODE=enforce/dev, the FW_STRICT_PRELOAD=1 backward-compat alias, and
// that the preload-spoofing guard (node -e "require(agent)") is still NOT treated as preloaded.
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

function spawnRequireSpoof(envExtra) {
  // `node -e "require(agent)"` — the classic preload-spoof attempt: the inline script text
  // (which contains the string "fw-agent") ends up in the parent's argv, NOT in execArgv, so
  // it must never be mistaken for a genuine --require preload.
  return spawnSync(
    process.execPath,
    ['-e', `require(${JSON.stringify(AGENT_PATH)})`],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 15000,
      env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, envExtra),
    }
  );
}

function spawnRealPreload(envExtra) {
  return spawnSync(
    process.execPath,
    [`--require=${AGENT_PATH}`, '-e', 'console.log("preloaded-ok")'],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 15000,
      env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, envExtra),
    }
  );
}

check('FW_MODE=enforce + no preload => child exits non-zero', () => {
  const res = spawnRequireSpoof({ FW_MODE: 'enforce' });
  assert.notStrictEqual(res.status, 0, 'expected non-zero exit, got ' + res.status);
  assert.ok(/CRITICAL/.test(res.stderr), 'expected a [CRITICAL] message on stderr:\n' + res.stderr);
});

check('FW_MODE=dev + no preload => continues, warning on stderr', () => {
  const res = spawnRequireSpoof({ FW_MODE: 'dev' });
  assert.strictEqual(res.status, 0, 'expected exit 0, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/WARNING/.test(res.stderr), 'expected a WARNING banner on stderr:\n' + res.stderr);
});

check('unset FW_MODE (default) + no preload => continues (dev is the default), warning on stderr', () => {
  const env = Object.assign({}, process.env);
  delete env.FW_MODE;
  delete env.FW_STRICT_PRELOAD;
  const res = spawnSync(
    process.execPath,
    ['-e', `require(${JSON.stringify(AGENT_PATH)})`],
    { cwd: REPO_ROOT, encoding: 'utf8', timeout: 15000, env: Object.assign(env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }) }
  );
  assert.strictEqual(res.status, 0, 'expected exit 0 by default, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/WARNING/.test(res.stderr), 'expected a WARNING banner on stderr:\n' + res.stderr);
});

check('FW_STRICT_PRELOAD=1 + no preload => exits non-zero (backward-compat alias for enforce)', () => {
  const res = spawnRequireSpoof({ FW_STRICT_PRELOAD: '1' });
  assert.notStrictEqual(res.status, 0, 'expected non-zero exit, got ' + res.status);
  assert.ok(/CRITICAL/.test(res.stderr), 'expected a [CRITICAL] message on stderr:\n' + res.stderr);
});

check('regression: node -e "require(agent)" spoof with enforce is still NOT preloaded (exits non-zero)', () => {
  // Same assertion as the enforce test above, phrased as an explicit regression guard against
  // the earlier substring-search preload check being reintroduced.
  const res = spawnRequireSpoof({ FW_MODE: 'enforce' });
  assert.notStrictEqual(res.status, 0, 'preload spoof must still be rejected under enforce, got exit ' + res.status);
});

check('genuine --require preload under FW_MODE=enforce continues normally (no false rejection)', () => {
  const res = spawnRealPreload({ FW_MODE: 'enforce' });
  assert.strictEqual(res.status, 0, 'expected exit 0 for a real preload, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(res.stdout.includes('preloaded-ok'), 'expected child script to have run:\n' + res.stdout);
  assert.ok(!/CRITICAL/.test(res.stderr), 'must not print the not-preloaded CRITICAL message:\n' + res.stderr);
});

console.log(`\n${passed} preload-mode checks passed.`);
