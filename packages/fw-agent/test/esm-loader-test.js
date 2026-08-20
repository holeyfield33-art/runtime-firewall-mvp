// packages/fw-agent/test/esm-loader-test.js
// P2-01: direct unit coverage for the ESM Module Customization Hook (index.js's
// Module.registerHooks() load hook), via real child processes (spawnSync, not mocked) exercising
// genuine Node ESM semantics — a static `import` declaration cannot be caught in-process (see
// esm-fixtures/static-import-sentinel.mjs for why), so this asserts on the crashed child's exit
// code and stderr, not a caught exception.
//
// module.registerHooks() requires Node >=22.15.0/>=23.5.0 (see index.js's own comment at the
// registration site). CI runs this on Node 18/20/22/24 (.github/workflows/ci.yml) — below the
// floor, ESM interception is an honest, documented UNSUPPORTED bypass, not a bug, so the checks
// that assert interception must condition on whether the hook is actually available on the Node
// running this test, not hard-assert a single outcome regardless of version.
'use strict';
const assert = require('assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { spawnSync } = require('child_process');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');
const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const FIXTURES_DIR = path.join(__dirname, 'esm-fixtures');
const REGISTER_HOOKS_AVAILABLE = typeof require('module').registerHooks === 'function';

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

function spawnFixture(fixture, extraEnv) {
  return spawnSync(
    process.execPath,
    [`--require=${AGENT_PATH}`, path.join(FIXTURES_DIR, fixture)],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 15000,
      env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, extraEnv),
    }
  );
}

check(REGISTER_HOOKS_AVAILABLE
  ? 'static `import` of malicious sentinel crashes the process with a [Firewall] error (no way to catch it in-process)'
  : `static \`import\` of malicious sentinel completes uncaught (honest BYPASS — registerHooks() unavailable on ${process.version})`, () => {
  const res = spawnFixture('static-import-sentinel.mjs');
  if (REGISTER_HOOKS_AVAILABLE) {
    assert.notStrictEqual(res.status, 0, 'expected non-zero exit, got ' + res.status);
    assert.ok(res.stderr.includes('[Firewall]'), 'expected a [Firewall] message on stderr:\n' + res.stderr);
    assert.ok(!res.stdout.includes('STATIC_IMPORT_COMPLETED'), 'the fixture body must never have run:\n' + res.stdout);
  } else {
    assert.strictEqual(res.status, 0, 'below the registerHooks() floor the import is not intercepted at all, so the fixture body runs and exits 0: ' + res.status + '\nstderr:\n' + res.stderr);
    assert.ok(res.stdout.includes('STATIC_IMPORT_COMPLETED'), 'expected the fixture body to have run (honest, disclosed bypass):\n' + res.stdout);
  }
});

check(REGISTER_HOOKS_AVAILABLE
  ? 'dynamic import() of malicious sentinel throws a catchable [Firewall] error'
  : `dynamic import() of malicious sentinel resolves uncaught (honest BYPASS — registerHooks() unavailable on ${process.version})`, () => {
  const res = spawnFixture('dynamic-import-sentinel.mjs');
  assert.strictEqual(res.status, 0, 'fixture itself always exits 0 (it catches the import rejection when one occurs): ' + res.status + '\nstderr:\n' + res.stderr);
  if (REGISTER_HOOKS_AVAILABLE) {
    assert.ok(res.stdout.includes('DYNAMIC_IMPORT_THREW'), 'expected the fixture to report a caught throw:\n' + res.stdout);
    assert.ok(res.stdout.includes('[Firewall]'), 'expected the caught error message to contain [Firewall]:\n' + res.stdout);
  } else {
    assert.ok(res.stdout.includes('DYNAMIC_IMPORT_COMPLETED'), 'expected the import to resolve cleanly (honest, disclosed bypass):\n' + res.stdout);
  }
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

check(REGISTER_HOOKS_AVAILABLE
  ? 'when Module.registerHooks() is available, the agent starts without ESM_HOOK_UNAVAILABLE warnings'
  : `when Module.registerHooks() is unavailable (Node ${process.version}), the agent still starts cleanly and discloses the gap (documented UNSUPPORTED, not a crash)`, () => {
  const res = spawnFixture('benign.mjs');
  assert.strictEqual(res.status, 0, 'agent must start cleanly either way: ' + res.status + '\nstderr:\n' + res.stderr);
  const warnedAboutEsm = res.stderr.includes('ESM_HOOK_UNAVAILABLE') || res.stderr.includes('ESM static/dynamic import interception not active');
  if (REGISTER_HOOKS_AVAILABLE) {
    assert.ok(!warnedAboutEsm, 'must not warn about a missing ESM hook when registerHooks() is actually available:\n' + res.stderr);
  } else {
    assert.ok(warnedAboutEsm, 'must honestly disclose that ESM interception is unavailable below the registerHooks() floor, not silently claim coverage:\n' + res.stderr);
  }
});

check('no DeprecationWarning is emitted (confirms registerHooks(), not the deprecated register(), is in use)', () => {
  const res = spawnFixture('benign.mjs');
  assert.strictEqual(res.status, 0, 'expected exit 0: ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(!/DeprecationWarning/.test(res.stderr), 'must not trigger a deprecation warning:\n' + res.stderr);
});

// N-03 / P-D: FW_REQUIRE_ESM_COVERAGE=1 is a separate, more specific opt-in than FW_MODE=enforce
// -- "I require ESM coverage specifically," not just "I require the agent to be preloaded." Like
// the checks above, the outcome it produces is genuinely Node-version-dependent, so condition on
// REGISTER_HOOKS_AVAILABLE rather than hard-asserting one branch.
check(REGISTER_HOOKS_AVAILABLE
  ? `FW_REQUIRE_ESM_COVERAGE=1 does not misfire when registerHooks() is genuinely available (Node ${process.version})`
  : `FW_REQUIRE_ESM_COVERAGE=1 fails closed when registerHooks() is unavailable (Node ${process.version})`, () => {
  const res = spawnFixture('benign.mjs', { FW_REQUIRE_ESM_COVERAGE: '1' });
  if (REGISTER_HOOKS_AVAILABLE) {
    assert.strictEqual(res.status, 0, 'the flag must not fail closed when ESM coverage is genuinely active: ' + res.status + '\nstderr:\n' + res.stderr);
  } else {
    assert.notStrictEqual(res.status, 0, 'expected a non-zero exit when ESM coverage is required but unavailable, got ' + res.status);
    assert.ok(res.stderr.includes('ESM_HOOK_UNAVAILABLE') || res.stderr.includes('not active'), 'expected the ESM_HOOK_UNAVAILABLE / "not active" message on stderr:\n' + res.stderr);
  }
});

check('FW_REQUIRE_ESM_COVERAGE unset (default) leaves ESM-unavailable behavior unchanged from before this flag existed', () => {
  const res = spawnFixture('benign.mjs');
  assert.strictEqual(res.status, 0, 'agent must start cleanly regardless of registerHooks() availability when the flag is unset: ' + res.status + '\nstderr:\n' + res.stderr);
});

// ── F-79: CommonJS loaded THROUGH the ESM loader (import of a CJS package) ────────────────────
// `import x from 'cjs-pkg'` uses Node's CJS-through-ESM interop: the load hook fires with
// result.format === 'commonjs', Module._cache is populated, but Module.prototype._compile is never
// called. The load hook now runs that interop-CJS source through the SAME scan-and-policy path as
// _compile and only THEN marks it verified. This closes a detection gap (malicious CJS imported via
// ESM previously ran unscanned) and a false positive (the later require() of the same CJS package
// was refused by the F-58 cache gate as an "unverified" entry -- the real vite/astro-picomatch FP).
// The scan path lives entirely in the registerHooks() load hook, so these assertions are gated on
// its availability; below the floor, ESM interception is a documented UNSUPPORTED bypass anyway.
check(REGISTER_HOOKS_AVAILABLE
  ? 'F-79 TP: malicious CJS imported via ESM (interop) is BLOCKED -- previously ran unscanned'
  : `F-79 TP: skipped -- registerHooks() unavailable on ${process.version} (ESM-interop scan path not present)`, () => {
  if (!REGISTER_HOOKS_AVAILABLE) return;
  const res = spawnFixture('import-interop-cjs-malicious.mjs');
  assert.notStrictEqual(res.status, 0, 'expected non-zero exit (interop-CJS import blocked), got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(res.stderr.includes('[Firewall]'), 'expected a [Firewall] detection on stderr:\n' + res.stderr);
  assert.ok(!res.stdout.includes('INTEROP_CJS_MALICIOUS_RAN'), 'the malicious CJS body must never have run:\n' + res.stdout);
});

check(REGISTER_HOOKS_AVAILABLE
  ? 'F-79 FP: benign CJS imported via ESM then require()d loads clean under FW_CACHE_POLICY=block'
  : `F-79 FP: skipped -- registerHooks() unavailable on ${process.version} (ESM-interop scan path not present)`, () => {
  if (!REGISTER_HOOKS_AVAILABLE) return;
  const res = spawnFixture('import-then-require-benign-cjs.mjs', { FW_CACHE_POLICY: 'block' });
  assert.strictEqual(res.status, 0, 'expected exit 0 (no cache-substitution false positive), got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(res.stdout.includes('INTEROP_CJS_BENIGN_OK'), 'expected the benign interop-CJS to import and require() cleanly:\n' + res.stdout);
  assert.ok(!/cache-substitution|Refused to load/.test(res.stderr), 'must not trip the F-58 cache gate on the now-verified interop-CJS entry:\n' + res.stderr);
});

console.log(`\n${passed} ESM loader checks passed.`);
