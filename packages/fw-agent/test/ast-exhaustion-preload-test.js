// packages/fw-agent/test/ast-exhaustion-preload-test.js
// F-91: span-exhaustion / decoy-flood bypass — verified through the REAL preload hook, not just
// AstScanner.scan(). A child process is started with the firewall genuinely preloaded via
// --require and FW_ENABLE_AST=1, then require()s a malicious module whose bracket+concat eval
// payload sits behind a flood of >40 harmless prescreen-matching decoy spans. Before the fix the
// firewall scanned candidate spans in file-position order and stopped after a fixed count, so the
// payload span was never parsed and require() succeeded. After the fix the firewall scans
// highest-risk-first and the require() must be blocked (the _compile hook throws a COMPILATION
// LOCKDOWN, so the child exits non-zero).
'use strict';
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
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
    console.error('  ✗ ' + name + '\n    ' + ((e && e.stack) || e));
    process.exit(1);
  }
}

const filler = 'x'.repeat(2100); // > MAX_SPAN_CHARS so each decoy line is its own distinct span
const decoys = Array.from({ length: 45 }, (_, i) => `const benign${i} = String.fromCharCode(65);${filler};`).join('\n');
// Bracket+concat obfuscated eval — no literal "eval(" call site; only the AST tier resolves it.
const evalPayload = "\nconst run = this['ev' + 'al'];\nrun('1+1');\n";
// Engineered high-risk decoy flood used to force an incomplete scan (each is a benign concat
// bracket access — high-risk by shape, harmless by value).
const hiRiskDecoys = Array.from({ length: 300 }, (_, i) => `const z${i} = obj['xx' + 'yy'];${filler}`).join('\n');

function writeModule(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-exhaustion-'));
  const file = path.join(dir, 'evil.js');
  fs.writeFileSync(file, `${body}\nmodule.exports = {};\n`);
  return file;
}

// Child requires `modulePath` with the firewall genuinely preloaded. Returns the spawn result.
function requireThroughPreload(modulePath, envExtra) {
  return spawnSync(
    process.execPath,
    [`--require=${AGENT_PATH}`, '-e', `require(${JSON.stringify(modulePath)}); console.log('LOADED-OK');`],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 20000,
      env: Object.assign(
        {},
        process.env,
        { FW_ENABLE_DETECTION: '1', FW_ENABLE_AST: '1', FW_ALLOW_DEV_POLICY_KEY: '1', FW_MODE: 'dev' },
        envExtra
      ),
    }
  );
}

check('preload hook blocks a bracket-eval payload hidden behind a 45-decoy flood', () => {
  const file = writeModule(decoys + evalPayload);
  const res = requireThroughPreload(file);
  assert.notStrictEqual(res.status, 0, 'require() must be blocked (non-zero exit), got ' + res.status + '\nstdout:\n' + res.stdout + '\nstderr:\n' + res.stderr);
  assert.ok(!/LOADED-OK/.test(res.stdout), 'the malicious module must not have loaded successfully');
  assert.ok(/COMPILATION LOCKDOWN/.test(res.stderr), 'expected a COMPILATION LOCKDOWN banner on stderr:\n' + res.stderr);
});

check('preload hook allows a clean module of the same size (no false positive)', () => {
  const cleanBody = Array.from({ length: 300 }, (_, i) => `const a${i} = (0, require)('m${i}');${filler}`).join('\n');
  // require('mN') will throw MODULE_NOT_FOUND at runtime, so only compile-scan the module without
  // executing its body: wrap the requires so they never actually run, keeping the firewall's
  // compile-time scan the thing under test.
  const guarded = `function load(){ ${cleanBody} } if (false) load();`;
  const file = writeModule(guarded);
  const res = requireThroughPreload(file);
  assert.strictEqual(res.status, 0, 'a clean module must load (exit 0), got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/LOADED-OK/.test(res.stdout), 'expected the clean module to load:\n' + res.stdout);
});

check('FW_AST_INCOMPLETE_POLICY=quarantine blocks an un-analyzable high-risk flood through the hook', () => {
  const file = writeModule(hiRiskDecoys + evalPayload);
  const res = requireThroughPreload(file, { FW_AST_INCOMPLETE_POLICY: 'quarantine' });
  assert.notStrictEqual(res.status, 0, 'quarantine policy must block an incomplete-scan module, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/COMPILATION LOCKDOWN/.test(res.stderr), 'expected a COMPILATION LOCKDOWN banner on stderr:\n' + res.stderr);
});

check('FW_AST_INCOMPLETE_POLICY=observe (default) does not block on incompleteness alone', () => {
  // A benign high-risk flood with NO real payload: under the default observe policy the module
  // still loads (incompleteness is telemetry-only), so we confirm observe never over-blocks. The
  // flood is wrapped in a never-called function so the firewall still compile-scans every line
  // (the thing under test) while the module body itself executes nothing.
  const file = writeModule('function dead(){\n' + hiRiskDecoys + '\n} if (false) dead();');
  const res = requireThroughPreload(file);
  assert.strictEqual(res.status, 0, 'default observe policy must not block on incompleteness, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/LOADED-OK/.test(res.stdout), 'expected the module to load under observe policy:\n' + res.stdout);
});

console.log(`\nAST exhaustion preload test passed (${passed}).`);
