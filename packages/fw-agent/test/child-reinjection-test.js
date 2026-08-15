// packages/fw-agent/test/child-reinjection-test.js
// P0-4: real spawns (spawnSync/Worker), no mocking. Verifies the firewall closes the
// child-process / worker escape: a firewalled parent's NODE_OPTIONS now propagates the agent to
// any spawned node process, and file-based Workers get an explicit --require injected into
// execArgv, while non-node children and eval-string workers are left alone / clearly unsupported.
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
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

function mkTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const tmp = mkTmpDir('fw-child-reinjection-');

// A module whose source contains a literal BLOCK_SIGNATURE (stratum+tcp://) so any harness that
// loads it through a hooked Module.prototype._compile reliably throws.
const sentinelPath = path.join(tmp, 'sentinel.js');
fs.writeFileSync(sentinelPath, "var SENTINEL = 'stratum+tcp://sentinel.invalid';\nmodule.exports = { ran: true };\n");

function spawnFirewalledParent(parentScriptPath, envExtra) {
  return spawnSync(process.execPath, [`--require=${AGENT_PATH}`, parentScriptPath], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 20000,
    env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, envExtra),
  });
}

// ── TP: child_process.spawn('node', ...) is now INTERCEPTED (the live escape being closed) ────
(function tpSpawnBlocked() {
  const childScript = path.join(tmp, 'spawn-child.js');
  fs.writeFileSync(childScript, `
    try {
      require(${JSON.stringify(sentinelPath)});
      console.log('CHILD_RESULT: ran');
    } catch (e) {
      console.log('CHILD_RESULT: blocked ' + e.message);
    }
  `);
  const parentScript = path.join(tmp, 'spawn-parent.js');
  fs.writeFileSync(parentScript, `
    const { spawnSync } = require('child_process');
    const res = spawnSync(process.execPath, [${JSON.stringify(childScript)}], { encoding: 'utf8', env: process.env });
    process.stdout.write(res.stdout || '');
    process.stderr.write(res.stderr || '');
  `);
  const res = spawnFirewalledParent(parentScript);
  check("TP: child_process.spawn('node', ...) child is blocked from loading the sentinel (escape closed)", () => {
    assert.ok(res.stdout.includes('CHILD_RESULT: blocked'), 'expected child to be blocked, got:\n' + res.stdout + '\n' + res.stderr);
    assert.ok(res.stdout.includes('[Firewall]'), 'expected a [Firewall] error message:\n' + res.stdout);
  });
})();

// ── Control: firewalled parent spawning a non-node process runs normally, env not corrupted ───
(function controlNonNode() {
  const parentScript = path.join(tmp, 'nonnode-parent.js');
  fs.writeFileSync(parentScript, `
    const { spawnSync } = require('child_process');
    const res = spawnSync('node', ['--version'], { encoding: 'utf8', env: process.env });
    // Also exercise a genuinely non-node binary to prove NODE_OPTIONS doesn't affect it at all.
    const echoRes = spawnSync('echo', ['hello-from-non-node'], { encoding: 'utf8', env: process.env });
    console.log('NODE_VERSION_STATUS:' + res.status);
    console.log('ECHO_STATUS:' + echoRes.status);
    console.log('ECHO_STDOUT:' + (echoRes.stdout || '').trim());
  `);
  const res = spawnFirewalledParent(parentScript);
  check('control: a non-node child process runs normally and NODE_OPTIONS does not corrupt it', () => {
    assert.ok(res.stdout.includes('NODE_VERSION_STATUS:0'), 'expected node --version to succeed:\n' + res.stdout + '\n' + res.stderr);
    assert.ok(res.stdout.includes('ECHO_STATUS:0'), 'expected echo to succeed:\n' + res.stdout + '\n' + res.stderr);
    assert.ok(res.stdout.includes('ECHO_STDOUT:hello-from-non-node'), 'expected echo output to be unaffected:\n' + res.stdout);
  });
})();

// ── No double-injection: nested children see exactly one --require <agent> in NODE_OPTIONS ────
(function noDoubleInjection() {
  const grandchildScript = path.join(tmp, 'nested-grandchild.js');
  fs.writeFileSync(grandchildScript, `console.log('GRANDCHILD_NODE_OPTIONS:' + (process.env.NODE_OPTIONS || ''));`);
  const childScript = path.join(tmp, 'nested-child.js');
  fs.writeFileSync(childScript, `
    // This child itself requires the agent again (as if it bootstrapped its own copy), then
    // spawns a grandchild — NODE_OPTIONS must not accumulate a second --require for the agent.
    require(${JSON.stringify(AGENT_PATH)});
    console.log('CHILD_NODE_OPTIONS:' + (process.env.NODE_OPTIONS || ''));
    const { spawnSync } = require('child_process');
    const res = spawnSync(process.execPath, [${JSON.stringify(grandchildScript)}], { encoding: 'utf8', env: process.env });
    process.stdout.write(res.stdout || '');
  `);
  const parentScript = path.join(tmp, 'nested-parent.js');
  fs.writeFileSync(parentScript, `
    const { spawnSync } = require('child_process');
    const res = spawnSync(process.execPath, [${JSON.stringify(childScript)}], { encoding: 'utf8', env: process.env });
    process.stdout.write(res.stdout || '');
    process.stderr.write(res.stderr || '');
  `);
  const res = spawnFirewalledParent(parentScript, { FW_ALLOW_DEV_POLICY_KEY: '1', FW_ENABLE_DETECTION: '1' });
  check('no double-injection: nested children carry exactly one --require <agent> in NODE_OPTIONS', () => {
    const childLine = /CHILD_NODE_OPTIONS:(.*)/.exec(res.stdout);
    const grandchildLine = /GRANDCHILD_NODE_OPTIONS:(.*)/.exec(res.stdout);
    assert.ok(childLine, 'missing CHILD_NODE_OPTIONS line:\n' + res.stdout + '\n' + res.stderr);
    assert.ok(grandchildLine, 'missing GRANDCHILD_NODE_OPTIONS line:\n' + res.stdout + '\n' + res.stderr);
    const countOccurrences = (str) => (str.match(/--require[= ]\S*index\.js/g) || []).length;
    assert.strictEqual(countOccurrences(childLine[1]), 1, 'expected exactly one --require <agent> in child NODE_OPTIONS, got: ' + childLine[1]);
    assert.strictEqual(countOccurrences(grandchildLine[1]), 1, 'expected exactly one --require <agent> in grandchild NODE_OPTIONS, got: ' + grandchildLine[1]);
  });
})();

// ── Worker: file-based worker requiring the sentinel is INTERCEPTED ────────────────────────────
(function workerIntercepted() {
  const workerScript = path.join(tmp, 'worker-child.js');
  fs.writeFileSync(workerScript, `
    const { parentPort } = require('worker_threads');
    try {
      require(${JSON.stringify(sentinelPath)});
      parentPort.postMessage({ status: 'ran' });
    } catch (e) {
      parentPort.postMessage({ status: 'blocked', message: e.message });
    }
  `);
  const parentScript = path.join(tmp, 'worker-parent.js');
  const outFile = path.join(tmp, 'worker-result.json');
  fs.writeFileSync(parentScript, `
    const { Worker } = require('worker_threads');
    const fs = require('fs');
    const w = new Worker(${JSON.stringify(workerScript)});
    const timer = setTimeout(() => { fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ status: 'timeout' })); process.exit(1); }, 15000);
    w.on('message', (msg) => { clearTimeout(timer); fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify(msg)); process.exit(0); });
    w.on('error', (err) => { clearTimeout(timer); fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ status: 'error', message: err.message })); process.exit(1); });
  `);
  spawnFirewalledParent(parentScript);
  const result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  check('worker: file-based Worker requiring the sentinel is INTERCEPTED', () => {
    assert.strictEqual(result.status, 'blocked', 'expected worker to be blocked: ' + JSON.stringify(result));
    assert.ok(result.message && result.message.includes('[Firewall]'), 'expected a [Firewall] message: ' + JSON.stringify(result));
  });
})();

// ── Worker: eval-string worker is UNSUPPORTED, with a warning ──────────────────────────────────
(function evalWorkerUnsupported() {
  const parentScript = path.join(tmp, 'eval-worker-parent.js');
  fs.writeFileSync(parentScript, `
    const { Worker } = require('worker_threads');
    const w = new Worker("require('worker_threads').parentPort.postMessage('ran');", { eval: true });
    w.on('message', () => process.exit(0));
    w.on('error', () => process.exit(1));
  `);
  const res = spawnFirewalledParent(parentScript);
  check('worker: eval-string Worker is reported UNSUPPORTED via a warning (cannot preload into an eval body)', () => {
    assert.ok(/cannot be re-injected/.test(res.stderr), 'expected the eval-worker-unsupported warning on stderr:\n' + res.stderr);
  });
})();

fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\n${passed} child/worker re-injection checks passed.`);
