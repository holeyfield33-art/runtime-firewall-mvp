// packages/fw-agent/test/telemetry-worker-failure-test.js
// F-21.1 (P0-3) + F-21.2 (P0-4): telemetry is optional/best-effort observability, and must never
// take down the protected host.
//   - F-21.1: `new Worker(...)` can itself throw synchronously (resource exhaustion, missing
//     worker file, sandbox/permission errors). Unwrapped, that exception previously propagated
//     straight out of module load and crashed the host on startup.
//   - F-21.2: `Worker` is an EventEmitter. With no 'error' listener attached, Node re-throws an
//     unhandled 'error' event, crashing the *parent* process — a telemetry-worker crash minutes
//     into a long-running process previously could take the protected host down with it.
//
// Both scenarios are reproduced with a real, spawned `--require`-preloaded firewalled child
// process (matching this suite's convention), using a preload shim that monkeypatches
// Module._load to intercept `require('worker_threads')` before the agent loads it. This exercises
// the REAL EventEmitter unhandled-'error'-throws hazard (Node's real Worker class is itself an
// EventEmitter) rather than a hand-rolled simulation of the crash mechanism.
'use strict';
process.env.FW_ENABLE_DETECTION = '1';

const crypto = require('crypto');
const { publicKey: TEST_PUBLIC_KEY, privateKey: TEST_PRIVATE_KEY } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { signPolicy } = require('../../../scripts/sign-policy');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');

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

function readAuditEvents(logDir) {
  const logPath = path.join(logDir, 'audit.log');
  if (!fs.existsSync(logPath)) return [];
  return fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

// Shared setup for both scenarios: a firewalled child with FW_TELEMETRY=1, a real signed policy
// (BLOCK on "evil-dep") to prove enforcement keeps working after telemetry degrades, and its own
// HELIOS_LOG_DIR so we can inspect the audit trail afterward.
function setupChildEnv(prefix) {
  const tmp = mkTmpDir(prefix);
  const logDir = mkTmpDir(prefix + 'log-');
  const evilDir = path.join(tmp, 'node_modules', 'evil-dep');
  fs.mkdirSync(evilDir, { recursive: true });
  fs.writeFileSync(path.join(evilDir, 'package.json'), JSON.stringify({ name: 'evil-dep', version: '1.0.0' }));
  fs.writeFileSync(path.join(evilDir, 'index.js'), 'module.exports = "evil-dep-loaded";\n');

  const signed = signPolicy({ 'evil-dep': 'BLOCK' }, TEST_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  return { tmp, logDir, evilDir };
}

function runChild(tmp, logDir, preloadShimPath, childScriptPath) {
  return spawnSync(process.execPath, [`--require=${preloadShimPath}`, `--require=${AGENT_PATH}`, childScriptPath], {
    cwd: tmp,
    encoding: 'utf8',
    env: Object.assign({}, process.env, {
      FW_ENABLE_DETECTION: '1',
      FW_TELEMETRY: '1',
      FW_POLICY_PUBKEY: TEST_PUBLIC_KEY,
      HELIOS_LOG_DIR: logDir,
    }),
    timeout: 15000,
  });
}

const CHILD_SCRIPT = `
  const path = require('path');
  let blockError = null;
  try { require(path.join(process.cwd(), 'node_modules', 'evil-dep', 'index.js')); } catch (e) { blockError = e.message; }
  console.log('RESULT:' + JSON.stringify({ blockError }));
`;

function parseResult(stdout) {
  const m = /RESULT:(.*)/.exec(stdout || '');
  if (!m) throw new Error('child produced no RESULT: line. stdout=\n' + stdout + '\nstderr=\n');
  return JSON.parse(m[1]);
}

// ── Scenario 1 (F-21.1): synchronous Worker construction failure ─────────────────────────────
(function constructionFailure() {
  const { tmp, logDir } = setupChildEnv('fw-telemetry-construct-fail-');

  const shimPath = path.join(tmp, 'throwing-worker-shim.js');
  fs.writeFileSync(shimPath, `
    const Module = require('module');
    const realLoad = Module._load;
    Module._load = function (request, parent, isMain) {
      if (request === 'worker_threads') {
        const real = realLoad.call(this, request, parent, isMain);
        class ThrowingWorker {
          constructor() { throw new Error('EMFILE: simulated worker construction failure (test)'); }
        }
        return Object.assign({}, real, { Worker: ThrowingWorker });
      }
      return realLoad.call(this, request, parent, isMain);
    };
  `);

  const childScriptPath = path.join(tmp, 'child.js');
  fs.writeFileSync(childScriptPath, CHILD_SCRIPT);

  const res = runChild(tmp, logDir, shimPath, childScriptPath);

  check('F-21.1: a synchronous Worker construction failure does not crash the host on startup', () => {
    assert.strictEqual(res.status, 0, 'child process must exit cleanly despite the construction failure: stderr=\n' + res.stderr);
  });

  check('F-21.1: firewall enforcement (BLOCK policy) still runs after telemetry fails to start', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.blockError && result.blockError.includes('[Firewall]'), 'evil-dep must still be blocked: ' + JSON.stringify(result));
  });

  check('F-21.1: a console warning reports the degraded telemetry state', () => {
    assert.ok(res.stderr.includes('[Firewall] Telemetry worker failed to start'), 'expected a telemetry-degraded warning on stderr, got:\n' + res.stderr);
  });

  check('F-21.1: a TELEMETRY_DEGRADED audit event records the construction failure', () => {
    const events = readAuditEvents(logDir);
    const degraded = events.find((e) => e.eventType === 'TELEMETRY_DEGRADED');
    assert.ok(degraded, 'expected a TELEMETRY_DEGRADED audit event, got: ' + JSON.stringify(events));
    assert.strictEqual(degraded.reason, 'failed to start');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

// ── Scenario 2 (F-21.2): asynchronous Worker 'error' after successful construction ────────────
(function asyncWorkerError() {
  const { tmp, logDir } = setupChildEnv('fw-telemetry-async-crash-');

  const shimPath = path.join(tmp, 'crashing-worker-shim.js');
  fs.writeFileSync(shimPath, `
    const Module = require('module');
    const { EventEmitter } = require('events');
    const realLoad = Module._load;
    Module._load = function (request, parent, isMain) {
      if (request === 'worker_threads') {
        const real = realLoad.call(this, request, parent, isMain);
        // A real EventEmitter that "starts up" fine, then crashes asynchronously shortly after
        // construction -- exactly the shape of an uncaught exception inside the real worker
        // thread, which Node surfaces as an 'error' event on the parent-side Worker handle.
        class CrashingWorker extends EventEmitter {
          constructor() {
            super();
            setImmediate(() => this.emit('error', new Error('simulated worker crash (test)')));
          }
          unref() {}
          postMessage() {}
          terminate() { return Promise.resolve(0); }
        }
        return Object.assign({}, real, { Worker: CrashingWorker });
      }
      return realLoad.call(this, request, parent, isMain);
    };
  `);

  const childScriptPath = path.join(tmp, 'child.js');
  // Give the setImmediate-scheduled 'error' event time to fire before the process would otherwise
  // exit, then exercise enforcement (which must still be running) and report.
  fs.writeFileSync(childScriptPath, `
    const path = require('path');
    setTimeout(() => {
      let blockError = null;
      try { require(path.join(process.cwd(), 'node_modules', 'evil-dep', 'index.js')); } catch (e) { blockError = e.message; }
      console.log('RESULT:' + JSON.stringify({ blockError }));
    }, 200);
  `);

  const res = runChild(tmp, logDir, shimPath, childScriptPath);

  check('F-21.2: an unhandled asynchronous Worker \'error\' event does not crash the host', () => {
    assert.strictEqual(res.status, 0, 'child process must survive the worker crash: stderr=\n' + res.stderr);
  });

  check('F-21.2: firewall enforcement (BLOCK policy) still runs after the telemetry worker crashes', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.blockError && result.blockError.includes('[Firewall]'), 'evil-dep must still be blocked: ' + JSON.stringify(result));
  });

  check('F-21.2: a console warning reports the degraded telemetry state', () => {
    assert.ok(res.stderr.includes('[Firewall] Telemetry worker crashed'), 'expected a telemetry-degraded warning on stderr, got:\n' + res.stderr);
  });

  check('F-21.2: a TELEMETRY_DEGRADED audit event records the crash, logged exactly once', () => {
    const events = readAuditEvents(logDir);
    const degradedEvents = events.filter((e) => e.eventType === 'TELEMETRY_DEGRADED');
    assert.strictEqual(degradedEvents.length, 1, 'expected exactly one TELEMETRY_DEGRADED event (not spammed), got: ' + JSON.stringify(events));
    assert.strictEqual(degradedEvents[0].reason, 'crashed');
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

console.log(`\n${passed} telemetry-worker-failure checks passed.`);
process.exit(0);
