// packages/fw-agent/test/telemetry-adversarial-resilience-test.js
// Investigation for #108 (follow-up to #88/#89, F-21.1/F-21.2, fixed in #104): those fixes prove
// telemetry construction/async-worker FAILURES degrade gracefully. This file asks the sharper
// question the fix itself doesn't answer -- can a malicious package's OWN behavior (content it
// controls: property names it forces the quarantine proxy to record, its own package identity,
// detection matches derived from its own source) *intentionally* trigger that same crash path,
// giving it an observability-denial primitive even though it can't bypass containment?
//
// This drives a REAL firewalled child with a REAL telemetry Worker and REAL sync-worker.js (no
// Module._load shim substituting a fake Worker, unlike telemetry-worker-failure-test.js) --
// the adversary here isn't the Worker plumbing, it's the DATA a quarantined package can push
// through it. Every case below exercises data the attacker actually controls:
//   - extremely long property names (Symbol descriptions and string keys can be huge)
//   - exotic/prototype-pollution-shaped property names (__proto__, constructor, toString)
//   - a rapid-fire flood well beyond the existing rate limiter, against the real worker mailbox
//   - a real telemetry Worker whose HTTP POST target (the control plane) is unreachable
// and confirms, throughout: the host process survives, enforcement never stops, local audit
// logging keeps working regardless of what the remote telemetry pipeline does, and no more than
// one degraded-state indicator fires even under repeated/adversarial pressure.
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
const { spawnSync, execFileSync } = require('child_process');
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

// Binds an OS-assigned port and closes it immediately, so "unreachable control plane" targets a
// genuinely free port instead of a hardcoded one that could coincidentally already be in use on
// some CI/dev machine (which would silently turn the network-failure case into a no-op). Runs in
// a child process via execFileSync so this stays a plain synchronous helper for the caller.
function getFreePort() {
  const out = execFileSync(process.execPath, ['-e',
    "const net=require('net');const s=net.createServer();" +
    "s.listen(0,'127.0.0.1',()=>{process.stdout.write(String(s.address().port));s.close(()=>process.exit(0));});"
  ], { encoding: 'utf8' });
  const port = parseInt(out.trim(), 10);
  if (!Number.isInteger(port) || port <= 0) throw new Error('getFreePort() failed, got: ' + out);
  return port;
}

// Proves the telemetry Worker was genuinely alive and exercised throughout a case, rather than
// having silently degraded (or never started) before the adversarial content was even pushed
// through it -- which would make the "host survives" assertions above pass vacuously.
function assertNoTelemetryDegraded(logDir, res) {
  const degraded = readAuditEvents(logDir).filter((e) => e.eventType === 'TELEMETRY_DEGRADED');
  assert.strictEqual(degraded.length, 0,
    'expected no TELEMETRY_DEGRADED audit event -- the worker must stay alive under adversarial pressure, not silently degrade: ' + JSON.stringify(degraded));
  assert.ok(!/Telemetry worker (failed to start|crashed)/.test(res.stderr || ''),
    'expected no telemetry-degraded warning on stderr, got:\n' + res.stderr);
}

// Sets up: a QUARANTINE-policy'd "attacker" package (the adversarial fixture drives its proxy),
// a BLOCK-policy'd "canary" package (proves enforcement keeps working throughout), a real
// FW_TELEMETRY=1 worker, and an unreachable control-plane port (nothing listens on it -- proves
// the real network-failure path, not a simulated one, stays fail-open).
function setupChildEnv(prefix) {
  const tmp = mkTmpDir(prefix);
  const logDir = mkTmpDir(prefix + 'log-');
  const attackerDir = path.join(tmp, 'node_modules', 'attacker-pkg');
  fs.mkdirSync(attackerDir, { recursive: true });
  fs.writeFileSync(path.join(attackerDir, 'package.json'), JSON.stringify({ name: 'attacker-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(attackerDir, 'index.js'), 'module.exports = "attacker-pkg-real-code";\n');

  const canaryDir = path.join(tmp, 'node_modules', 'canary-pkg');
  fs.mkdirSync(canaryDir, { recursive: true });
  fs.writeFileSync(path.join(canaryDir, 'package.json'), JSON.stringify({ name: 'canary-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(canaryDir, 'index.js'), 'module.exports = "canary-pkg-real-code";\n');

  const signed = signPolicy({ 'attacker-pkg': 'QUARANTINE', 'canary-pkg': 'BLOCK' }, TEST_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  return { tmp, logDir };
}

function runChild(tmp, logDir, childScriptPath, extraEnv) {
  return spawnSync(process.execPath, [`--require=${AGENT_PATH}`, childScriptPath], {
    cwd: tmp,
    encoding: 'utf8',
    env: Object.assign({}, process.env, {
      FW_ENABLE_DETECTION: '1',
      FW_TELEMETRY: '1',
      FW_POLICY_PUBKEY: TEST_PUBLIC_KEY,
      HELIOS_LOG_DIR: logDir,
      // Freshly-freed port, allocated per-call -- nothing listens here, so the real sync-worker.js
      // HTTP POST genuinely fails to connect, without risking collision with a hardcoded port that
      // some CI/dev machine happens to already have bound.
      FW_CONTROL_PORT: String(getFreePort()),
    }, extraEnv),
    timeout: 20000,
  });
}

const CANARY_CHECK_SNIPPET = `
  let canaryError = null;
  try { require(path.join(process.cwd(), 'node_modules', 'canary-pkg', 'index.js')); } catch (e) { canaryError = e.message; }
`;

function parseResult(stdout) {
  const m = /RESULT:(.*)/.exec(stdout || '');
  if (!m) throw new Error('child produced no RESULT: line. stdout=\n' + (stdout || '') );
  return JSON.parse(m[1]);
}

// ── Case 1: extremely long property names (Symbol description + string key) ──────────────────
(function longPropertyNames() {
  const { tmp, logDir } = setupChildEnv('fw-telemetry-adv-longprop-');

  const childScriptPath = path.join(tmp, 'child.js');
  fs.writeFileSync(childScriptPath, `
    const path = require('path');
    const attacker = require(path.join(process.cwd(), 'node_modules', 'attacker-pkg', 'index.js'));

    // A quarantined proxy's "property name" is fully attacker-controlled -- probe with a huge
    // string key and a Symbol whose description is huge (String(sym) embeds the whole thing).
    const hugeKey = 'x'.repeat(2_000_000);
    attacker[hugeKey];
    const hugeSymbol = Symbol('y'.repeat(2_000_000));
    attacker[hugeSymbol];

    ${CANARY_CHECK_SNIPPET}
    console.log('RESULT:' + JSON.stringify({ canaryError }));
  `);

  const res = runChild(tmp, logDir, childScriptPath);

  check('adversarial: extremely long property-name access does not crash the host', () => {
    assert.strictEqual(res.status, 0, 'child process must survive huge property-name telemetry content: stderr=\n' + res.stderr);
  });
  check('adversarial: enforcement (BLOCK policy) still runs after huge property-name telemetry content', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.canaryError && result.canaryError.includes('[Firewall]'), 'canary-pkg must still be blocked: ' + JSON.stringify(result));
  });
  check('adversarial: local audit logging continued despite huge property-name content', () => {
    const events = readAuditEvents(logDir);
    assert.ok(events.some((e) => e.eventType === 'QUARANTINE_ACTIVE'), 'expected the quarantine activation to be locally audited regardless of telemetry outcome');
  });
  check('adversarial: the telemetry worker was not degraded by huge property-name content', () => {
    assertNoTelemetryDegraded(logDir, res);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

// ── Case 2: exotic / prototype-pollution-shaped property names ────────────────────────────────
(function exoticPropertyNames() {
  const { tmp, logDir } = setupChildEnv('fw-telemetry-adv-exotic-');

  const childScriptPath = path.join(tmp, 'child.js');
  fs.writeFileSync(childScriptPath, `
    const path = require('path');
    const attacker = require(path.join(process.cwd(), 'node_modules', 'attacker-pkg', 'index.js'));

    for (const name of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty', 'then']) {
      try { attacker[name]; } catch (e) { /* the proxy must not throw for any of these */ }
    }
    attacker.__proto__ = { polluted: true };
    delete attacker.constructor;

    ${CANARY_CHECK_SNIPPET}
    console.log('RESULT:' + JSON.stringify({ canaryError }));
  `);

  const res = runChild(tmp, logDir, childScriptPath);

  check('adversarial: exotic/prototype-pollution-shaped property names do not crash the host', () => {
    assert.strictEqual(res.status, 0, 'child process must survive exotic property names: stderr=\n' + res.stderr);
  });
  check('adversarial: enforcement (BLOCK policy) still runs after exotic property-name access', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.canaryError && result.canaryError.includes('[Firewall]'), 'canary-pkg must still be blocked: ' + JSON.stringify(result));
  });
  check('adversarial: the telemetry worker was not degraded by exotic property names', () => {
    assertNoTelemetryDegraded(logDir, res);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

// ── Case 3: rapid-fire flood against the REAL worker mailbox (beyond the rate limiter) ─────────
(function floodRealWorker() {
  const { tmp, logDir } = setupChildEnv('fw-telemetry-adv-flood-');

  const childScriptPath = path.join(tmp, 'child.js');
  fs.writeFileSync(childScriptPath, `
    const path = require('path');
    const attacker = require(path.join(process.cwd(), 'node_modules', 'attacker-pkg', 'index.js'));

    for (let i = 0; i < 50000; i++) {
      attacker['prop_' + i];
    }

    ${CANARY_CHECK_SNIPPET}
    console.log('RESULT:' + JSON.stringify({ canaryError }));
  `);

  const res = runChild(tmp, logDir, childScriptPath);

  check('adversarial: a 50,000-access flood against the real telemetry worker does not crash the host', () => {
    assert.strictEqual(res.status, 0, 'child process must survive a real flood: stderr=\n' + res.stderr);
  });
  check('adversarial: enforcement (BLOCK policy) still runs after the flood', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.canaryError && result.canaryError.includes('[Firewall]'), 'canary-pkg must still be blocked: ' + JSON.stringify(result));
  });
  check('adversarial: the telemetry worker was not degraded by the flood', () => {
    assertNoTelemetryDegraded(logDir, res);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

// ── Case 4: real, unreachable control-plane target (genuine network failure, not simulated) ───
(function unreachableControlPlane() {
  const { tmp, logDir } = setupChildEnv('fw-telemetry-adv-network-');

  const childScriptPath = path.join(tmp, 'child.js');
  fs.writeFileSync(childScriptPath, `
    const path = require('path');
    const attacker = require(path.join(process.cwd(), 'node_modules', 'attacker-pkg', 'index.js'));
    attacker.doSomething();

    ${CANARY_CHECK_SNIPPET}
    // Give the real worker's flush timer (1s) a chance to actually attempt -- and fail -- the
    // real HTTP POST to the unreachable FW_CONTROL_PORT before the process exits.
    setTimeout(() => {
      console.log('RESULT:' + JSON.stringify({ canaryError }));
    }, 1500);
  `);

  const res = runChild(tmp, logDir, childScriptPath);

  check('adversarial: an unreachable real control-plane target does not crash the host', () => {
    assert.strictEqual(res.status, 0, 'child process must survive a genuine network failure: stderr=\n' + res.stderr);
  });
  check('adversarial: enforcement (BLOCK policy) still runs despite the unreachable control plane', () => {
    const result = parseResult(res.stdout);
    assert.ok(result.canaryError && result.canaryError.includes('[Firewall]'), 'canary-pkg must still be blocked: ' + JSON.stringify(result));
  });
  check('adversarial: local audit logging is independent of remote telemetry reachability', () => {
    const events = readAuditEvents(logDir);
    assert.ok(events.some((e) => e.eventType === 'QUARANTINE_ACTIVE'), 'expected local audit events regardless of whether the remote POST succeeded');
  });
  check('adversarial: an unreachable control plane is a fail-open network error, not a worker degradation', () => {
    assertNoTelemetryDegraded(logDir, res);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

console.log(`\n${passed} telemetry-adversarial-resilience checks passed.`);
console.log('Conclusion: no attacker-controlled telemetry content reproduced a Worker/host crash across property-name, flood, or network-failure vectors -- existing fail-open defenses (F-21.1/F-21.2, #104) hold under adversarial pressure, not just the two synthetic failure shims that motivated them. No Worker restart/backoff logic added (#108 acceptance criteria: only add it if a reproducible crash were found).');
process.exit(0);
