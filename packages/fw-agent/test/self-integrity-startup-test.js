'use strict';

// Regression for startup ordering: a modified security-critical local module must be rejected
// before its top-level code executes. The fixture is a temporary copy so the repository checkout
// and its committed baseline remain untouched.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const AGENT_DIR = path.join(__dirname, '..');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-self-integrity-startup-'));
const cleanAgentDir = path.join(tmpDir, 'clean', 'fw-agent');
const tamperedAgentDir = path.join(tmpDir, 'tampered', 'fw-agent');
const cleanLogDir = path.join(tmpDir, 'clean-log');
const tamperedLogDir = path.join(tmpDir, 'tampered-log');

function runAgent(agentDir, logDir) {
  return spawnSync(process.execPath, [
    `--require=${path.join(agentDir, 'index.js')}`,
    '-e',
    'console.log("startup-ok")',
  ], {
    cwd: tmpDir,
    encoding: 'utf8',
    env: {
      ...process.env,
      FW_ENABLE_DETECTION: '1',
      FW_MODE: 'enforce',
      FW_ALLOW_DEV_POLICY_KEY: '1',
      HELIOS_LOG_DIR: logDir,
    },
    timeout: 15000,
  });
}

try {
  fs.cpSync(AGENT_DIR, cleanAgentDir, { recursive: true });
  const clean = runAgent(cleanAgentDir, cleanLogDir);
  assert.strictEqual(clean.status, 0, `clean agent must start successfully:\n${clean.stderr}`);
  assert.match(clean.stdout, /startup-ok/);

  fs.cpSync(AGENT_DIR, tamperedAgentDir, { recursive: true });
  const sentinel = path.join(tmpDir, 'tampered-module-executed');
  const detectorPath = path.join(tamperedAgentDir, 'src', 'detector.js');
  const detector = fs.readFileSync(detectorPath, 'utf8');
  fs.writeFileSync(
    detectorPath,
    `require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'executed');\n${detector}`,
    'utf8'
  );

  const tampered = runAgent(tamperedAgentDir, tamperedLogDir);
  assert.notStrictEqual(tampered.status, 0, 'tampered agent must fail closed before startup');
  assert.match(tampered.stderr, /self-integrity check FAILED/);
  assert.strictEqual(
    fs.existsSync(sentinel),
    false,
    'tampered security module must not execute top-level side effects before integrity rejection'
  );

  console.log('Self-integrity startup ordering test passed.');
} finally {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
