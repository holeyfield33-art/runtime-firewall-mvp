// packages/fw-agent/test/policy-watcher-unit-test.js
// Unit tests for PolicyWatcher: Ed25519 signature verification, hot-reload, tamper detection.
// Tests legitimately sign with the bundled dev key — opt in explicitly so the F-02a guard
// (which rejects dev-key policy in production) does not block the test run.
'use strict';
process.env.FW_ALLOW_DEV_POLICY_KEY = '1';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { PolicyWatcher } = require('../src/policy-watcher');
const { signPolicy } = require('../../../scripts/sign-policy');

// Dev private key (CI/test only - see scripts/dev-private-key.pem)
const DEV_PRIVATE_KEY = fs.readFileSync(
  path.join(__dirname, '../../../scripts/dev-private-key.pem'), 'utf8'
);

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
  const tmpBase = path.join(os.tmpdir(), `fw-watcher-test-${Date.now()}`);
  fs.mkdirSync(tmpBase, { recursive: true });

  let testIdx = 0;
  function freshPolicyPath() {
    const dir = path.join(tmpBase, String(++testIdx));
    fs.mkdirSync(dir, { recursive: true });
    return path.join(dir, 'policy.signed.json');
  }

  function writeSignedPolicy(policyPath, rules) {
    const signed = signPolicy(rules, DEV_PRIVATE_KEY);
    fs.writeFileSync(policyPath, JSON.stringify(signed, null, 2) + '\n', 'utf8');
    return signed;
  }

  // Test 1: verify() true for correctly signed file
  {
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, { lodash: 'OBSERVE' });
    const watcher = new PolicyWatcher(policyPath, {});
    assert.strictEqual(watcher.verify(), true, 'verify() must be true for a signed file');
    console.log('  ok verify() returns true for a correctly signed file');
  }

  // Test 2: verify() false when file is tampered without re-signing
  {
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, { lodash: 'OBSERVE' });
    const raw = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
    raw.rules.lodash = 'BLOCK';
    fs.writeFileSync(policyPath, JSON.stringify(raw, null, 2));
    const watcher = new PolicyWatcher(policyPath, {});
    assert.strictEqual(watcher.verify(), false, 'verify() must be false for tampered file');
    console.log('  ok verify() returns false when file is tampered without re-signing');
  }

  // Test 3: verify() false for file with no signature field
  {
    const policyPath = freshPolicyPath();
    fs.writeFileSync(policyPath, JSON.stringify({ version: 1, rules: {}, signedAt: '2026-07-02T00:00:00.000Z' }));
    const watcher = new PolicyWatcher(policyPath, {});
    assert.strictEqual(watcher.verify(), false, 'verify() must be false for unsigned file');
    console.log('  ok verify() returns false for unsigned (old-format) policy file');
  }

  // Test 4: verify() false when policy file is deleted
  {
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, {});
    fs.unlinkSync(policyPath);
    const watcher = new PolicyWatcher(policyPath, {});
    assert.strictEqual(watcher.verify(), false, 'verify() must be false when file missing');
    console.log('  ok verify() returns false when policy file is deleted');
  }

  // Test 5: lockdown fires when file is tampered (short interval)
  {
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, { express: 'OBSERVE' });

    let lockdownFired = false;
    let rulesReceived = null;
    const watcher = new PolicyWatcher(policyPath, {
      onTamperDetected: () => { lockdownFired = true; },
      onValidChange: (r) => { rulesReceived = r; },
    }, { intervalMs: 50 });
    watcher.start();

    assert.deepStrictEqual(rulesReceived, { express: 'OBSERVE' }, 'Initial rules must be delivered');

    const raw = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
    raw.rules.express = 'BLOCK';
    fs.writeFileSync(policyPath, JSON.stringify(raw));

    await sleep(200);
    watcher.stop();

    assert.strictEqual(lockdownFired, true, 'Lockdown must fire on tamper');
    assert.strictEqual(watcher.isLocked, true, 'Watcher must be locked');
    console.log('  ok Lockdown fires when file is tampered without re-signing');
  }

  // Test 6: hot-reload fires when policy is validly re-signed
  {
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, { express: 'OBSERVE' });

    let hotReloadCount = 0;
    let lastRules = null;
    const watcher = new PolicyWatcher(policyPath, {
      onTamperDetected: () => { throw new Error('Unexpected lockdown in test 6'); },
      onValidChange: (r) => { hotReloadCount++; lastRules = r; },
    }, { intervalMs: 50 });
    watcher.start();

    assert.strictEqual(hotReloadCount, 1, 'Initial onValidChange must fire once');

    await sleep(100);
    writeSignedPolicy(policyPath, { express: 'OBSERVE', axios: 'BLOCK' });

    await sleep(200);
    watcher.stop();

    assert.strictEqual(hotReloadCount, 2, 'onValidChange must fire again on valid update');
    assert.strictEqual(lastRules.axios, 'BLOCK', 'Hot-reloaded rules must include new entry');
    console.log('  ok Hot-reload fires when policy is validly re-signed with new rules');
  }

  // Test 7: no spurious lockdown or hot-reload for unchanged signed file
  {
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, { axios: 'OBSERVE' });

    let lockdownFired = false;
    let hotReloadCount = 0;
    const watcher = new PolicyWatcher(policyPath, {
      onTamperDetected: () => { lockdownFired = true; },
      onValidChange: () => { hotReloadCount++; },
    }, { intervalMs: 50 });
    watcher.start();

    await sleep(200);
    watcher.stop();

    assert.strictEqual(lockdownFired, false, 'No lockdown for untampered file');
    assert.strictEqual(hotReloadCount, 1, 'onValidChange fires only once (initial load)');
    console.log('  ok No spurious lockdown or hot-reload for unchanged signed file');
  }

  try { fs.rmSync(tmpBase, { recursive: true }); } catch (e) {}

  console.log('All policy-watcher unit tests passed.');
})().catch(err => {
  console.error('Policy-watcher test FAILED:', err);
  process.exit(1);
});
