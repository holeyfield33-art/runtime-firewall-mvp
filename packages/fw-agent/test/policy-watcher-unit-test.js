// packages/fw-agent/test/policy-watcher-unit-test.js
// Unit tests for PolicyWatcher: Ed25519 signature verification, hot-reload, tamper detection.
//
// F-62: there is no shared, committed dev private key any more (see SECURITY.md "Policy
// signing key management" for the revocation record of the old one). These general functional
// tests don't care WHICH key is used, only that verification is internally consistent, so they
// generate a fresh Ed25519 keypair in-memory for this process only (never written to disk,
// never committed anywhere) and point the watcher at it via FW_POLICY_PUBKEY -- the same
// explicit-trusted-key path a real production deployment uses. FW_POLICY_PUBKEY must be set
// BEFORE policy-watcher.js is first required, since it reads the env var once at module load.
'use strict';
const crypto = require('crypto');
const { publicKey: TEST_PUBLIC_KEY, privateKey: TEST_PRIVATE_KEY } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
process.env.FW_POLICY_PUBKEY = TEST_PUBLIC_KEY;

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { PolicyWatcher } = require('../src/policy-watcher');
const { signPolicy } = require('../../../scripts/sign-policy');

const DEV_PRIVATE_KEY = TEST_PRIVATE_KEY;

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

  // Test 8: F-62 regression -- crypto.verify/createHash captured at module load resist a
  // monkeypatch installed AFTER the module has already loaded. This is the real F-62 threat:
  // require('crypto') returns the same cached module object to every caller, so allowed code
  // that runs after policy-watcher.js has already required('crypto') can patch .verify /
  // .createHash on that shared object. If policy-watcher.js were still calling crypto.verify(...)
  // fresh on every check (rather than a pristine reference captured at its own module top level),
  // this monkeypatch would make every forged signature pass.
  {
    const crypto = require('crypto');
    const realVerify = crypto.verify;
    const realCreateHash = crypto.createHash;

    try {
      // Forge crypto.verify to always report "valid".
      crypto.verify = () => true;
      // Forge crypto.createHash to always report the same digest, which would defeat
      // _hashRules()'s change-detection if it were using the live (monkeypatched) crypto object.
      crypto.createHash = () => ({
        update() { return this; },
        digest() { return 'forged-constant-hash'; },
      });

      // 8a. A TAMPERED policy (signed, then mutated without re-signing) must still be REJECTED --
      // proves _loadAndVerify() uses the pristine crypto.verify captured at module load, not the
      // monkeypatched one that would otherwise rubber-stamp it.
      const tamperedPath = freshPolicyPath();
      writeSignedPolicy(tamperedPath, { 'forged-test-pkg': 'OBSERVE' });
      const rawTampered = JSON.parse(fs.readFileSync(tamperedPath, 'utf8'));
      rawTampered.rules['forged-test-pkg'] = 'BLOCK'; // mutate without re-signing
      fs.writeFileSync(tamperedPath, JSON.stringify(rawTampered));
      const tamperedWatcher = new PolicyWatcher(tamperedPath, {});
      assert.strictEqual(
        tamperedWatcher.verify(), false,
        'forged signature must still be rejected even with crypto.verify monkeypatched to always return true'
      );

      // 8b. A genuinely, correctly-signed policy must still verify true (the fix must not break
      // the legitimate path).
      const validPath = freshPolicyPath();
      writeSignedPolicy(validPath, { 'valid-test-pkg': 'OBSERVE' });
      const validWatcher = new PolicyWatcher(validPath, {});
      assert.strictEqual(
        validWatcher.verify(), true,
        'a genuinely valid signature must still verify true under a crypto.verify monkeypatch'
      );

      // 8c. Hot-reload change-detection must still work -- proves _hashRules() uses the pristine
      // crypto.createHash, not the monkeypatched one that would otherwise make every rule set
      // hash identically and silently suppress hot-reload.
      const reloadPath = freshPolicyPath();
      writeSignedPolicy(reloadPath, { 'reload-pkg': 'OBSERVE' });
      let reloadCount = 0;
      let lastRules = null;
      const reloadWatcher = new PolicyWatcher(reloadPath, {
        onTamperDetected: () => { throw new Error('Unexpected lockdown in test 8c'); },
        onValidChange: (r) => { reloadCount++; lastRules = r; },
      }, { intervalMs: 50 });
      reloadWatcher.start();
      assert.strictEqual(reloadCount, 1, 'initial onValidChange must fire once');

      await sleep(100);
      writeSignedPolicy(reloadPath, { 'reload-pkg': 'OBSERVE', 'reload-pkg-2': 'BLOCK' });
      await sleep(200);
      reloadWatcher.stop();

      assert.strictEqual(
        reloadCount, 2,
        'onValidChange must still fire for a real rule change even with crypto.createHash monkeypatched to a constant digest'
      );
      assert.strictEqual(lastRules['reload-pkg-2'], 'BLOCK');

      console.log('  ok F-62: crypto.verify/createHash monkeypatched AFTER module load do not affect policy-watcher decisions');
    } finally {
      crypto.verify = realVerify;
      crypto.createHash = realCreateHash;
    }
  }

  try { fs.rmSync(tmpBase, { recursive: true }); } catch (e) {}

  console.log('All policy-watcher unit tests passed.');
})().catch(err => {
  console.error('Policy-watcher test FAILED:', err);
  process.exit(1);
});
