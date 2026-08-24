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

  // Test 9: F-71 regression -- canonicalPayload's byte-building primitives (JSON.stringify,
  // Object.keys, Array.prototype.sort, Buffer.from) are captured pristine at module load, so a
  // monkeypatch of any of them installed AFTER the module loaded cannot decouple the bytes
  // pristineVerify checks from the rules object that gets applied. Distinct from Test 8 (F-62),
  // which patches crypto.verify/createHash. The attack: reuse a genuine signature issued for a
  // benign (here: empty-rules) policy, ship it alongside forged malicious rules, and patch a
  // byte-building primitive so the forged rules' canonical bytes collapse back to the empty-rules
  // bytes the signature actually covers. Each captured primitive is a distinct way to do that.
  {
    // A genuine signature over an EMPTY-rules policy -- the "previously-valid payload" whose
    // signature the attacker reuses.
    const signedEmpty = signPolicy({}, DEV_PRIVATE_KEY);
    const forged = {
      version: 1,
      rules: { 'evil.js': 'ALLOW' },
      signedAt: signedEmpty.signedAt,
      signature: signedEmpty.signature, // stale-but-genuine empty-rules signature
    };
    const forgedPath = freshPolicyPath();
    fs.writeFileSync(forgedPath, JSON.stringify(forged, null, 2), 'utf8');

    // Real primitives captured before any patch, so patches can delegate to them (keeping the
    // test harness working) and so we can restore them afterwards.
    const realStringify = JSON.stringify;
    const realKeys = Object.keys;
    const realSort = Array.prototype.sort;
    const realBufferFrom = Buffer.from;

    // The exact bytes the forged canonical payload must collapse to for the empty signature to
    // validate it.
    const emptyCanonicalStr = realStringify({ version: 1, rules: {}, signedAt: signedEmpty.signedAt });
    const emptyCanonicalBuf = realBufferFrom(emptyCanonicalStr);
    const evilCanonicalStr = realStringify({ version: 1, rules: { 'evil.js': 'ALLOW' }, signedAt: signedEmpty.signedAt });

    // Sanity: with NO patch, the forged policy is rejected (its true canonical bytes don't match
    // the empty-rules signature).
    assert.strictEqual(new PolicyWatcher(forgedPath, {}).verify(), false,
      'sanity: forged policy (evil rules + empty-rules signature) must be rejected with no monkeypatch');

    // 9a. JSON.stringify patched to emit the empty-rules bytes for the forged canonical shape.
    JSON.stringify = function (value, ...rest) {
      if (value && value.rules && realKeys(value.rules).includes('evil.js') && value.signedAt === signedEmpty.signedAt) {
        return emptyCanonicalStr;
      }
      return realStringify.call(this, value, ...rest);
    };
    try {
      // The patch really is live -- it WOULD fool a global-JSON.stringify canonicalizer:
      assert.strictEqual(
        JSON.stringify({ version: 1, rules: { 'evil.js': 'ALLOW' }, signedAt: signedEmpty.signedAt }),
        emptyCanonicalStr,
        'scaffolding: the JSON.stringify patch must collapse the forged canonical to empty-rules bytes');
      assert.strictEqual(new PolicyWatcher(forgedPath, {}).verify(), false,
        'F-71: forged policy must stay REJECTED with JSON.stringify monkeypatched to empty-rules bytes');
      // The legitimate path must still verify true under the patch (fix must not break it).
      const validPath = freshPolicyPath();
      writeSignedPolicy(validPath, { 'valid-71': 'OBSERVE' });
      assert.strictEqual(new PolicyWatcher(validPath, {}).verify(), true,
        'F-71: a genuinely valid signature must still verify true under the JSON.stringify patch');
    } finally {
      JSON.stringify = realStringify;
    }

    // 9b. Object.keys patched to drop the forged key (collapsing rules to {} in the canonical).
    Object.keys = function (o) {
      const ks = realKeys(o);
      return ks.includes('evil.js') ? [] : ks;
    };
    try {
      assert.strictEqual(new PolicyWatcher(forgedPath, {}).verify(), false,
        'F-71: forged policy must stay REJECTED with Object.keys monkeypatched to drop the forged key');
    } finally {
      Object.keys = realKeys;
    }

    // 9c. Array.prototype.sort patched to return [] for the forged key list.
    // eslint-disable-next-line no-extend-native
    Array.prototype.sort = function (...args) {
      if (Array.isArray(this) && this.includes('evil.js')) return [];
      return realSort.apply(this, args);
    };
    try {
      assert.strictEqual(new PolicyWatcher(forgedPath, {}).verify(), false,
        'F-71: forged policy must stay REJECTED with Array.prototype.sort monkeypatched to empty the key list');
    } finally {
      Array.prototype.sort = realSort;
    }

    // 9d. Buffer.from patched to return the empty-rules bytes for the forged canonical string.
    Buffer.from = function (v, ...rest) {
      if (typeof v === 'string' && v === evilCanonicalStr) return emptyCanonicalBuf;
      return realBufferFrom(v, ...rest);
    };
    try {
      assert.strictEqual(new PolicyWatcher(forgedPath, {}).verify(), false,
        'F-71: forged policy must stay REJECTED with Buffer.from monkeypatched to empty-rules bytes');
    } finally {
      Buffer.from = realBufferFrom;
    }

    console.log('  ok F-71: JSON.stringify/Object.keys/Array.prototype.sort/Buffer.from monkeypatched AFTER module load do not forge a policy past verification');
  }

  // Test 10: F-80 regression (PENTEST-003 finding) -- canonicalPayload's key-sort copy loop
  // (`sorted[k] = rules[k]` onto a fresh {}) is bracket assignment, a [[Set]] operation subject to
  // prototype-chain interception -- distinct from Tests 8/9, which patch whole functions/globals.
  // No monkeypatch of crypto.verify/createHash or any F-71 primitive is used here; the vector is
  // the copy loop's own target object. Two scenarios, both must be REJECTED after the F-80 fix
  // (Object.create(null) as the copy target):
  //   (a) the literal key '__proto__' -- Object.prototype's own built-in accessor silently no-ops
  //       a bracket-assignment of a non-object value, dropping the key from the signed bytes while
  //       JSON.parse's `rules` (CreateDataProperty, accessor-immune) keeps it as a real own
  //       property -- pure stock JS semantics, no pollution needed.
  //   (b) an ORDINARY key name (an npm-package-shaped string), forged via Object.prototype
  //       pollution simulating an already-running lower-privileged allowed dependency -- proves
  //       the bug generalizes past '__proto__' to any policy key.
  // Attack shape: sign a policy that does NOT include the target key, then TAMPER THE RAW JSON
  // TEXT (never touch the private key, never mutate a JS object pre-serialization -- text-level
  // editing is what actually reaches JSON.parse's safe CreateDataProperty path) to inject the
  // target key, and confirm verify() now correctly returns false.
  {
    // Scenario (a): literal '__proto__' key.
    {
      const policyPath = freshPolicyPath();
      writeSignedPolicy(policyPath, { 'left-pad': 'OBSERVE' });
      let text = fs.readFileSync(policyPath, 'utf8');
      text = text.replace('"left-pad": "OBSERVE"', '"left-pad": "OBSERVE",\n    "__proto__": "BLOCK"');
      fs.writeFileSync(policyPath, text);

      const parsedCheck = JSON.parse(text);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(parsedCheck.rules, '__proto__'), true,
        'sanity: JSON.parse must produce a real own "__proto__" property (CreateDataProperty) for this test to be meaningful'
      );

      const watcher = new PolicyWatcher(policyPath, {});
      assert.strictEqual(
        watcher.verify(), false,
        'F-80: a policy tampered post-signing to inject a "__proto__" rule (no private key, no JS object mutation, raw text edit only) must be REJECTED'
      );
    }

    // Scenario (b): an ordinary key name, forged via Object.prototype pollution (simulating an
    // already-running allowed dependency), proving the bug is not '__proto__'-specific.
    {
      const TARGET_KEY = 'totally-normal-pkg-name';
      let swallowed = null;
      Object.defineProperty(Object.prototype, TARGET_KEY, {
        configurable: true,
        set(v) { swallowed = v; },
        get() { return undefined; },
      });
      try {
        const policyPath = freshPolicyPath();
        writeSignedPolicy(policyPath, { 'some-other-pkg': 'OBSERVE' });
        let text = fs.readFileSync(policyPath, 'utf8');
        text = text.replace('"some-other-pkg": "OBSERVE"', `"some-other-pkg": "OBSERVE",\n    "${TARGET_KEY}": "BLOCK"`);
        fs.writeFileSync(policyPath, text);

        const watcher = new PolicyWatcher(policyPath, {});
        assert.strictEqual(
          watcher.verify(), false,
          'F-80: a policy tampered post-signing to inject an ordinary package-name rule, while Object.prototype is polluted for that exact key, must be REJECTED'
        );
      } finally {
        delete Object.prototype[TARGET_KEY];
      }
    }

    // The legitimate path must still work: signing/verifying a policy whose rules genuinely
    // include a tricky key must succeed end-to-end (the fix must not break real usage).
    {
      const policyPath = freshPolicyPath();
      writeSignedPolicy(policyPath, { 'left-pad': 'OBSERVE', 'a-real-pkg': 'BLOCK' });
      const watcher = new PolicyWatcher(policyPath, {});
      assert.strictEqual(watcher.verify(), true, 'F-80: an honestly-signed, untampered policy must still verify true');
    }

    console.log('  ok F-80: canonicalPayload\'s copy-loop target is prototype-pollution-immune (Object.create(null)) -- forged "__proto__" and arbitrary-key rules are rejected');
  }

  // Test 11: F-83 regression (PENTEST-004 finding) -- canonicalPayload's key-sort copy loop reads
  // the sorted key array with `for...of`, which dispatches through
  // Array.prototype[Symbol.iterator] -- a property F-71's pristine captures (Object.keys,
  // Array.prototype.sort, JSON.stringify, Buffer.from) never touched, and F-80's Object.create(null)
  // copy target doesn't gate either (the bug is in what the loop SEES, not what it writes to).
  // Allowed code with earlier execution in the process can replace Array.prototype[Symbol.iterator]
  // with a generator that yields every legitimate key while silently skipping one forged key of its
  // choice -- Object.keys/sort still return the real, complete list; only the for...of consuming it
  // is redirected. Attack shape: sign a policy WITHOUT the target key (genuine signature over the
  // honest bytes), tamper the raw JSON TEXT post-signing to inject the forged key (JSON.parse's
  // CreateDataProperty makes it a real own property of the returned `rules`, same as Test 10), then
  // install a TARGETED Symbol.iterator that drops exactly that key from canonicalPayload's view --
  // collapsing the forged canonical bytes back to the originally-signed ones.
  {
    const TARGET_KEY = 'evil-pkg';
    const policyPath = freshPolicyPath();
    writeSignedPolicy(policyPath, { 'left-pad': 'OBSERVE' });
    let text = fs.readFileSync(policyPath, 'utf8');
    text = text.replace('"left-pad": "OBSERVE"', `"left-pad": "OBSERVE",\n    "${TARGET_KEY}": "BLOCK"`);
    fs.writeFileSync(policyPath, text);

    const parsedCheck = JSON.parse(text);
    assert.strictEqual(
      Object.prototype.hasOwnProperty.call(parsedCheck.rules, TARGET_KEY), true,
      'sanity: JSON.parse must produce a real own forged-key property for this test to be meaningful'
    );

    // Sanity: with NO Symbol.iterator pollution, F-80's fix already rejects this (the forged key's
    // real bytes don't match the stale signature) -- confirms the harness is exercising the right
    // policy before we add the F-83-specific pollution on top.
    assert.strictEqual(new PolicyWatcher(policyPath, {}).verify(), false,
      'sanity: forged policy (extra key, no pollution) must be rejected before testing the Symbol.iterator vector');

    const realArrayIterator = Array.prototype[Symbol.iterator];
    // eslint-disable-next-line no-extend-native
    Array.prototype[Symbol.iterator] = function () {
      const arr = this;
      if (Array.isArray(arr) && arr.includes(TARGET_KEY) && arr.includes('left-pad')) {
        let i = 0;
        return {
          next() {
            while (i < arr.length) {
              const v = arr[i++];
              if (v === TARGET_KEY) continue;
              return { value: v, done: false };
            }
            return { value: undefined, done: true };
          },
          [Symbol.iterator]() { return this; },
        };
      }
      return realArrayIterator.call(arr);
    };
    try {
      // The patch really is live -- it WOULD fool a for...of/spread consumer of this exact key set:
      assert.deepStrictEqual(
        Array.from(['left-pad', TARGET_KEY]), ['left-pad'],
        'scaffolding: the Symbol.iterator patch must filter the forged key out of iteration'
      );

      assert.strictEqual(
        new PolicyWatcher(policyPath, {}).verify(), false,
        'F-83: forged policy must stay REJECTED with Array.prototype[Symbol.iterator] monkeypatched to hide the forged key from the copy loop'
      );

      // Legitimate path, under the SAME active pollution: an honestly-signed policy whose rules
      // genuinely include both 'left-pad' and the target-shaped key must still verify true -- the
      // fix must not depend on the iterator at all, so the pollution has no effect either way.
      const honestPath = freshPolicyPath();
      writeSignedPolicy(honestPath, { 'left-pad': 'OBSERVE', [TARGET_KEY]: 'BLOCK' });
      assert.strictEqual(new PolicyWatcher(honestPath, {}).verify(), true,
        'F-83: an honestly-signed policy containing the same key names must still verify true under the Symbol.iterator patch');
    } finally {
      Array.prototype[Symbol.iterator] = realArrayIterator;
    }

    console.log('  ok F-83: canonicalPayload\'s copy loop reads the sorted key array by index, not for...of -- Symbol.iterator monkeypatched AFTER module load does not forge a policy past verification');
  }

  try { fs.rmSync(tmpBase, { recursive: true }); } catch (e) {}

  console.log('All policy-watcher unit tests passed.');
})().catch(err => {
  console.error('Policy-watcher test FAILED:', err);
  process.exit(1);
});
