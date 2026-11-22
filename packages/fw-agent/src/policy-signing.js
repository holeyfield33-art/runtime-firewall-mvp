// packages/fw-agent/src/policy-signing.js
// The ONE authoritative policy-signing implementation (SRS-FW-004 P0).
//
// Used by:
//   - the package-owned CLIs  bin/aletheia-policy-keygen.js  and  bin/aletheia-policy-sign.js
//     (shipped in the npm package, so installed consumers never need the source repo), and
//   - the repository's scripts/sign-policy.js and scripts/generate-policy-key.js, which are now
//     thin wrappers around this module (repo dev/test workflows keep their old entry points).
//
// The signed bytes come from policy-watcher.js's own exported canonicalPayload() -- the exact
// function the running agent verifies with -- so the signer and the verifier cannot drift apart
// (previously scripts/sign-policy.js kept a hand-maintained byte-identical copy; see the F-80 /
// F-83 / F-84 notes in policy-watcher.js for why drift there was a real correctness risk).
//
// Zero dependencies: node:crypto, node:fs, node:path only. This module is NOT loaded by the agent
// at runtime (index.js never requires it), so it is outside the .helios-baseline self-hash set.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { canonicalPayload, isValidSignedAt } = require('./policy-watcher');

// Same capture discipline as policy-watcher.js: the signer's own key-sort copy reads pristine
// primitives captured at module load (F-80/F-83/F-84). The sorted copy becomes BOTH the input to
// canonicalPayload() and the `rules` field of the output file, so the two stay consistent.
const pristineCreate = Object.create;
const pristineKeys = Object.keys;
const pristineSort = Array.prototype.sort;
const pristineCall = Function.prototype.call;
const pristineApply = Reflect.apply;
const pristineSign = crypto.sign;
const pristineVerify = crypto.verify;

const POLICY_VERSION = 1;

function sortedRulesCopy(rules) {
  const sorted = pristineCreate(null);
  const keys = pristineApply(pristineCall, pristineSort, [pristineKeys(rules)]);
  for (let i = 0; i < keys.length; i++) sorted[keys[i]] = rules[keys[i]];
  return sorted;
}

/**
 * Sign a rules object with an Ed25519 private key (PKCS#8 PEM).
 * Returns the policy envelope { version, rules, signedAt, signature } ready to write as
 * policy.signed.json. Behavior and output are identical to the pre-0.6.3 scripts/sign-policy.js.
 */
function signPolicy(rules, privateKeyPem, signedAt) {
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)) {
    throw new TypeError('rules must be a JSON object mapping module/package keys to BLOCK | QUARANTINE | OBSERVE');
  }
  // Omitted argument → CLI default (UTC ISO with ms). Explicit invalid value is rejected.
  const ts = signedAt === undefined || signedAt === null ? new Date().toISOString() : signedAt;
  if (!isValidSignedAt(ts)) {
    throw new Error(`signedAt must be a UTC ISO-8601 timestamp with milliseconds (e.g. 2026-11-21T00:00:00.000Z); received: ${JSON.stringify(signedAt)}`);
  }
  const sorted = sortedRulesCopy(rules);
  const payload = canonicalPayload(POLICY_VERSION, sorted, ts);
  const sigBuffer = pristineSign(null, payload, { key: privateKeyPem, format: 'pem', type: 'pkcs8' });
  return { version: POLICY_VERSION, rules: sorted, signedAt: ts, signature: sigBuffer.toString('base64url') };
}

/** Verify an envelope against an SPKI PEM public key using the agent's canonical payload. */
function verifyPolicyEnvelope(envelope, publicKeyPem) {
  if (!envelope || envelope.version !== POLICY_VERSION || !envelope.rules || !isValidSignedAt(envelope.signedAt) || !envelope.signature) return false;
  try {
    return pristineVerify(null, canonicalPayload(envelope.version, envelope.rules, envelope.signedAt),
      { key: publicKeyPem, format: 'pem', type: 'spki' }, Buffer.from(envelope.signature, 'base64url'));
  } catch (e) {
    return false;
  }
}

/** Generate a fresh Ed25519 key pair as PEM strings (PKCS#8 private, SPKI public). */
function generatePolicyKeyPair() {
  return crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/** Derive the SPKI PEM public key from a PKCS#8 PEM private key. */
function publicKeyFromPrivate(privateKeyPem) {
  return crypto.createPublicKey(crypto.createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' });
}

/** SHA-256 fingerprint of a public key's SPKI DER encoding (for matching against FW_POLICY_PUBKEY). */
function publicKeyFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return 'SHA256:' + crypto.createHash('sha256').update(der).digest('base64');
}

/**
 * Write a new key pair to disk. Never overwrites an existing private OR public key file unless
 * `force` is true. The private key file is created with mode 0600 using an exclusive-create flag
 * so a concurrent writer cannot be silently clobbered either.
 */
function writeKeyPairFiles(privateKeyPath, publicKeyPath, { force = false } = {}) {
  if (!force) {
    for (const p of [privateKeyPath, publicKeyPath]) {
      if (fs.existsSync(p)) {
        const err = new Error(`Refusing to overwrite existing key file: ${p} (pass --force to replace it)`);
        err.code = 'EEXIST_KEYFILE';
        throw err;
      }
    }
  }
  const { publicKey, privateKey } = generatePolicyKeyPair();
  fs.mkdirSync(path.dirname(path.resolve(privateKeyPath)), { recursive: true });
  fs.mkdirSync(path.dirname(path.resolve(publicKeyPath)), { recursive: true });
  if (force && fs.existsSync(privateKeyPath)) fs.unlinkSync(privateKeyPath);
  fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600, flag: 'wx' });
  try { fs.chmodSync(privateKeyPath, 0o600); } catch (e) { /* best-effort on non-POSIX */ }
  fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644, flag: force ? 'w' : 'wx' });
  return { publicKey, privateKeyPath, publicKeyPath };
}

module.exports = {
  POLICY_VERSION,
  canonicalPayload,
  signPolicy,
  verifyPolicyEnvelope,
  generatePolicyKeyPair,
  publicKeyFromPrivate,
  publicKeyFingerprint,
  writeKeyPairFiles,
};
