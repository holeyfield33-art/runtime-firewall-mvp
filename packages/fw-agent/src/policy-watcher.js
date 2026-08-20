// packages/fw-agent/src/policy-watcher.js
// Continuous policy integrity verification using Ed25519 asymmetric signatures.
//
// policy.signed.json format:
//   { "version": 1, "rules": {...}, "signedAt": "ISO-8601", "signature": "base64url" }
//
// The signature covers the canonical JSON of { version, rules (keys sorted), signedAt }.
// An invalid or missing signature immediately triggers emergency lockdown.
// A valid signature with changed rules triggers hot-reload via onValidChange().
//
// To sign a policy file, generate your own local dev key first (never commit it — see
// SECURITY.md "Policy signing key management"), then sign with it:
//   node scripts/generate-policy-key.js > /tmp/my-dev-key.txt   # keep the private key local-only
//   node scripts/sign-policy.js <your-private-key.pem> rules.json policy.signed.json
//
// To generate a production key pair:
//   node scripts/generate-policy-key.js

const fs = require('fs');
const crypto = require('crypto');

// ── F-62: pristine crypto method capture ──────────────────────────────────────
// require('crypto') returns the SAME cached module object to every caller in the process —
// including any allowed code that runs after this module loads. crypto.verify(...) was
// previously called fresh (via `crypto.verify`) on every signature check, so a monkeypatch on
// crypto.verify installed by allowed code AFTER this module has already loaded defeats every
// future signature verification, including the ones this file performs. Capturing the
// functions here, at module top level, before any later-loaded code has a chance to run,
// means a later `crypto.verify = () => true` mutates the crypto module's OWN property, not
// this local binding — so this file's checks keep using the real implementation regardless.
//
// crypto.verify is the actual trust decision (does this policy carry a genuine signature) and
// is always captured. crypto.createHash has two call sites in this file:
//   - _hashRules(): change-detection only ("not security-critical — just diffing", see below).
//     Every tick still independently re-verifies the signature via pristineVerify before
//     _hashRules ever runs, so a forged createHash here cannot smuggle unsigned/tampered rules
//     past the trust gate. It CAN, if forced to collide, suppress onValidChange from firing for
//     a validly re-signed policy (a staleness/downgrade-prevention concern, not a forgery one).
//     Captured anyway for defense-in-depth since it costs nothing and removes the ambiguity.
const pristineVerify = crypto.verify;
const pristineCreateHash = crypto.createHash;

const WATCH_INTERVAL_MS = 60_000;

// ── Dev/CI public key ─────────────────────────────────────────────────────────
// PRODUCTION: replace with your own key and regenerate .helios-baseline.
//
// F-62 dev-key rotation: this replaces a public key whose matching private key
// (scripts/dev-private-key.pem) was committed to this public repository — see SECURITY.md
// "Policy signing key management" for the revocation record. The matching private key for
// THIS public key has never been committed anywhere and never will be: there is no shared
// dev private key any more. Generate your own with `node scripts/generate-policy-key.js`,
// keep it local-only, and either set FW_POLICY_PUBKEY to your own public key (recommended —
// this is the real production path) or replace the constant below for your own fork.
const DEV_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFz7lD+f865pDlKeKLHtWDJk6Gs/C6SXHR8xA9tfE0As=
-----END PUBLIC KEY-----`;

// Allow the public key to be overridden via environment variable for production deployments.
// FW_POLICY_PUBKEY must be a PEM-encoded Ed25519 SPKI public key.
const PUBLIC_KEY_PEM = process.env.FW_POLICY_PUBKEY || DEV_PUBLIC_KEY_PEM;

// F-02a: true when we're verifying with the bundled dev key (fallback, or explicitly set).
// No matching private key is committed anywhere in this repo (F-62 rotation, see SECURITY.md)
// -- but this constant is still public by nature (it's a public key, meant to be shared), and
// a deployer's own locally-generated dev key is not distinguishable from it at this layer, so
// the same treat-it-as-unverified-for-production posture still applies: still gated below.
// Fail loud in start() unless explicitly opted in via FW_ALLOW_DEV_POLICY_KEY=1.
const USING_DEV_POLICY_KEY = PUBLIC_KEY_PEM.trim() === DEV_PUBLIC_KEY_PEM.trim();

/**
 * Build the canonical signed payload buffer from a policy object.
 * Keys in rules are sorted alphabetically so the byte sequence is deterministic.
 */
function canonicalPayload(version, rules, signedAt) {
  const sorted = {};
  for (const k of Object.keys(rules).sort()) sorted[k] = rules[k];
  return Buffer.from(JSON.stringify({ version, rules: sorted, signedAt }));
}

/**
 * F-33: production dev-key guard that does NOT depend on a policy file being present.
 *
 * The in-`start()` guard below only fires when a policy.signed.json exists (start() returns
 * early otherwise), so a production deploy running the bundled dev key with no policy file on
 * disk got zero signal — even though a policy file could be dropped in later and hot-loaded,
 * and even though shipping the public dev key at all in production is a misconfiguration worth
 * failing loud on. Call this from agent startup, before the watcher, so the check runs
 * regardless of policy-file presence.
 *
 * Refuses to start (process.exit(1)) when running in production against the bundled dev key
 * without an explicit acknowledgement. Local/dev/CI is unaffected: NODE_ENV is not 'production'
 * there, and operators can still opt in with FW_ALLOW_DEV_POLICY_KEY=1.
 *
 * @param {object} [env]  - injectable for tests; defaults to process.env
 * @param {function} [exit] - injectable for tests; defaults to process.exit
 * @returns {boolean} true if a refusal was triggered (tests), false otherwise
 */
function assertProductionKeyConfig(env = process.env, exit = process.exit) {
  if (env.NODE_ENV === 'production' && USING_DEV_POLICY_KEY && env.FW_ALLOW_DEV_POLICY_KEY !== '1') {
    console.error(
      '[CRITICAL] Running in production (NODE_ENV=production) with the bundled development ' +
      'policy key. The matching private key is public, so any attacker can forge a policy ' +
      'signature. Set FW_POLICY_PUBKEY to your production public key. Refusing to start.'
    );
    exit(1);
    return true;
  }
  return false;
}

class PolicyWatcher {
  /**
   * @param {string} policyPath   - Absolute path to policy.signed.json
   * @param {object} callbacks    - { onTamperDetected(), onValidChange(rules) }
   * @param {object} [options]    - { intervalMs }
   */
  constructor(policyPath, callbacks, options = {}) {
    this.policyPath = policyPath;
    this.onTamperDetected = (callbacks && callbacks.onTamperDetected) || (() => {});
    this.onValidChange = (callbacks && callbacks.onValidChange) || (() => {});
    this.locked = false;
    this.timer = null;
    this._intervalMs = (options && options.intervalMs) || WATCH_INTERVAL_MS;
    this._lastRulesHash = null;
  }

  /**
   * Attempt to read, parse, and cryptographically verify the policy file.
   * Returns { version, rules, signedAt } on success, or null on any failure.
   * Fail-closed: unsigned, malformed, or tampered policies return null.
   */
  _loadAndVerify() {
    let content;
    try {
      content = fs.readFileSync(this.policyPath, 'utf8');
    } catch (e) {
      console.error('[PolicyWatcher] Cannot read policy file:', e.message);
      return null;
    }

    let policy;
    try {
      policy = JSON.parse(content);
    } catch (e) {
      console.error('[PolicyWatcher] Policy file is not valid JSON:', e.message);
      return null;
    }

    const { version, rules, signedAt, signature } = policy;

    if (version !== 1 || !rules || typeof rules !== 'object' || !signedAt || !signature) {
      console.error('[PolicyWatcher] Policy file is missing required fields (version, rules, signedAt, signature).');
      return null;
    }

    const payload = canonicalPayload(version, rules, signedAt);
    let sigBuffer;
    try {
      sigBuffer = Buffer.from(signature, 'base64url');
    } catch (e) {
      console.error('[PolicyWatcher] Policy signature is not valid base64url.');
      return null;
    }

    let valid = false;
    try {
      valid = pristineVerify(null, payload, { key: PUBLIC_KEY_PEM, format: 'pem', type: 'spki' }, sigBuffer);
    } catch (e) {
      console.error('[PolicyWatcher] Signature verification error:', e.message);
      return null;
    }

    if (!valid) {
      console.error('[PolicyWatcher] Policy signature is INVALID.');
      return null;
    }

    return { version, rules, signedAt };
  }

  /**
   * Verify the policy file cryptographically.
   * Returns true if valid, false otherwise. Safe to call directly in tests.
   */
  verify() {
    return this._loadAndVerify() !== null;
  }

  /**
   * Hash the rules for change detection (not security-critical — just diffing).
   */
  _hashRules(rules) {
    return pristineCreateHash('sha256').update(JSON.stringify(rules)).digest('hex');
  }

  /**
   * Start the periodic integrity check.
   * Verifies the policy on startup; calls onTamperDetected() if verification fails.
   * Calls onValidChange(rules) with the initial rules on startup, then on every verified change.
   */
  start() {
    if (!fs.existsSync(this.policyPath)) return;

    // F-02a: refuse to verify a policy file against the bundled dev key in production.
    // The dev private key is public (committed to the repo), so any attacker can forge
    // a valid signature. Only allow the dev key when FW_ALLOW_DEV_POLICY_KEY=1.
    if (USING_DEV_POLICY_KEY && process.env.FW_ALLOW_DEV_POLICY_KEY !== '1') {
      console.error(
        '[CRITICAL] Policy file found but FW_POLICY_PUBKEY is missing or set to the bundled ' +
        'development key. The matching private key is public, making this unsafe. Set ' +
        'FW_POLICY_PUBKEY to your production public key, or set FW_ALLOW_DEV_POLICY_KEY=1 ' +
        'for local/dev/CI use. Refusing to run.'
      );
      process.exit(1);
    }

    const initial = this._loadAndVerify();
    if (!initial) {
      this.locked = true;
      console.error('\n[CRITICAL] Policy file failed signature verification on startup. EMERGENCY LOCKDOWN ACTIVE.');
      this.onTamperDetected();
      return;
    }

    this._lastRulesHash = this._hashRules(initial.rules);
    this.onValidChange(initial.rules);

    this.timer = setInterval(() => {
      if (this.locked) return;

      const result = this._loadAndVerify();
      if (!result) {
        this.locked = true;
        console.error('\n[CRITICAL] Policy integrity violation detected. EMERGENCY LOCKDOWN ACTIVE.');
        this.onTamperDetected();
        return;
      }

      const newHash = this._hashRules(result.rules);
      if (newHash !== this._lastRulesHash) {
        this._lastRulesHash = newHash;
        console.log('[PolicyWatcher] Valid policy update detected \u2014 hot-reloading rules.');
        this.onValidChange(result.rules);
      }
    }, this._intervalMs);

    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  get isLocked() {
    return this.locked;
  }
}

module.exports = { PolicyWatcher, canonicalPayload, assertProductionKeyConfig };

