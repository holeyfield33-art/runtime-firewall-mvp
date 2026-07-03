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
// To sign a policy file:
//   node scripts/sign-policy.js scripts/dev-private-key.pem rules.json policy.signed.json
//
// To generate a production key pair:
//   node scripts/generate-policy-key.js

const fs = require('fs');
const crypto = require('crypto');

const WATCH_INTERVAL_MS = 60_000;

// ── Dev/CI public key ─────────────────────────────────────────────────────────
// Generated with: node scripts/generate-policy-key.js
// PRODUCTION: replace with your own key and regenerate .helios-baseline.
// The private key is in scripts/dev-private-key.pem — DO NOT deploy that file.
const DEV_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEANejKx1KxfXVk5B0UzI2Cp3XO9hmy6nIXTAhsW0bhlFo=
-----END PUBLIC KEY-----`;

// Allow the public key to be overridden via environment variable for production deployments.
// FW_POLICY_PUBKEY must be a PEM-encoded Ed25519 SPKI public key.
const PUBLIC_KEY_PEM = process.env.FW_POLICY_PUBKEY || DEV_PUBLIC_KEY_PEM;

// F-02a: true when no production key was supplied and we fell back to the bundled dev key.
// The matching private key (scripts/dev-private-key.pem) is committed to the public repo,
// so any policy file signed with it is trivially forgeable. Fail loud in start() if a
// policy file is present and we are still using the dev key without an explicit opt-in.
const USING_DEV_POLICY_KEY = !process.env.FW_POLICY_PUBKEY;

/**
 * Build the canonical signed payload buffer from a policy object.
 * Keys in rules are sorted alphabetically so the byte sequence is deterministic.
 */
function canonicalPayload(version, rules, signedAt) {
  const sorted = {};
  for (const k of Object.keys(rules).sort()) sorted[k] = rules[k];
  return Buffer.from(JSON.stringify({ version, rules: sorted, signedAt }));
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
      valid = crypto.verify(null, payload, { key: PUBLIC_KEY_PEM, format: 'pem', type: 'spki' }, sigBuffer);
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
    return crypto.createHash('sha256').update(JSON.stringify(rules)).digest('hex');
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
        '[CRITICAL] Policy file found but FW_POLICY_PUBKEY is not set, so the bundled ' +
        'development key would verify it. The matching private key is public, making this ' +
        'unsafe. Set FW_POLICY_PUBKEY to your production public key, or set ' +
        'FW_ALLOW_DEV_POLICY_KEY=1 for local/dev/CI use. Refusing to run.'
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

module.exports = { PolicyWatcher, canonicalPayload };

