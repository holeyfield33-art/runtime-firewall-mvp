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

// ── F-71: pristine byte-building primitive capture ─────────────────────────────
// canonicalPayload() below builds the EXACT byte sequence that pristineVerify() checks a
// signature against. Every ambient global it uses to build those bytes is therefore a
// trust-gating primitive: allowed code that runs after this module loads can monkeypatch any
// of them so the bytes handed to pristineVerify no longer correspond to the `rules` object
// that _loadAndVerify() actually returns and the agent applies. That decoupling lets a
// stale-but-genuine signature (e.g. one that was validly issued for an empty-rules policy)
// validate a forged rules object. Captured here, at module top level, before any later-loaded
// code has a chance to run — a later `JSON.stringify = ...` then mutates the global, not this
// binding, so canonicalPayload keeps building honest bytes regardless. Each capture, and why
// it gates the decision:
//   - JSON.stringify (the reported F-71 vector): patched to emit fixed bytes (the empty-rules
//     payload) makes a stale empty-rules signature validate the forged rules verbatim.
//   - Object.keys AND Array.prototype.sort: together they produce the key set that gets
//     serialized (`Object.keys(rules).sort()`). Either one patched to drop keys or return an
//     empty/short array makes the canonical bytes omit the forged keys while the returned
//     object keeps them — the same stale-signature bypass. (A patched sort can `return []`
//     ignoring its receiver, so it is as much a drop vector as Object.keys.)
//   - Buffer.from: canonicalPayload wraps the JSON string in a Buffer; patched to return fixed
//     bytes it is byte-for-byte equivalent to patching JSON.stringify.
//   - Object.create (added under F-84, see that note below): canonicalPayload's copy-target
//     construction is itself a primitive call this list originally missed.
// NOT captured, having been checked and found NOT to gate the decision:
//   - JSON.parse — the object it produces in _loadAndVerify is the SAME object canonicalPayload
//     serializes AND the same object _loadAndVerify returns for enforcement, so the signature
//     is always verified against exactly the bytes of the object that will be applied. A
//     patched parse changes which object is under scrutiny but cannot decouple bytes-verified
//     from object-returned; the worst it can do is cause a fail-closed rejection, never a
//     forgery. (crypto.verify/createHash are already pristine-captured above under F-62.)
// The signing side (scripts/sign-policy.js) runs offline in a trusted process and keeps its own
// byte-identical canonicalPayload; these captures are the running-firewall verification side.
const pristineStringify = JSON.stringify;
const pristineKeys = Object.keys;
const pristineSort = Array.prototype.sort;
const pristineBufferFrom = Buffer.from;
const pristineCreate = Object.create;

// ── F-80: null-prototype copy target (PENTEST-003 finding, F-71 follow-on) ─────────────────────
// F-71 captured the byte-building PRIMITIVES pristine, but canonicalPayload's own key-sort copy
// loop below still built `sorted` as a plain `{}` and populated it via bracket assignment
// (`sorted[k] = rules[k]`). Plain-object bracket assignment is NOT a primitive call -- it is a
// [[Set]] operation that walks the object's prototype chain, so it is interceptable independent
// of every F-71 capture: (1) the literal key '__proto__' has a built-in Object.prototype accessor
// that silently no-ops for a non-object value -- `sorted['__proto__'] = 'BLOCK'` sets nothing, no
// monkeypatch or pollution required, pure stock JS semantics; (2) allowed code with EARLIER
// execution in the process (e.g. an OBSERVE-tier dependency) can define an accessor on
// Object.prototype for ANY ordinary key name (a ordinary npm package name), which the same
// bracket-assignment then silently swallows too. `rules` itself (from JSON.parse, which uses
// CreateDataProperty and is immune to both) keeps the injected key as a real own property, so an
// attacker with filesystem write access to policy.signed.json can add a forged rule for that key
// via a raw TEXT edit post-signing -- no private key, no F-71 primitive touched -- and
// canonicalPayload's signed bytes silently omit it while _loadAndVerify() still returns and
// applies a `rules` object that has it. Live-reproduced both cases (PENTEST-003) with a real
// generated Ed25519 keypair, the project's own sign-policy.js, and the unmodified pre-fix
// _loadAndVerify(): a policy signed WITHOUT a '__proto__'/target rule still verified VALID after
// the key was injected, and the forged rule was present in the applied rules object.
//
// Fix: build the copy target with Object.create(null) instead of `{}`. A null-prototype object
// has no inherited accessor anywhere in its chain (there is no chain), so bracket assignment on
// it is always a plain own-data-property write, immune to both the '__proto__' special case and
// arbitrary-key Object.prototype pollution -- for every key, not just ones enumerated in advance.
// JSON.stringify serializes a null-prototype object's own enumerable properties identically to a
// plain object (verified: it never consults the prototype chain), so this changes nothing about
// the produced bytes for any rules object that does NOT hit this bug -- i.e. every ordinary
// policy signs and verifies exactly as before. scripts/sign-policy.js's own separate
// canonicalPayload copy has the identical bug and is fixed identically (see that file) --
// required for the two to stay byte-compatible: an honestly-signed policy containing a
// '__proto__'-shaped or currently-polluted-name key must still verify.
//
// ── F-83: index-based key iteration, not for...of (PENTEST-003 second pass, F-71 follow-on) ────
// F-71 pristine-captured Object.keys and Array.prototype.sort themselves, and F-80 hardened the
// copy target -- but the loop READING the sorted key array back out was still `for (const k of
// keysArray)`, which is sugar for calling keysArray[Symbol.iterator]() and stepping it. That
// dispatch goes through Array.prototype[Symbol.iterator], a distinct property from
// Array.prototype.sort that F-71 never captured. Allowed code with earlier execution in the
// process can replace it (`Array.prototype[Symbol.iterator] = function* () { ... }`) with a
// generator that passes through every legitimate key while silently swallowing one forged key of
// the attacker's choice -- the pristine Object.keys/sort calls still return the real, complete
// key list; only the FOR...OF CONSUMING it is redirected. Reproduced live: a targeted filtering
// iterator dropped one forged rule from the signed bytes while `rules` (built the same way
// _loadAndVerify applies it) kept the forged rule as a real own property -- verify() returned
// true and the forged rule was live, with F-80's Object.create(null) fix still in place (this
// bypass is in the iteration source, not the assignment target, so F-80 does not touch it).
//
// Fix: iterate the sorted key array by index (`.length` + `keysArray[i]`) instead of for...of.
// Array indexed access and `.length` are direct property reads -- neither dispatches through
// Symbol.iterator or any other overridable protocol, so this closes the gap without needing a
// new pristine capture. scripts/sign-policy.js's own separate canonicalPayload (and signPolicy's
// inline copy) have the identical bug and are fixed identically, for the same byte-compatibility
// reason as F-80.
//
// ── F-84: pristine Object.create capture (PENTEST-005 finding, F-80 follow-on) ─────────────────
// F-80's fix (above) depends entirely on `Object.create(null)` actually producing a null-
// prototype object -- but `Object.create` itself was never added to F-71's pristine-capture list,
// so it was still called as the live ambient global. Allowed code that monkeypatches
// `Object.create` AFTER this module loads (e.g. redirecting the `proto === null` case to return
// an ordinary object instead) makes `canonicalPayload`'s `sorted = Object.create(null)` produce an
// object that DOES inherit from Object.prototype -- reopening F-80's exact bracket-assignment
// bug (`sorted[keys[i]] = ...` becomes interceptable again) through a new vector: attacking the
// construction of the copy target, not the copy loop itself, which F-80/F-83 never considered.
// Live-reproduced (PENTEST-005): with Object.create monkeypatched post-load, a policy signed
// WITHOUT a '__proto__' rule, tampered post-signing (raw text edit, no private key) to add one,
// verified VALID again -- identical bypass shape to the original pre-F-80 bug. F-80's own
// FW_FREEZE_PROTOTYPES=1 opt-in hardening does not mitigate this either: Object.create is an
// own property of the Object constructor function, not a property on any frozen prototype.
// Fix: capture `pristineCreate = Object.create` at module top level (F-71's list, above) and call
// `pristineCreate(null)` instead of the ambient global. scripts/sign-policy.js's three separate
// Object.create(null) call sites (canonicalPayload once, signPolicy once) have the identical gap
// and are fixed identically, for the same byte-compatibility reason as every prior follow-on here.
/**
 * Build the canonical signed payload buffer from a policy object.
 * Keys in rules are sorted alphabetically so the byte sequence is deterministic.
 * Uses pristine byte-building primitives (see F-71/F-84 notes above) so a post-load monkeypatch of
 * JSON.stringify / Object.keys / Array.prototype.sort / Buffer.from / Object.create cannot
 * decouple the bytes verified here from the rules object the agent applies. Uses a pristinely-
 * constructed null-prototype copy target (see F-80/F-84 notes above) so the copy loop itself
 * cannot be defeated via prototype-chain interception. Iterates the sorted key array by index, not
 * for...of (see F-83 note above), so the loop itself cannot be defeated via Symbol.iterator
 * interception either.
 */
function canonicalPayload(version, rules, signedAt) {
  const sorted = pristineCreate(null);
  const keys = pristineSort.call(pristineKeys(rules));
  for (let i = 0; i < keys.length; i++) sorted[keys[i]] = rules[keys[i]];
  return pristineBufferFrom(pristineStringify({ version, rules: sorted, signedAt }));
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
   * Uses pristineStringify to match the pristineCreateHash capture already on this line: this
   * is NOT a forgery gate (every tick re-verifies the signature via pristineVerify before this
   * runs), only staleness-hardening — a monkeypatched stringify here could at most collide two
   * distinct rule sets and suppress a legitimate hot-reload, the same downgrade concern the
   * F-62 createHash capture already addresses. Pristine on both inputs removes the ambiguity.
   */
  _hashRules(rules) {
    return pristineCreateHash('sha256').update(pristineStringify(rules)).digest('hex');
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

