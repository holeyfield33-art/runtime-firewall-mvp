#!/usr/bin/env node
// scripts/sign-policy.js
// Signs a policy rules file with an Ed25519 private key, producing policy.signed.json.
//
// Usage (CLI):
//   node scripts/sign-policy.js <private-key.pem> <rules.json> [output.json]
//
// rules.json format:
//   { "lodash": "QUARANTINE", "express": "OBSERVE" }
//
// Output (policy.signed.json):
//   { "version": 1, "rules": {...}, "signedAt": "ISO", "signature": "base64url" }
//
// The module also exports { signPolicy } for programmatic use in tests.
'use strict';

const crypto = require('crypto');
const fs = require('fs');

/**
 * Sort rules keys alphabetically for a deterministic canonical form.
 * The signed payload is always JSON.stringify({ version, rules: sortedRules, signedAt }).
 *
 * F-80: the copy target is Object.create(null), not `{}` -- see the matching note in
 * packages/fw-agent/src/policy-watcher.js's canonicalPayload(). A plain `{}` here is vulnerable
 * to the same prototype-chain interception on the copy loop's bracket assignment (a literal
 * '__proto__' key, or any key an already-running process has put an Object.prototype accessor on)
 * silently dropping that key from the signed bytes. Kept byte-identical to the verify-side
 * implementation deliberately: for a rules object with no such key, a null-prototype copy target
 * serializes identically to a plain-object one (JSON.stringify never consults the prototype
 * chain), so this changes nothing for ordinary policies -- it only matters for the keys that were
 * being silently dropped before.
 *
 * F-83: the copy loop reads the sorted key array by index, not `for...of` -- see the matching
 * note in policy-watcher.js's canonicalPayload(). `for...of` dispatches through
 * Array.prototype[Symbol.iterator], which allowed code with earlier execution in the process can
 * replace with a filtering generator that silently drops one key from what the loop sees while
 * Object.keys/sort themselves still returned the complete list -- decoupling the signed bytes
 * from the rules object a step earlier than F-80's bracket-assignment gap, and independent of it.
 * This file runs offline in a trusted signer process, so it is not the live attack surface (the
 * verify-side copy in policy-watcher.js is), but it must stay byte-identical to that side or an
 * honestly-signed policy could sign successfully yet fail to verify.
 */
function canonicalPayload(version, rules, signedAt) {
  const sorted = Object.create(null);
  const keys = Object.keys(rules).sort();
  for (let i = 0; i < keys.length; i++) sorted[keys[i]] = rules[keys[i]];
  return Buffer.from(JSON.stringify({ version, rules: sorted, signedAt }));
}

/**
 * Sign a rules object with the given Ed25519 private key PEM.
 * Returns the full policy object ready to write as policy.signed.json.
 */
function signPolicy(rules, privateKeyPem, signedAt) {
  const ts = signedAt || new Date().toISOString();
  const version = 1;
  // F-80: same null-prototype fix as canonicalPayload() above -- this `sorted` becomes the
  // `rules` field written into the actual signed output file, not just the signed bytes, so an
  // unfixed plain-object copy here would silently drop the same class of key from a LEGITIMATE
  // signing operation too (a correctness bug, not by itself an attacker-exploitable one, since
  // this runs only in the trusted offline signer -- but it must match the verify side or an
  // honestly-signed policy containing such a key would sign successfully yet fail to verify).
  //
  // F-83 follow-up: this loop was missed in the first F-83 pass -- canonicalPayload() a few lines
  // up was switched to index-based iteration, but this SEPARATE copy (which builds the `sorted`
  // object that becomes BOTH the signed payload's input AND the output `rules` field) was left on
  // `for...of`. Caught by PENTEST-005's Threat Modeler before merge, not by the original fix.
  // The practical exposure differs from the verify-side bug: because this same `sorted` object
  // feeds both canonicalPayload() and the returned `rules` field, a Symbol.iterator pollution here
  // drops a key from BOTH consistently -- it cannot decouple signed-bytes from applied-rules the
  // way F-83's verify-side bug could, so it is not by itself a forgery vector. It IS a correctness
  // and supply-chain-on-the-signing-tool concern: an operator signing a policy that is SUPPOSED to
  // include a BLOCK rule, in a compromised or already-polluted offline signing environment, could
  // get back a validly-signed policy.signed.json silently missing that exact rule, with no error.
  // Fixed identically to canonicalPayload() -- index-based iteration, immune to Symbol.iterator.
  const sorted = Object.create(null);
  const keys = Object.keys(rules).sort();
  for (let i = 0; i < keys.length; i++) sorted[keys[i]] = rules[keys[i]];
  const payload = canonicalPayload(version, sorted, ts);
  const sigBuffer = crypto.sign(null, payload, { key: privateKeyPem, format: 'pem', type: 'pkcs8' });
  return {
    version,
    rules: sorted,
    signedAt: ts,
    signature: sigBuffer.toString('base64url'),
  };
}

module.exports = { signPolicy, canonicalPayload };

// ── CLI entrypoint ────────────────────────────────────────────────────────────
if (require.main === module) {
  const [,, keyFile, rulesFile, outFile = 'policy.signed.json'] = process.argv;
  if (!keyFile || !rulesFile) {
    console.error('Usage: node scripts/sign-policy.js <private-key.pem> <rules.json> [output.json]');
    process.exit(1);
  }

  let privateKeyPem, rules;
  try {
    privateKeyPem = fs.readFileSync(keyFile, 'utf8');
  } catch (e) {
    console.error(`Cannot read private key: ${keyFile}\n${e.message}`);
    process.exit(1);
  }
  try {
    rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8'));
  } catch (e) {
    console.error(`Cannot parse rules file: ${rulesFile}\n${e.message}`);
    process.exit(1);
  }

  const signed = signPolicy(rules, privateKeyPem);
  fs.writeFileSync(outFile, JSON.stringify(signed, null, 2) + '\n', 'utf8');
  console.log(`Signed policy written to ${outFile} (signedAt: ${signed.signedAt})`);
}
