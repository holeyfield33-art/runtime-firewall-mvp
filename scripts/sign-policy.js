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
 */
function canonicalPayload(version, rules, signedAt) {
  const sorted = {};
  for (const k of Object.keys(rules).sort()) sorted[k] = rules[k];
  return Buffer.from(JSON.stringify({ version, rules: sorted, signedAt }));
}

/**
 * Sign a rules object with the given Ed25519 private key PEM.
 * Returns the full policy object ready to write as policy.signed.json.
 */
function signPolicy(rules, privateKeyPem, signedAt) {
  const ts = signedAt || new Date().toISOString();
  const version = 1;
  const sorted = {};
  for (const k of Object.keys(rules).sort()) sorted[k] = rules[k];
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
