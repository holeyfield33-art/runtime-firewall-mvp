#!/usr/bin/env node
// aletheia-policy-sign -- sign a rules file into policy.signed.json (ships in the npm package).
'use strict';

const fs = require('fs');
const { signPolicy, verifyPolicyEnvelope, publicKeyFromPrivate, publicKeyFingerprint } = require('../src/policy-signing');

const USAGE = `Usage: aletheia-policy-sign <private-key.pem> <rules.json> [output.json]

Signs a rules object ({"name": "BLOCK" | "QUARANTINE" | "OBSERVE", ...}) with your Ed25519 private
key and writes the signed envelope (default output: ./policy.signed.json). The agent reads
policy.signed.json from the directory the process is started in (process.cwd()) and verifies it
against FW_POLICY_PUBKEY.`;

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) { console.log(USAGE); process.exit(0); }
const [keyFile, rulesFile, outFile = 'policy.signed.json'] = args;
if (!keyFile || !rulesFile || args.length > 3) { console.error(USAGE); process.exit(2); }

let privateKeyPem, rules;
try { privateKeyPem = fs.readFileSync(keyFile, 'utf8'); }
catch (e) { console.error(`Cannot read private key: ${keyFile}\n${e.message}`); process.exit(1); }
try { rules = JSON.parse(fs.readFileSync(rulesFile, 'utf8')); }
catch (e) { console.error(`Cannot parse rules file: ${rulesFile}\n${e.message}`); process.exit(1); }

let signed, publicKeyPem;
try {
  signed = signPolicy(rules, privateKeyPem);
  publicKeyPem = publicKeyFromPrivate(privateKeyPem);
} catch (e) {
  console.error(`Signing failed: ${e.message}`); process.exit(1);
}
// Self-check with the agent's own canonical payload before writing anything.
if (!verifyPolicyEnvelope(signed, publicKeyPem)) {
  console.error('Internal error: the produced signature did not verify. Nothing written.'); process.exit(1);
}
fs.writeFileSync(outFile, JSON.stringify(signed, null, 2) + '\n', 'utf8');
console.log(`Signed policy written to ${outFile} (signedAt: ${signed.signedAt})`);
console.log(`Verifies with public key fingerprint: ${publicKeyFingerprint(publicKeyPem)}`);
console.log('The agent must run with FW_POLICY_PUBKEY set to that public key.');
