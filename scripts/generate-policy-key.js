#!/usr/bin/env node
// scripts/generate-policy-key.js
// Generates an Ed25519 key pair for policy signing.
//
// Usage:
//   node scripts/generate-policy-key.js
//
// Output:
//   Prints the public key (embed in policy-watcher.js) and private key (store securely).
//   NEVER commit the private key to source control in a production deployment.
'use strict';

const { generateKeyPairSync } = require('crypto');

const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

console.log('=== Ed25519 Policy Signing Key Pair ===\n');
console.log('PUBLIC KEY (embed as DEV_PUBLIC_KEY_PEM in packages/fw-agent/src/policy-watcher.js):');
console.log(publicKey);
console.log('PRIVATE KEY (store securely — never commit to production repos):');
console.log(privateKey);
console.log('\nNext steps:');
console.log('  1. Replace DEV_PUBLIC_KEY_PEM in policy-watcher.js with the public key above.');
console.log('  2. Regenerate .helios-baseline: see CONTRIBUTING.md (baseline regeneration instructions)');
console.log('  3. Sign your policy: node scripts/sign-policy.js <private-key.pem> <rules.json>');
