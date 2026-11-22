#!/usr/bin/env node
// aletheia-policy-keygen -- generate an Ed25519 policy-signing key pair (ships in the npm package).
// The private key is written to a file (mode 0600) and is NEVER printed to stdout.
'use strict';

const path = require('path');
const { writeKeyPairFiles, publicKeyFingerprint } = require('../src/policy-signing');

const USAGE = `Usage: aletheia-policy-keygen [--private-key <file>] [--public-key <file>] [--force]

Generates an Ed25519 key pair for signing policy.signed.json.
  --private-key <file>  default: ./aletheia-policy-private.pem  (written with mode 0600)
  --public-key  <file>  default: ./aletheia-policy-public.pem
  --force               replace existing key files (otherwise the command refuses)

The private key is never printed. Keep it off the production host and out of source control.
Production: set FW_POLICY_PUBKEY to the contents of the public key file.`;

function parseArgs(argv) {
  const opts = { privateKey: 'aletheia-policy-private.pem', publicKey: 'aletheia-policy-public.pem', force: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { opts.help = true; }
    else if (a === '--force') { opts.force = true; }
    else if (a === '--private-key' && argv[i + 1]) { opts.privateKey = argv[++i]; }
    else if (a === '--public-key' && argv[i + 1]) { opts.publicKey = argv[++i]; }
    else { opts.error = `Unknown or incomplete argument: ${a}`; }
  }
  return opts;
}

const opts = parseArgs(process.argv.slice(2));
if (opts.help) { console.log(USAGE); process.exit(0); }
if (opts.error) { console.error(opts.error + '\n\n' + USAGE); process.exit(2); }
if (path.resolve(opts.privateKey) === path.resolve(opts.publicKey)) {
  console.error('--private-key and --public-key must be different files.'); process.exit(2);
}

let result;
try {
  result = writeKeyPairFiles(opts.privateKey, opts.publicKey, { force: opts.force });
} catch (e) {
  console.error(e.code === 'EEXIST_KEYFILE' ? e.message : `Key generation failed: ${e.message}`);
  process.exit(1);
}

console.log(`Private key written to ${result.privateKeyPath} (mode 0600) -- not printed; keep it secret.`);
console.log(`Public key written to  ${result.publicKeyPath}`);
console.log(`Public key fingerprint: ${publicKeyFingerprint(result.publicKey)}`);
console.log('');
console.log('Next steps:');
console.log(`  1. Write your rules, e.g. {"some-package": "BLOCK"} in rules.json`);
console.log(`  2. npx aletheia-policy-sign ${result.privateKeyPath} rules.json policy.signed.json`);
console.log('  3. Put policy.signed.json in the directory your app is STARTED from (process.cwd()).');
console.log(`  4. Production: export FW_POLICY_PUBKEY="$(cat ${result.publicKeyPath})"`);
console.log('     Do not edit files under node_modules; FW_POLICY_PUBKEY is the supported configuration.');
