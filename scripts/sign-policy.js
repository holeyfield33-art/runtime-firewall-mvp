#!/usr/bin/env node
// scripts/sign-policy.js
// Repository entry point kept for existing dev/test workflows. Since 0.6.3-candidate (SRS-FW-004)
// this is a thin wrapper: the ONE authoritative signing implementation lives in the published
// package at packages/fw-agent/src/policy-signing.js (CLI: packages/fw-agent/bin/aletheia-policy-sign.js,
// installed for consumers as `aletheia-policy-sign`). Do not add signing logic here.
//
// Usage (CLI, unchanged):
//   node scripts/sign-policy.js <private-key.pem> <rules.json> [output.json]
//
// The module also exports { signPolicy, canonicalPayload } for programmatic use in tests.
'use strict';

const { signPolicy, canonicalPayload } = require('../packages/fw-agent/src/policy-signing');

module.exports = { signPolicy, canonicalPayload };

if (require.main === module) {
  require('../packages/fw-agent/bin/aletheia-policy-sign.js');
}
