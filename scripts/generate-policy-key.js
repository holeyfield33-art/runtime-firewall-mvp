#!/usr/bin/env node
// scripts/generate-policy-key.js
// Repository entry point kept for existing workflows. Since 0.6.3-candidate (SRS-FW-004) this
// delegates to the package-owned CLI packages/fw-agent/bin/aletheia-policy-keygen.js (installed
// for consumers as `aletheia-policy-keygen`). It writes the key pair to files and never prints
// the private key; it refuses to overwrite existing key files unless --force is given.
//
// Usage:
//   node scripts/generate-policy-key.js [--private-key <file>] [--public-key <file>] [--force]
'use strict';

require('../packages/fw-agent/bin/aletheia-policy-keygen.js');
