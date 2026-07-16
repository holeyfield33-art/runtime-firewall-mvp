#!/usr/bin/env node
// scripts/generate-baseline.js
// Regenerates packages/fw-agent/.helios-baseline — the SHA-256 self-integrity anchor the
// agent verifies on every startup (see verifySelfIntegrity() in packages/fw-agent/index.js).
//
// The hash MUST be computed identically to index.js: same file list, same order, UTF-8 with
// CRLF→LF normalization (F-23, so the check is stable across Linux/macOS/Windows/CI). Any edit
// to one of the hashed source files requires re-running this and committing the new baseline,
// or the agent will refuse to start.
//
// Usage:
//   node scripts/generate-baseline.js          # write the baseline
//   node scripts/generate-baseline.js --check   # verify without writing (exit 1 on mismatch)
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const AGENT_DIR = path.join(__dirname, '..', 'packages', 'fw-agent');
const BASELINE_FILE = path.join(AGENT_DIR, '.helios-baseline');

// Keep this list in lockstep with verifySelfIntegrity() in index.js.
const SELF_FILES = [
  path.join(AGENT_DIR, 'index.js'),
  path.join(AGENT_DIR, 'src', 'detector.js'),
  path.join(AGENT_DIR, 'src', 'behavior-tracker.js'),
  path.join(AGENT_DIR, 'src', 'policy-watcher.js'),
  path.join(AGENT_DIR, 'src', 'quarantine.js'),
  path.join(AGENT_DIR, 'src', 'audit-log.js'),
  path.join(AGENT_DIR, 'src', 'policy.js'),
];

function computeSelfHash() {
  const hash = crypto.createHash('sha256');
  for (const f of SELF_FILES) {
    try {
      const content = fs.readFileSync(f, 'utf8').replace(/\r\n/g, '\n');
      hash.update(content, 'utf8');
    } catch (e) {
      console.error(`[generate-baseline] Cannot read ${f}: ${e.message}`);
      process.exit(1);
    }
  }
  return hash.digest('hex');
}

const current = computeSelfHash();

if (process.argv.includes('--check')) {
  const stored = fs.existsSync(BASELINE_FILE) ? fs.readFileSync(BASELINE_FILE, 'utf8').trim() : '(missing)';
  if (stored === current) {
    console.log(`[generate-baseline] OK — baseline matches (${current}).`);
    process.exit(0);
  }
  console.error(`[generate-baseline] MISMATCH\n  stored:  ${stored}\n  current: ${current}`);
  process.exit(1);
}

fs.writeFileSync(BASELINE_FILE, current + '\n', 'utf8');
console.log(`[generate-baseline] Wrote ${BASELINE_FILE}\n  ${current}`);
