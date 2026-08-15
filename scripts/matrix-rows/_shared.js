// scripts/matrix-rows/_shared.js
// Tiny helpers shared by the per-row probes in this directory. Deliberately does NOT require
// 'vm', 'child_process', or 'worker_threads' itself — each row probe requires only what its own
// execution surface needs, so no single file combines the signals (e.g. dynamic code + process
// exec) that the real behavioral detector (DYNAMIC_CODE_EXEC_CHAIN) is designed to block. Every
// row file is its own Module.prototype._compile unit, so combining unrelated primitives in one
// file would make the *harness* itself look like the malware pattern being probed for.
'use strict';

const fs = require('fs');
const path = require('path');

const FIXTURES_DIR = path.join(__dirname, '..', '..', 'red-team', 'corpus', 'fixtures');
const AGENT_PATH = path.join(__dirname, '..', '..', 'packages', 'fw-agent', 'index.js');

function outfileReport(rowId) {
  const outFile = process.env.MATRIX_OUTFILE;
  return function report(verdict, detail) {
    const payload = JSON.stringify({ rowId, verdict, detail });
    if (outFile) {
      fs.writeFileSync(outFile, payload, 'utf8');
    } else {
      process.stdout.write(payload + '\n');
    }
  };
}

function isFirewallError(e) {
  return !!(e && typeof e.message === 'string' && e.message.includes('[Firewall]'));
}

module.exports = { FIXTURES_DIR, AGENT_PATH, outfileReport, isFirewallError };
