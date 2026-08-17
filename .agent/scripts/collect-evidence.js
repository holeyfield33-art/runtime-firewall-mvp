#!/usr/bin/env node
// .agent/scripts/collect-evidence.js
// Runs a single verification/test command, captures stdout/stderr/exit code, hashes the full
// output for tamper-evidence, and writes an evidence-bundle.schema.json-conformant record plus
// the raw logs into <runDir>/evidence/. This is the only sanctioned way receipts should cite
// "evidence" — a receipt claiming a result must point at one of these files.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { execFileSync } = require('child_process');

const EXCERPT_LIMIT = 4000;

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function currentSha(cwd) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim();
  } catch (e) {
    return 'UNKNOWN';
  }
}

function collect({ runDir, phaseId, evidenceId, command, cwd, timeoutMs }) {
  const evidenceDir = path.join(runDir, 'evidence');
  fs.mkdirSync(evidenceDir, { recursive: true });

  const startedAt = new Date().toISOString();
  // shell:true delegates to the platform native shell (cmd.exe on Windows, /bin/sh on Unix)
  // so the same command string works across environments without a hard-coded 'bash' dependency.
  const result = spawnSync(command, {
    shell: true,
    cwd,
    encoding: 'utf8',
    timeout: timeoutMs || 10 * 60 * 1000,
    maxBuffer: 1024 * 1024 * 64,
  });
  const endedAt = new Date().toISOString();

  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  const exitCode = result.status === null ? -1 : result.status;
  const timedOut = !!result.signal && result.status === null;

  fs.writeFileSync(path.join(evidenceDir, `${evidenceId}.stdout.log`), stdout);
  fs.writeFileSync(path.join(evidenceDir, `${evidenceId}.stderr.log`), stderr);

  const record = {
    id: evidenceId,
    run_id: path.basename(runDir),
    phase_id: phaseId,
    type: 'command',
    command,
    exit_code: exitCode,
    started_at: startedAt,
    ended_at: endedAt,
    cwd,
    git_sha: currentSha(cwd),
    stdout_sha256: sha256(stdout),
    stderr_sha256: sha256(stderr),
    stdout_excerpt: stdout.slice(0, EXCERPT_LIMIT),
    stderr_excerpt: stderr.slice(0, EXCERPT_LIMIT),
    timed_out: timedOut,
  };
  fs.writeFileSync(path.join(evidenceDir, `${evidenceId}.json`), JSON.stringify(record, null, 2) + '\n');

  const indexFile = path.join(evidenceDir, 'index.json');
  const index = fs.existsSync(indexFile) ? JSON.parse(fs.readFileSync(indexFile, 'utf8')) : [];
  index.push(evidenceId);
  fs.writeFileSync(indexFile, JSON.stringify(index, null, 2) + '\n');

  return record;
}

function main() {
  const args = process.argv.slice(2);
  const sepIdx = args.indexOf('--');
  if (sepIdx === -1) {
    console.error('Usage: collect-evidence.js <runDir> <phaseId> <evidenceId> [--cwd <dir>] -- <command...>');
    process.exit(2);
  }
  const before = args.slice(0, sepIdx);
  const command = args.slice(sepIdx + 1).join(' ');
  const [runDir, phaseId, evidenceId] = before;
  let cwd = process.cwd();
  const cwdIdx = before.indexOf('--cwd');
  if (cwdIdx !== -1) cwd = before[cwdIdx + 1];

  if (!runDir || !phaseId || !evidenceId || !command) {
    console.error('Usage: collect-evidence.js <runDir> <phaseId> <evidenceId> [--cwd <dir>] -- <command...>');
    process.exit(2);
  }

  const record = collect({ runDir, phaseId, evidenceId, command, cwd });
  console.log(JSON.stringify({ id: record.id, exit_code: record.exit_code, git_sha: record.git_sha }, null, 2));
  // The evidence collector itself never "fails" on a nonzero command exit code — a red-team
  // attack that returns nonzero because it was correctly blocked is a successful observation.
  // Callers (agents/gates) decide what an exit code means for their own PASS/FAIL logic.
}

if (require.main === module) {
  main();
}

module.exports = { collect, sha256 };
