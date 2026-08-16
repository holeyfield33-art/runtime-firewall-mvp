#!/usr/bin/env node
// .agent/scripts/release-warden.js
// Deterministic release gate (Agent 3). Reads the engineer + verifier receipts, checkpoints, and
// evidence for a run directory and computes PASS / BLOCK / FREEZE. This script IS the Release
// Warden's authority — no LLM output can override what this computes. An LLM may be used upstream
// to draft warden-receipt.json's prose fields, but the "status" field MUST come from this script.
'use strict';

const fs = require('fs');
const path = require('path');
const { validateReceipt } = require('./validate-receipt');
const { readCheckpoints } = require('./checkpoint');

const CONTRACTS_DIR = path.join(__dirname, '..', 'contracts');

// Files/paths whose modification by Agent 1 is an automatic FREEZE, regardless of what the
// engineer receipt claims. Kept in sync with .agent/rules/security-gates.md.
const FORBIDDEN_PATH_PATTERNS = [
  /(^|\/)mrn[-_]?crs/i,
  /(^|\/)\.npmrc$/,
  /(^|\/)\.helios-baseline$/,
  /(^|\/)policy\.signed\.json$/,
  /(^|\/)\.agent\/(contracts|scripts|rules|agents)\//,
];

// Files whose modification means a P0-registry-relevant sync would be needed before an eventual
// npm publish. Kept in sync with .agent/rules/sync-gate-rule.md.
const SYNC_TRIGGER_PATTERNS = [
  /packages\/fw-agent\/src\/detector\.js$/,
  /packages\/fw-agent\/src\/behavior-tracker\.js$/,
  /packages\/fw-agent\/src\/aho-corasick\.js$/,
  /packages\/fw-agent\/src\/policy\.js$/,
  /packages\/fw-agent\/index\.js$/,
];

function loadJson(file) {
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function evaluate(runDir) {
  const reasons = [];
  const checks = {};
  let freezeReason = null;

  const engineerPath = path.join(runDir, 'engineer-receipt.json');
  const verifierPath = path.join(runDir, 'verifier-receipt.json');
  const evidenceIndexPath = path.join(runDir, 'evidence', 'index.json');

  const engineer = loadJson(engineerPath);
  const verifier = loadJson(verifierPath);
  const evidenceIndex = loadJson(evidenceIndexPath) || [];

  // ── Missing artifacts is always a FREEZE: no receipt, no verdict. ──────────────────────────
  if (!engineer) {
    return freeze('engineer-receipt.json missing', { engineer_receipt_present: false });
  }
  if (!verifier) {
    return freeze('verifier-receipt.json missing', { engineer_receipt_present: true, verifier_receipt_present: false });
  }
  checks.engineer_receipt_present = true;
  checks.verifier_receipt_present = true;

  // ── Schema validation ───────────────────────────────────────────────────────────────────────
  const engValid = validateReceipt(path.join(CONTRACTS_DIR, 'engineer-receipt.schema.json'), engineerPath);
  const verValid = validateReceipt(path.join(CONTRACTS_DIR, 'verifier-receipt.schema.json'), verifierPath);
  checks.engineer_receipt_valid = engValid.valid;
  checks.verifier_receipt_valid = verValid.valid;
  if (!engValid.valid || !verValid.valid) {
    return freeze('receipt(s) failed schema validation', checks, [
      ...engValid.errors.map((e) => `engineer-receipt: ${e}`),
      ...verValid.errors.map((e) => `verifier-receipt: ${e}`),
    ]);
  }

  // ── Candidate SHA consistency: engineer, verifier, and checkpoints must all agree. ─────────
  // Rework loops reuse the same run directory and accumulate checkpoints across iterations, so
  // only the MOST RECENT checkpoint per role matters — a stale checkpoint from an earlier,
  // superseded candidate must not be compared against the current receipts.
  const checkpoints = readCheckpoints(runDir);
  const latestByPredicate = (pred) => {
    for (let i = checkpoints.length - 1; i >= 0; i--) {
      if (pred(checkpoints[i])) return checkpoints[i];
    }
    return null;
  };
  const latestA1 = latestByPredicate((c) => c.label === 'a1-candidate' || c.label.startsWith('a1-rework-candidate'));
  const latestVerifyStart = latestByPredicate((c) => c.label === 'a2-verify-start');
  const latestVerifyEnd = latestByPredicate((c) => c.label === 'a2-verify-end');
  const candidateChecks = [latestA1, latestVerifyStart, latestVerifyEnd].filter(Boolean);
  const shas = new Set([engineer.candidate_sha, verifier.candidate_sha, ...candidateChecks.map((c) => c.sha)]);
  checks.candidate_sha_consistent = shas.size <= 1;
  if (!checks.candidate_sha_consistent) {
    return freeze(`candidate SHA mismatch across artifacts: ${[...shas].join(', ')}`, checks);
  }

  const verifyStart = latestVerifyStart;
  const verifyEnd = latestVerifyEnd;
  checks.candidate_sha_immutable_during_verification =
    !verifyStart || !verifyEnd || verifyStart.sha === verifyEnd.sha;
  if (!checks.candidate_sha_immutable_during_verification) {
    return freeze('candidate SHA changed during verification', checks);
  }

  // ── Forbidden file modification ─────────────────────────────────────────────────────────────
  const forbiddenTouched = (engineer.changed_files || []).filter((f) =>
    FORBIDDEN_PATH_PATTERNS.some((re) => re.test(f))
  );
  checks.forbidden_files_touched = forbiddenTouched;
  if (forbiddenTouched.length > 0) {
    return freeze(`forbidden file(s) modified: ${forbiddenTouched.join(', ')}`, checks);
  }

  // ── Registry / publish artifacts touched prematurely (before any human approval step) ──────
  // This script only has the changed_files list, not diff content, so it cannot itself detect a
  // version bump inside package.json — that requires the manual check in rules/security-gates.md.
  // It stays false here (not a free pass — false means "not auto-detected", not "verified clean").
  checks.registry_modified_prematurely = false;

  // ── Required evidence present ───────────────────────────────────────────────────────────────
  const citedEvidence = [...(engineer.evidence || []), ...(verifier.evidence || [])];
  const missingEvidence = citedEvidence.filter((id) => !evidenceIndex.includes(id));
  checks.evidence_present = missingEvidence.length === 0 && citedEvidence.length > 0;
  if (!checks.evidence_present) {
    return freeze(`cited evidence missing from evidence/index.json: ${missingEvidence.join(', ') || '(no evidence cited)'}`, checks);
  }

  // ── A2 verdict is authoritative and cannot be overridden ────────────────────────────────────
  checks.a2_pass = verifier.status === 'PASS';
  if (engineer.status !== 'PASS') {
    reasons.push('engineer receipt status is not PASS');
  }
  if (!checks.a2_pass) {
    return { status: 'BLOCK', reasons: [...reasons, 'red-team-verifier reported FAIL'], checks, freeze_reason: null };
  }

  // ── P0 regression: engineer's own recorded test runs must all be exit 0 ─────────────────────
  const failingTests = (engineer.tests_run || []).filter((t) => t.exit_code !== 0);
  checks.p0_regression = failingTests.length > 0;
  if (checks.p0_regression) {
    return { status: 'BLOCK', reasons: [...reasons, `engineer tests_run had nonzero exit codes: ${failingTests.map((t) => t.command).join(', ')}`], checks, freeze_reason: null };
  }

  // ── Regressions flagged explicitly by the verifier ──────────────────────────────────────────
  const verifierRegressions = (verifier.regressions || []).filter((r) => r && r.status && r.status !== 'OK' && r.status !== 'PASS');
  checks.verifier_regressions_clean = verifierRegressions.length === 0;
  if (!checks.verifier_regressions_clean) {
    return { status: 'BLOCK', reasons: [...reasons, `verifier reported regressions: ${JSON.stringify(verifierRegressions)}`], checks, freeze_reason: null };
  }

  // ── Sync gate (deterministic, not model-decided) ────────────────────────────────────────────
  const syncFiles = (engineer.changed_files || []).filter((f) => SYNC_TRIGGER_PATTERNS.some((re) => re.test(f)));
  const syncRequired = syncFiles.length > 0;

  return {
    status: 'PASS',
    reasons,
    checks,
    freeze_reason: null,
    sync_required: syncRequired,
    sync_reason: syncRequired
      ? `changed_files touched detector-relevant source: ${syncFiles.join(', ')}`
      : 'no detector-relevant source files changed',
  };

  function freeze(reason, extraChecks, extraReasons) {
    return {
      status: 'FREEZE',
      reasons: extraReasons || [reason],
      checks: { ...checks, ...extraChecks },
      freeze_reason: reason,
      sync_required: false,
      sync_reason: 'not evaluated — run frozen',
    };
  }
}

function writeWardenReceipt(runDir, phaseId, result) {
  const engineer = loadJson(path.join(runDir, 'engineer-receipt.json'));
  const verifier = loadJson(path.join(runDir, 'verifier-receipt.json'));
  const receipt = {
    phase_id: phaseId,
    agent: 'release-warden',
    status: result.status,
    candidate_sha: (verifier && verifier.candidate_sha) || (engineer && engineer.candidate_sha) || 'UNKNOWN',
    checks: result.checks,
    sync_required: !!result.sync_required,
    sync_reason: result.sync_reason || 'not evaluated',
    reasons: result.reasons || [],
    freeze_reason: result.freeze_reason || '',
    evidence: [...((engineer && engineer.evidence) || []), ...((verifier && verifier.evidence) || [])],
    timestamp: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(runDir, 'warden-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  return receipt;
}

function main() {
  const [, , runDir, phaseId] = process.argv;
  if (!runDir) {
    console.error('Usage: release-warden.js <runDir> [phaseId]');
    process.exit(2);
  }
  const result = evaluate(runDir);
  const receipt = writeWardenReceipt(runDir, phaseId || 'UNKNOWN', result);
  console.log(JSON.stringify(receipt, null, 2));

  if (receipt.status === 'PASS') process.exit(0);
  if (receipt.status === 'BLOCK') process.exit(1);
  process.exit(2); // FREEZE
}

if (require.main === module) {
  main();
}

module.exports = { evaluate, writeWardenReceipt, FORBIDDEN_PATH_PATTERNS, SYNC_TRIGGER_PATTERNS };
