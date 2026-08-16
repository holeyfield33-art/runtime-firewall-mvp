#!/usr/bin/env node
// .agent/scripts/release-warden.js
// Deterministic release gate (Agent 3). Reads the engineer + verifier receipts, checkpoints, and
// evidence for a run directory and computes PASS / BLOCK / FREEZE. This script IS the Release
// Warden's authority — no LLM output can override what this computes. An LLM may be used upstream
// to draft warden-receipt.json's prose fields, but the "status" field MUST come from this script.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
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

// P2-01 finding: any legitimate change to a self-integrity-checked file (packages/fw-agent's
// verifySelfIntegrity() in index.js) requires regenerating packages/fw-agent/.helios-baseline —
// which is unconditionally on FORBIDDEN_PATH_PATTERNS above, so every such change would FREEZE
// even when the code change itself is correct and fully verified. The narrow carve-out below
// mirrors index.js's OWN computeSelfHash() exactly (same file list/order, same \r\n->\n
// normalization, same sha256/hex digest) and reads every input via `git show <sha>:<path>` — i.e.
// it recomputes the hash itself from the candidate's own committed content, it never trusts
// Agent 1's regenerated file byte-for-byte. A .helios-baseline change is excused from FREEZE ONLY
// if it is mathematically forced to be exactly what the candidate's own selfFiles hash to; any
// mismatch is treated as a STRONGER signal than a bare forbidden-path hit (baseline present but
// doesn't match the code it claims to protect), not a pass. Every other forbidden path is
// unaffected — this carve-out is scoped to exactly one filename.
const HELIOS_BASELINE_PATH = 'packages/fw-agent/.helios-baseline';
const HELIOS_SELF_INTEGRITY_FILES = [
  'index.js',
  'src/detector.js',
  'src/behavior-tracker.js',
  'src/policy-watcher.js',
  'src/quarantine.js',
  'src/audit-log.js',
  'src/policy.js',
].map((f) => `packages/fw-agent/${f}`);

function gitShowAtSha(sha, relPath) {
  try {
    return execFileSync('git', ['show', `${sha}:${relPath}`], { encoding: 'utf8' });
  } catch (e) {
    return null;
  }
}

function computeExpectedHeliosBaseline(sha) {
  const hash = crypto.createHash('sha256');
  for (const relPath of HELIOS_SELF_INTEGRITY_FILES) {
    const content = gitShowAtSha(sha, relPath);
    if (content === null) continue; // mirrors index.js's try/catch-and-skip on read failure
    hash.update(content.replace(/\r\n/g, '\n'), 'utf8');
  }
  return hash.digest('hex');
}

// Returns { ok: true } only if the baseline at `sha` is exactly what recomputing index.js's own
// hash algorithm over the candidate's own committed selfFiles produces.
function verifyHeliosBaselineRegeneration(sha) {
  const actualRaw = gitShowAtSha(sha, HELIOS_BASELINE_PATH);
  if (actualRaw === null) {
    return { ok: false, reason: `could not read ${HELIOS_BASELINE_PATH} at ${sha} via git show` };
  }
  const expected = computeExpectedHeliosBaseline(sha);
  const actual = actualRaw.trim();
  if (actual !== expected) {
    return {
      ok: false,
      reason: `${HELIOS_BASELINE_PATH} at ${sha} does NOT match the independently recomputed hash of its own selfFiles (expected ${expected}, found ${actual})`,
    };
  }
  return { ok: true, verifiedHash: expected };
}

// Files whose modification means a P0-registry-relevant sync would be needed before an eventual
// npm publish. Kept in sync with .agent/rules/sync-gate-rule.md.
const SYNC_TRIGGER_PATTERNS = [
  /packages\/fw-agent\/src\/detector\.js$/,
  /packages\/fw-agent\/src\/behavior-tracker\.js$/,
  /packages\/fw-agent\/src\/aho-corasick\.js$/,
  /packages\/fw-agent\/src\/policy\.js$/,
  /packages\/fw-agent\/index\.js$/,
];

// Agent 4 (Docs Scribe) runs only after this script has already emitted PASS, and is bound to an
// ALLOWLIST (not a blocklist) of documentation paths — its entire mandate is docs, so anything
// outside this list is out of scope by definition, regardless of what its receipt claims.
// Kept in sync with .agent/rules/security-gates.md and .agent/agents/docs-scribe.md.
const DOC_PATH_ALLOWLIST = [
  /(^|\/)CHANGELOG\.md$/,
  /(^|\/)README\.md$/,
  /(^|\/)docs\//,
  /(^|\/)\.agent\/README\.md$/,
  /(^|\/)\.agent\/RUNBOOK\.md$/,
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
  let forbiddenTouched = (engineer.changed_files || []).filter((f) =>
    FORBIDDEN_PATH_PATTERNS.some((re) => re.test(f))
  );

  // Narrow carve-out (see HELIOS_SELF_INTEGRITY_FILES comment above): excuse a .helios-baseline
  // hit ONLY if independently recomputing its hash from the candidate's own committed selfFiles
  // matches exactly. A mismatch is NOT excused — it stays in forbiddenTouched and freezes, same as
  // any other forbidden path, but with a stronger, more specific reason attached below.
  let heliosBaselineCheck = null;
  if (forbiddenTouched.includes(HELIOS_BASELINE_PATH)) {
    heliosBaselineCheck = verifyHeliosBaselineRegeneration(engineer.candidate_sha);
    if (heliosBaselineCheck.ok) {
      forbiddenTouched = forbiddenTouched.filter((f) => f !== HELIOS_BASELINE_PATH);
    }
  }
  checks.forbidden_files_touched = forbiddenTouched;
  checks.helios_baseline_regeneration = heliosBaselineCheck;
  if (forbiddenTouched.length > 0) {
    const baselineNote = forbiddenTouched.includes(HELIOS_BASELINE_PATH) && heliosBaselineCheck && !heliosBaselineCheck.ok
      ? ` (baseline recomputation: ${heliosBaselineCheck.reason})`
      : '';
    return freeze(`forbidden file(s) modified: ${forbiddenTouched.join(', ')}${baselineNote}`, checks);
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

  // ── Optional Agent 4 (Docs Scribe) receipt ──────────────────────────────────────────────────
  // Additive only: a missing docs-receipt.json never blocks or downgrades this PASS (Agent 4 may
  // simply not have run yet). But if present, it is held to the exact same mechanical discipline
  // as Agent 1 — "I only touched docs" is a claim in the receipt, not a fact, until every path in
  // changed_files is verified against DOC_PATH_ALLOWLIST and clear of FORBIDDEN_PATH_PATTERNS.
  let docsInfo = { present: false };
  const docsPath = path.join(runDir, 'docs-receipt.json');
  if (fs.existsSync(docsPath)) {
    const docsValid = validateReceipt(path.join(CONTRACTS_DIR, 'docs-receipt.schema.json'), docsPath);
    if (!docsValid.valid) {
      return freeze('docs-receipt.json failed schema validation', checks, docsValid.errors.map((e) => `docs-receipt: ${e}`));
    }
    const docs = loadJson(docsPath);
    const docsChangedFiles = docs.changed_files || [];
    const docsForbidden = docsChangedFiles.filter((f) => FORBIDDEN_PATH_PATTERNS.some((re) => re.test(f)));
    const docsOutOfScope = docsChangedFiles.filter((f) => !DOC_PATH_ALLOWLIST.some((re) => re.test(f)));
    const docsInvalidPaths = [...new Set([...docsForbidden, ...docsOutOfScope])];
    if (docsInvalidPaths.length > 0) {
      return freeze(`docs-scribe touched non-documentation path(s): ${docsInvalidPaths.join(', ')}`, checks);
    }
    docsInfo = { present: true, status: docs.status, changed_files: docsChangedFiles };
  }
  checks.docs_receipt = docsInfo;

  return {
    status: 'PASS',
    reasons,
    checks,
    freeze_reason: null,
    sync_required: syncRequired,
    sync_reason: syncRequired
      ? `changed_files touched detector-relevant source: ${syncFiles.join(', ')}`
      : 'no detector-relevant source files changed',
    docs: docsInfo,
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
    docs: result.docs || { present: false },
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

module.exports = { evaluate, writeWardenReceipt, FORBIDDEN_PATH_PATTERNS, SYNC_TRIGGER_PATTERNS, DOC_PATH_ALLOWLIST };
