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

// Files that must never appear in a published package's file list, regardless of what the Release
// Auditor's (Agent 2r) own `status` says — "what accidentally got packaged" is meant to be a
// mechanical decision, not a trust call on prose. Checked against release-audit-receipt.json's
// `packaged_files` (the real, verbatim `npm pack --dry-run` output) whenever that receipt exists,
// independent of any release-track opt-in flag. Kept in sync with .agent/agents/release-auditor.md.
const PACKAGE_DENY_PATTERNS = [
  /(^|\/)test\//i,
  /(^|\/)tests\//i,
  /(^|\/)__tests__\//i,
  /\.test\.[cm]?js$/i,
  /\.spec\.[cm]?js$/i,
  /(^|\/)\.git\//,
  /(^|\/)\.github\//,
  /(^|\/)node_modules\//,
  /(^|\/)\.env(\.|$)/,
  /(^|\/).*-key\.pem$/i,
  /(^|\/)dev-private-key\.pem$/i,
  /(^|\/)\.agent\//,
  /(^|\/)red-team\//i,
  /(^|\/)coverage\//i,
  /(^|\/)\.nyc_output\//,
  /\.log$/i,
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

// SECURITY: an evidence ID existing in evidence/index.json is not sufficient proof it was actually
// produced for THIS run — the index is a flat array of ID strings, cross-referenced by every
// receipt-evidence check in this file, but nothing previously opened the evidence bundle itself
// (collect-evidence.js's own {id}.json record, which carries its own recorded phase_id/run_id) to
// confirm those match the phase/run actually being evaluated. Evidence captured for a different
// phase or run — a typo'd --cwd/runDir/phaseId, or an ID string copied from elsewhere — was
// previously accepted as valid provenance without complaint. Every evidence-citation check in this
// file now calls this after confirming index membership, never as a replacement for it (a missing
// bundle file is itself reported, distinctly, from a bundle that exists but doesn't match).
function verifyEvidenceBinding(runDir, phaseId, evidenceIds) {
  const runId = path.basename(runDir);
  const mismatched = [];
  for (const id of evidenceIds) {
    const bundlePath = path.join(runDir, 'evidence', `${id}.json`);
    let bundle;
    try {
      bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
    } catch (e) {
      mismatched.push(`${id} (evidence bundle file missing or unreadable: ${e.message})`);
      continue;
    }
    if (bundle.run_id !== runId || bundle.phase_id !== phaseId) {
      mismatched.push(`${id} (recorded for run_id=${bundle.run_id}, phase_id=${bundle.phase_id}, not this run's ${runId}/${phaseId})`);
    }
  }
  return mismatched;
}

// Reused by the reliability-receipt gate below. Independent of the base_sha directive lookup
// earlier in evaluate() (that one is scoped inside the base_sha/candidateSha guard) — this one
// must run unconditionally, since require_reliability_review has to be checked even when base_sha
// is absent.
//
// SECURITY: resolves by each directive file's OWN `phase_id` field, matched EXACTLY — never by
// filename. The previous implementation filtered filenames with `startsWith(phaseId)` and took
// files[0] with no exact-match check and no disambiguation of multiple matches. Demonstrated
// exploitable both directions: an unrelated directive whose filename happens to be a string-
// prefix superset of the target phase_id could spuriously impose its own require_* flags on a
// phase that never asked for them, or — depending on filesystem listing order, since readdirSync
// order is not guaranteed sorted — silently absorb and skip a genuinely required review instead.
// Directory listing is now sorted for determinism, and every file's parsed content is checked
// against phaseId directly; a directive file that fails to parse is skipped (not fatal), not
// forwarded as a match.
function loadDirectiveForPhase(phaseId) {
  if (!phaseId) return null;
  let files;
  try {
    const directivesDir = path.join(__dirname, '..', 'directives');
    files = fs.readdirSync(directivesDir).filter((f) => f.endsWith('.json')).sort();
    for (const f of files) {
      let directive;
      try {
        directive = loadJson(path.join(directivesDir, f));
      } catch (e) {
        continue; // malformed directive file — skip it, never let it crash directive resolution
      }
      if (directive && directive.phase_id === phaseId) return directive;
    }
    return null;
  } catch (e) {
    return null;
  }
}

// Shared by every optional PASS/FAIL "verdict" receipt beyond the mandatory engineer/verifier
// pair (reliability, quality, test-coverage, and any future one): FREEZE if required-but-missing,
// invalid, wrong candidate SHA, or citing evidence that doesn't exist (provenance broke); BLOCK if
// present and status !== 'PASS' (send back to rework, not fatal); otherwise present-and-fine or
// simply absent-and-not-required. Pulled into one function specifically because copy-pasting this
// per receipt type already produced one real bug (the threat-model precondition check originally
// sat AFTER the a2_pass early-return and so never ran on FAIL runs — see PENTEST-001's history) —
// consolidating it here means every future receipt type gets that fix for free instead of risking
// the same class of drift again. Pure: returns a descriptor, never calls freeze()/mutates `checks`
// itself, so the caller (which owns those closures) decides what to do with the outcome.
function evaluateOptionalVerdictReceipt({ runDir, phaseId, candidateSha, evidenceIndex, filename, schemaName, required, roleLabel }) {
  const filePath = path.join(runDir, filename);
  const exists = fs.existsSync(filePath);
  if (required && !exists) {
    return { outcome: 'freeze', reason: `${filename} required by directive but missing`, info: { present: false, required } };
  }
  if (!exists) {
    return { outcome: 'ok', info: { present: false, required } };
  }
  const valid = validateReceipt(path.join(CONTRACTS_DIR, schemaName), filePath);
  if (!valid.valid) {
    return {
      outcome: 'freeze',
      reason: `${filename} failed schema validation`,
      extraReasons: valid.errors.map((e) => `${filename}: ${e}`),
      info: { present: false, required },
    };
  }
  const receipt = loadJson(filePath);
  if (receipt.candidate_sha !== candidateSha) {
    return {
      outcome: 'freeze',
      reason: `${filename} candidate_sha (${receipt.candidate_sha}) does not match candidate_sha (${candidateSha})`,
      info: { present: false, required },
    };
  }
  const cited = receipt.evidence || [];
  const missing = cited.filter((id) => !evidenceIndex.includes(id));
  if (missing.length > 0) {
    return {
      outcome: 'freeze',
      reason: `${filename} cites evidence missing from evidence/index.json: ${missing.join(', ')}`,
      info: { present: false, required },
    };
  }
  const mismatchedEvidence = verifyEvidenceBinding(runDir, phaseId, cited);
  if (mismatchedEvidence.length > 0) {
    return {
      outcome: 'freeze',
      reason: `${filename} cites evidence not recorded for this phase/run: ${mismatchedEvidence.join('; ')}`,
      info: { present: false, required },
    };
  }
  const info = { present: true, required, status: receipt.status };
  if (receipt.status !== 'PASS') {
    return { outcome: 'block', reason: `${roleLabel} reported ${receipt.status}`, info, receipt };
  }
  return { outcome: 'ok', info, receipt };
}

function evaluate(runDir, phaseId) {
  const reasons = [];
  const checks = {};
  let freezeReason = null;

  const engineerPath = path.join(runDir, 'engineer-receipt.json');
  const verifierPath = path.join(runDir, 'verifier-receipt.json');
  const evidenceIndexPath = path.join(runDir, 'evidence', 'index.json');

  // SECURITY: malformed JSON in either mandatory receipt must FREEZE with a specific reason, not
  // crash. loadJson()'s own JSON.parse can still throw here (unlike validateReceipt(), which is
  // now hardened below) — caught explicitly so the diagnosis stays precise instead of falling
  // through to main()'s generic catch-all.
  let engineer;
  try {
    engineer = loadJson(engineerPath);
  } catch (e) {
    return freeze(`engineer-receipt.json is not valid JSON: ${e.message}`, { engineer_receipt_present: true, engineer_receipt_valid: false });
  }
  let verifier;
  try {
    verifier = loadJson(verifierPath);
  } catch (e) {
    return freeze(`verifier-receipt.json is not valid JSON: ${e.message}`, { engineer_receipt_present: true, verifier_receipt_present: true, verifier_receipt_valid: false });
  }
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
  //
  // SECURITY: checkpoints.json is the ONLY corroboration of candidate_sha that isn't self-reported
  // by the very receipts being evaluated. It MUST be mandatory, not merely checked-if-present —
  // a run with no checkpoints.json at all (or missing one of the three required labels) has zero
  // independent confirmation that any verification actually happened against the claimed SHA, and
  // must FREEZE. Demonstrated exploitable when this was optional: two fabricated receipts that
  // merely agree with each other on a fake candidate_sha, with checkpoints.json entirely absent,
  // reached PASS — candidate_sha_consistent degraded to bare self-report agreement, and
  // candidate_sha_immutable_during_verification was vacuously true via `!verifyStart || !verifyEnd`.
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

  const missingCheckpoints = [
    !latestA1 && 'a1-candidate',
    !latestVerifyStart && 'a2-verify-start',
    !latestVerifyEnd && 'a2-verify-end',
  ].filter(Boolean);
  if (missingCheckpoints.length > 0) {
    return freeze(
      `checkpoints.json missing required checkpoint(s): ${missingCheckpoints.join(', ')} — candidate SHA has no independent corroboration`,
      { checkpoints_present: false },
    );
  }
  checks.checkpoints_present = true;

  const shas = new Set([engineer.candidate_sha, verifier.candidate_sha, latestA1.sha, latestVerifyStart.sha, latestVerifyEnd.sha]);
  checks.candidate_sha_consistent = shas.size <= 1;
  if (!checks.candidate_sha_consistent) {
    return freeze(`candidate SHA mismatch across artifacts: ${[...shas].join(', ')}`, checks);
  }

  checks.candidate_sha_immutable_during_verification = latestVerifyStart.sha === latestVerifyEnd.sha;
  if (!checks.candidate_sha_immutable_during_verification) {
    return freeze('candidate SHA changed during verification', checks);
  }

  // ── Authoritative changed-file list: derive from git diff(base..candidate) ──────────────────
  // Trust boundary: never treat the self-reported engineer.changed_files as authoritative.
  // Compute the list from git using SHAs recorded by the checkpoints/receipts. Prefer the
  // verified candidate SHA captured by checkpoints over receipt fields when available.
  const pickCandidateSha = () => {
    if (latestVerifyEnd && latestVerifyEnd.sha) return latestVerifyEnd.sha;
    if (latestVerifyStart && latestVerifyStart.sha) return latestVerifyStart.sha;
    if (latestA1 && latestA1.sha) return latestA1.sha;
    return engineer.candidate_sha || verifier.candidate_sha || null;
  };
  const candidateSha = pickCandidateSha();
  const baseSha = engineer.base_sha || null;

  // ── base_sha honesty: it's still self-reported, and the whole point of deriving changed_files
  // from `git diff base..candidate` is worthless if `base_sha` itself can be picked to make that
  // diff appear artificially small or empty (e.g. base_sha === candidate_sha hides everything).
  // Two independent checks, neither trusting the receipt's prose:
  //   1. base_sha must be a genuine git ancestor of candidate_sha, and not equal to it — rules out
  //      the degenerate "same commit" case and any unrelated/future SHA.
  //   2. if a directive file for this phase_id exists, its OWN base_sha is the authoritative
  //      reference; a receipt's base_sha may legitimately differ (branch topology reasons, as
  //      actually happened on P2-01), but only with a non-empty base_sha_note disclosing why —
  //      an undisclosed silent deviation from the directive is exactly the kind of scope-widening
  //      this check exists to catch.
  if (baseSha && candidateSha) {
    if (baseSha === candidateSha) {
      return freeze('base_sha equals candidate_sha (no possible diff — cannot derive changed_files honestly)', checks);
    }
    let isAncestor = false;
    try {
      execFileSync('git', ['merge-base', '--is-ancestor', baseSha, candidateSha], { encoding: 'utf8' });
      isAncestor = true;
    } catch (e) {
      isAncestor = false;
    }
    checks.base_sha_is_ancestor = isAncestor;
    if (!isAncestor) {
      return freeze(`base_sha (${baseSha}) is not a git ancestor of candidate_sha (${candidateSha})`, checks);
    }

    // Consolidated onto loadDirectiveForPhase() — this used to be its own inline, separately-
    // buggy filename-prefix lookup; now shares the single exact-phase_id-match resolver.
    const directiveForBaseShaCheck = loadDirectiveForPhase(phaseId);
    if (directiveForBaseShaCheck) {
      const directive = directiveForBaseShaCheck;
      const directiveBaseSha = directive && directive.base_sha;
      if (directiveBaseSha && directiveBaseSha !== baseSha) {
        const note = (engineer.base_sha_note || '').trim();
        checks.base_sha_matches_directive = false;
        checks.base_sha_deviation_disclosed = note.length > 0;
        if (note.length === 0) {
          return freeze(`engineer receipt's base_sha (${baseSha}) differs from directive's base_sha (${directiveBaseSha}) with no base_sha_note explaining the deviation`, checks);
        }
      } else {
        checks.base_sha_matches_directive = true;
      }
    }
  }

  function normalizePath(p) {
    return p.replace(/\\/g, '/').replace(/^\.\//, '');
  }

  // ── Diff scope: candidate's own commit against its immediate parent, NOT base_sha..candidate.
  // `base_sha` is the DIRECTIVE's original starting point (often several already-reviewed commits
  // upstream on a shared branch — e.g. the whole .agent/ scaffold in this repo's actual history);
  // diffing all the way back to it conflates "everything on this branch since the directive
  // began" with "what THIS specific candidate changed," and floods forbidden-path/sync detection
  // with unrelated, already-committed files. `changed_files` has always meant the latter in every
  // real receipt this graph has produced — `<candidateSha>^..<candidateSha>` is what actually
  // matches that meaning. (Assumes one commit per candidate/rework-iteration, the convention
  // every real run here has followed; a multi-commit candidate between checkpoints is not
  // correctly captured by this and should be squashed before checkpointing.)
  let gitChanged = [];
  let gitChangedOk = true;
  try {
    if (!candidateSha) throw new Error('missing candidate SHA');
    const out = execFileSync('git', ['diff', '--name-only', `${candidateSha}^..${candidateSha}`], { encoding: 'utf8' });
    gitChanged = out
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map(normalizePath);
  } catch (e) {
    gitChangedOk = false;
  }

  checks.changed_files_git_derived = gitChanged;
  if (!gitChangedOk) {
    return freeze('could not derive changed files from git (candidate^..candidate)', {
      changed_files_git_derived_ok: false,
      candidate_sha_present: !!candidateSha,
    });
  }

  // If the engineer provided changed_files, require exact set equality after normalization.
  const engChanged = (engineer.changed_files || []).map(normalizePath);
  if (engChanged.length > 0) {
    const engSet = new Set(engChanged);
    const gitSet = new Set(gitChanged);
    const omits = gitChanged.filter((f) => !engSet.has(f));
    const extras = engChanged.filter((f) => !gitSet.has(f));
    if (omits.length > 0 || extras.length > 0) {
      const parts = [];
      if (omits.length > 0) parts.push(`receipt omits: ${omits.join(', ')}`);
      if (extras.length > 0) parts.push(`receipt reports extra: ${extras.join(', ')}`);
      const msg = `engineer receipt changed_files mismatch with git-derived list — ${parts.join(' ; ')}`;
      return freeze(msg, checks);
    }
  }

  // ── Forbidden file modification (using git-derived list only) ───────────────────────────────
  let forbiddenTouched = gitChanged.filter((f) => FORBIDDEN_PATH_PATTERNS.some((re) => re.test(f)));

  // Narrow carve-out (see HELIOS_SELF_INTEGRITY_FILES comment above): excuse a .helios-baseline
  // hit ONLY if independently recomputing its hash from the candidate's own committed selfFiles
  // matches exactly. A mismatch is NOT excused — it stays in forbiddenTouched and freezes, same as
  // any other forbidden path, but with a stronger, more specific reason attached below.
  let heliosBaselineCheck = null;
  if (forbiddenTouched.includes(HELIOS_BASELINE_PATH)) {
    heliosBaselineCheck = verifyHeliosBaselineRegeneration(candidateSha);
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

  // ── Required evidence present, and actually bound to this phase/run ────────────────────────
  const citedEvidence = [...(engineer.evidence || []), ...(verifier.evidence || [])];
  const missingEvidence = citedEvidence.filter((id) => !evidenceIndex.includes(id));
  checks.evidence_present = missingEvidence.length === 0 && citedEvidence.length > 0;
  if (!checks.evidence_present) {
    return freeze(`cited evidence missing from evidence/index.json: ${missingEvidence.join(', ') || '(no evidence cited)'}`, checks);
  }
  const mismatchedEvidence = verifyEvidenceBinding(runDir, phaseId, citedEvidence);
  checks.evidence_content_bound = mismatchedEvidence.length === 0;
  if (!checks.evidence_content_bound) {
    return freeze(`cited evidence not recorded for this phase/run: ${mismatchedEvidence.join('; ')}`, checks);
  }

  // ── Every required-gate check below (threat-model precondition, then the five optional
  // peer-reviewer verdicts) is evaluated BEFORE a2_pass/p0_regression/verifier_regressions_clean,
  // deliberately, for every one of them — not just threat-model. SECURITY: this used to be true
  // only for threat-model; the five verdict gates further down sat AFTER the a2_pass early-return,
  // so whenever the verifier already failed (or a P0/regression check fired), a required-but-
  // missing reliability/quality/test/compatibility/release-audit receipt was never checked at all,
  // and the persisted warden-receipt.json then falsely reported it as required:false — a receipt
  // reader had no way to tell "not required" from "required but never evaluated." Demonstrated via
  // a constructed run: require_reliability_review:true + verifier.status=FAIL produced BLOCK
  // without ever checking reliability-receipt.json's existence. One directive load now serves all
  // six checks (was loaded separately, redundantly, for threat-model and for the verdict gates).
  const directiveForGates = loadDirectiveForPhase(phaseId);

  // Threat Modeler (Agent 1b) — opt-in per directive (require_threat_model: true). Unlike
  // reliability/verifier receipts this one has no PASS/FAIL verdict to BLOCK on — it is a recon
  // precondition, not a judgment — so the only two outcomes are "present, COMPLETE, evidence
  // checks out" (fine) or FREEZE (missing, invalid, wrong candidate, missing evidence, or
  // explicitly INCOMPLETE — attacking off an admittedly incomplete map is exactly the discipline
  // this gate exists to prevent).
  const threatModelDirective = directiveForGates;
  const threatModelRequired = !!(threatModelDirective && threatModelDirective.require_threat_model);
  const threatModelPath = path.join(runDir, 'threat-model.json');
  const threatModelExists = fs.existsSync(threatModelPath);
  let threatModelInfo = { present: false, required: threatModelRequired };
  if (threatModelRequired && !threatModelExists) {
    return freeze('threat-model.json required by directive but missing', checks);
  }
  if (threatModelExists) {
    const tmValid = validateReceipt(path.join(CONTRACTS_DIR, 'threat-model.schema.json'), threatModelPath);
    if (!tmValid.valid) {
      return freeze('threat-model.json failed schema validation', checks, tmValid.errors.map((e) => `threat-model: ${e}`));
    }
    const threatModel = loadJson(threatModelPath);
    if (threatModel.candidate_sha !== candidateSha) {
      return freeze(`threat-model candidate_sha (${threatModel.candidate_sha}) does not match candidate_sha (${candidateSha})`, checks);
    }
    const tmEvidence = threatModel.evidence || [];
    const missingTmEvidence = tmEvidence.filter((id) => !evidenceIndex.includes(id));
    if (missingTmEvidence.length > 0) {
      return freeze(`threat-model cites evidence missing from evidence/index.json: ${missingTmEvidence.join(', ')}`, checks);
    }
    const mismatchedTmEvidence = verifyEvidenceBinding(runDir, phaseId, tmEvidence);
    if (mismatchedTmEvidence.length > 0) {
      return freeze(`threat-model cites evidence not recorded for this phase/run: ${mismatchedTmEvidence.join('; ')}`, checks);
    }
    if (threatModelRequired && threatModel.status !== 'COMPLETE') {
      return freeze(`threat-model.status is "${threatModel.status}" (not COMPLETE) but this directive requires a completed threat model before the pentester proceeds`, checks);
    }
    threatModelInfo = { present: true, required: threatModelRequired, status: threatModel.status, attack_classes_identified: (threatModel.likely_attack_classes || []).length };
  }
  checks.threat_model = threatModelInfo;

  // ── Optional peer-reviewer verdict receipts (Reliability, Code Quality, Test Engineer,
  // Compatibility, Release Audit) — evaluated here, before a2_pass/p0_regression/regressions
  // below, for the same reason threat-model is: opt-in per directive, backward compatible by
  // construction (a directive predating a given flag behaves exactly as before that receipt type
  // existed), and if present even without opting in, still validated and honored. All five share
  // evaluateOptionalVerdictReceipt() (see its comment for why this is one function instead of five
  // copy-pasted blocks).
  const directiveForVerdicts = directiveForGates;

  const reliabilityResult = evaluateOptionalVerdictReceipt({
    runDir,
    phaseId,
    candidateSha,
    evidenceIndex,
    filename: 'reliability-receipt.json',
    schemaName: 'reliability-receipt.schema.json',
    required: !!(directiveForVerdicts && directiveForVerdicts.require_reliability_review),
    roleLabel: 'reliability-reviewer',
  });
  if (reliabilityResult.outcome === 'freeze') {
    return freeze(reliabilityResult.reason, checks, reliabilityResult.extraReasons);
  }
  let reliabilityInfo = reliabilityResult.info;
  if (reliabilityResult.receipt) {
    reliabilityInfo = {
      ...reliabilityInfo,
      blocking_findings: (reliabilityResult.receipt.findings || []).filter((f) => f.severity === 'blocking').length,
      advisory_findings: (reliabilityResult.receipt.findings || []).filter((f) => f.severity === 'advisory').length,
    };
  }
  checks.reliability_receipt = reliabilityInfo;
  if (reliabilityResult.outcome === 'block') {
    return { status: 'BLOCK', reasons: [...reasons, reliabilityResult.reason], checks, freeze_reason: null, reliability: reliabilityInfo, threat_model: threatModelInfo };
  }

  const qualityResult = evaluateOptionalVerdictReceipt({
    runDir,
    phaseId,
    candidateSha,
    evidenceIndex,
    filename: 'quality-receipt.json',
    schemaName: 'quality-receipt.schema.json',
    required: !!(directiveForVerdicts && directiveForVerdicts.require_quality_review),
    roleLabel: 'quality-reviewer',
  });
  if (qualityResult.outcome === 'freeze') {
    return freeze(qualityResult.reason, checks, qualityResult.extraReasons);
  }
  let qualityInfo = qualityResult.info;
  if (qualityResult.receipt) {
    qualityInfo = {
      ...qualityInfo,
      blocking_findings: (qualityResult.receipt.findings || []).filter((f) => f.severity === 'blocking').length,
      advisory_findings: (qualityResult.receipt.findings || []).filter((f) => f.severity === 'advisory').length,
    };
  }
  checks.quality_receipt = qualityInfo;
  if (qualityResult.outcome === 'block') {
    return { status: 'BLOCK', reasons: [...reasons, qualityResult.reason], checks, freeze_reason: null, reliability: reliabilityInfo, threat_model: threatModelInfo, quality: qualityInfo };
  }

  const testReviewResult = evaluateOptionalVerdictReceipt({
    runDir,
    phaseId,
    candidateSha,
    evidenceIndex,
    filename: 'test-coverage-receipt.json',
    schemaName: 'test-coverage-receipt.schema.json',
    required: !!(directiveForVerdicts && directiveForVerdicts.require_test_review),
    roleLabel: 'test-engineer',
  });
  if (testReviewResult.outcome === 'freeze') {
    return freeze(testReviewResult.reason, checks, testReviewResult.extraReasons);
  }
  let testReviewInfo = testReviewResult.info;
  if (testReviewResult.receipt) {
    testReviewInfo = {
      ...testReviewInfo,
      blocking_findings: (testReviewResult.receipt.findings || []).filter((f) => f.severity === 'blocking').length,
      advisory_findings: (testReviewResult.receipt.findings || []).filter((f) => f.severity === 'advisory').length,
      false_positive_tests_found: (testReviewResult.receipt.false_positive_tests_found || []).length,
    };
  }
  checks.test_coverage_receipt = testReviewInfo;
  if (testReviewResult.outcome === 'block') {
    return { status: 'BLOCK', reasons: [...reasons, testReviewResult.reason], checks, freeze_reason: null, reliability: reliabilityInfo, threat_model: threatModelInfo, quality: qualityInfo, test_coverage: testReviewInfo };
  }

  const compatibilityResult = evaluateOptionalVerdictReceipt({
    runDir,
    phaseId,
    candidateSha,
    evidenceIndex,
    filename: 'compatibility-receipt.json',
    schemaName: 'compatibility-receipt.schema.json',
    required: !!(directiveForVerdicts && directiveForVerdicts.require_compatibility_review),
    roleLabel: 'compatibility-reviewer',
  });
  if (compatibilityResult.outcome === 'freeze') {
    return freeze(compatibilityResult.reason, checks, compatibilityResult.extraReasons);
  }
  let compatibilityInfo = compatibilityResult.info;
  if (compatibilityResult.receipt) {
    compatibilityInfo = {
      ...compatibilityInfo,
      blocking_findings: (compatibilityResult.receipt.findings || []).filter((f) => f.severity === 'blocking').length,
      advisory_findings: (compatibilityResult.receipt.findings || []).filter((f) => f.severity === 'advisory').length,
    };
  }
  checks.compatibility_receipt = compatibilityInfo;
  if (compatibilityResult.outcome === 'block') {
    return { status: 'BLOCK', reasons: [...reasons, compatibilityResult.reason], checks, freeze_reason: null, reliability: reliabilityInfo, threat_model: threatModelInfo, quality: qualityInfo, test_coverage: testReviewInfo, compatibility: compatibilityInfo };
  }

  // ── Release Auditor (Agent 2r) — same opt-in verdict gate as the others, PLUS a mechanical
  // deny-list check on packaged_files that runs whenever the receipt exists, independent of the
  // opt-in flag and independent of the receipt's own `status`. "What accidentally got packaged" is
  // meant to be a script decision (see release-auditor.md and PACKAGE_DENY_PATTERNS above), not a
  // trust call on this role's prose — a Release Auditor that reports PASS while packaged_files
  // still contains a forbidden path is exactly the failure mode this check exists to catch.
  const releaseAuditResult = evaluateOptionalVerdictReceipt({
    runDir,
    phaseId,
    candidateSha,
    evidenceIndex,
    filename: 'release-audit-receipt.json',
    schemaName: 'release-audit-receipt.schema.json',
    required: !!(directiveForVerdicts && directiveForVerdicts.require_release_audit),
    roleLabel: 'release-auditor',
  });
  if (releaseAuditResult.outcome === 'freeze') {
    return freeze(releaseAuditResult.reason, checks, releaseAuditResult.extraReasons);
  }
  let releaseAuditInfo = releaseAuditResult.info;
  if (releaseAuditResult.receipt) {
    const packagedFiles = (releaseAuditResult.receipt.packaged_files || []).map(normalizePath);
    const deniedPackagedFiles = packagedFiles.filter((f) => PACKAGE_DENY_PATTERNS.some((re) => re.test(f)));
    releaseAuditInfo = {
      ...releaseAuditInfo,
      blocking_findings: (releaseAuditResult.receipt.findings || []).filter((f) => f.severity === 'blocking').length,
      advisory_findings: (releaseAuditResult.receipt.findings || []).filter((f) => f.severity === 'advisory').length,
      packaged_files_count: packagedFiles.length,
      denied_packaged_files: deniedPackagedFiles,
    };
    checks.release_audit_receipt = releaseAuditInfo;
    if (deniedPackagedFiles.length > 0) {
      return freeze(`release-audit packaged_files contains forbidden path(s): ${deniedPackagedFiles.join(', ')}`, checks);
    }
  }
  checks.release_audit_receipt = releaseAuditInfo;
  if (releaseAuditResult.outcome === 'block') {
    return { status: 'BLOCK', reasons: [...reasons, releaseAuditResult.reason], checks, freeze_reason: null, reliability: reliabilityInfo, threat_model: threatModelInfo, quality: qualityInfo, test_coverage: testReviewInfo, compatibility: compatibilityInfo, release_audit: releaseAuditInfo };
  }

  // All optional-gate accumulator fields (threat_model/reliability/quality/test_coverage/
  // compatibility/release_audit) are fully and honestly computed by this point, regardless of
  // what the checks below find — the property the gate-ordering fix above exists to guarantee.
  const gateInfo = { threat_model: threatModelInfo, reliability: reliabilityInfo, quality: qualityInfo, test_coverage: testReviewInfo, compatibility: compatibilityInfo, release_audit: releaseAuditInfo };

  // ── Engineer's own status must actually gate the verdict, not just get noted ─────────────────
  // Previously pushed onto `reasons` but never checked — a receipt with status !== 'PASS' but
  // otherwise-clean everything-else still fell through to an overall PASS at the bottom of this
  // function, with an unused, unacted-on reason sitting in the output. Found while moving this
  // section; fixed alongside it since it's the same theme (a real signal must actually gate the
  // outcome, not just get silently recorded).
  if (engineer.status !== 'PASS') {
    return { status: 'BLOCK', reasons: [...reasons, 'engineer receipt status is not PASS'], checks, freeze_reason: null, ...gateInfo };
  }

  // ── A2 verdict is authoritative and cannot be overridden ────────────────────────────────────
  checks.a2_pass = verifier.status === 'PASS';
  if (!checks.a2_pass) {
    return { status: 'BLOCK', reasons: [...reasons, `${verifier.agent || 'verifier'} reported FAIL`], checks, freeze_reason: null, ...gateInfo };
  }

  // ── P0 regression: engineer's own recorded test runs must all be exit 0 ─────────────────────
  const failingTests = (engineer.tests_run || []).filter((t) => t.exit_code !== 0);
  checks.p0_regression = failingTests.length > 0;
  if (checks.p0_regression) {
    return { status: 'BLOCK', reasons: [...reasons, `engineer tests_run had nonzero exit codes: ${failingTests.map((t) => t.command).join(', ')}`], checks, freeze_reason: null, ...gateInfo };
  }

  // ── Regressions flagged explicitly by the verifier ──────────────────────────────────────────
  const verifierRegressions = (verifier.regressions || []).filter((r) => r && r.status && r.status !== 'OK' && r.status !== 'PASS');
  checks.verifier_regressions_clean = verifierRegressions.length === 0;
  if (!checks.verifier_regressions_clean) {
    return { status: 'BLOCK', reasons: [...reasons, `verifier reported regressions: ${JSON.stringify(verifierRegressions)}`], checks, freeze_reason: null, ...gateInfo };
  }

  // ── Sync gate (deterministic, not model-decided) ────────────────────────────────────────────
  const syncFiles = gitChanged.filter((f) => SYNC_TRIGGER_PATTERNS.some((re) => re.test(f)));
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
    ...gateInfo,
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
    reliability: result.reliability || { present: false, required: false },
    threat_model: result.threat_model || { present: false, required: false },
    quality: result.quality || { present: false, required: false },
    test_coverage: result.test_coverage || { present: false, required: false },
    compatibility: result.compatibility || { present: false, required: false },
    release_audit: result.release_audit || { present: false, required: false },
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
  // SECURITY: defense-in-depth backstop. Every crash site found in practice (malformed JSON in
  // any of six now-hardened call sites, and any other unexpected input shape) is now handled with
  // a specific reason closer to its source, but this catch-all guarantees the property holds for
  // ANY cause, known or not: evaluate() must never crash the process with no warden-receipt.json
  // written and no recorded decision. Fail closed, always with a receipt, always FREEZE (exit 2),
  // never colliding with BLOCK's exit code the way a bare uncaught exception (exit 1) used to.
  let result;
  try {
    result = evaluate(runDir, phaseId);
  } catch (e) {
    result = {
      status: 'FREEZE',
      reasons: [`release-warden.js crashed evaluating this run: ${e.message}`],
      checks: {},
      freeze_reason: `unhandled exception during evaluation: ${e.message}`,
      sync_required: false,
      sync_reason: 'not evaluated — run frozen',
    };
  }
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
