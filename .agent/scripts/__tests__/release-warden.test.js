// .agent/scripts/__tests__/release-warden.test.js
// Plain node+assert test (repo convention, no jest/mocha) for release-warden.js's security
// properties. Each check targets one of the fixes made in fix/graph-trust-hardening, reproducing
// the exact defect that was found before asserting it's now closed. Calls evaluate() directly
// (exported by release-warden.js) rather than spawning a child process per case, for speed --
// evaluate() still does real git operations against this checkout, so the candidate/base SHAs
// used below are real, reachable commits in this repo's own history, not synthetic ones.
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
process.chdir(REPO_ROOT); // evaluate()'s git calls run relative to process.cwd()

const { evaluate } = require('../release-warden.js');
const RELEASE_WARDEN_CLI = path.join(__dirname, '..', 'release-warden.js');

// Some defects only manifest through the real CLI entry point (main() -> writeWardenReceipt()),
// not through evaluate() called directly in-process -- found by independent adversarial
// re-verification when a defect in writeWardenReceipt() itself (which re-reads receipts a second
// time, outside evaluate()'s own protection) went undetected by every evaluate()-only test above.
function runCli(runDir, phaseId) {
  return spawnSync(process.execPath, [RELEASE_WARDEN_CLI, runDir, phaseId], { encoding: 'utf8', timeout: 30000 });
}

// A real commit and its real immediate parent, already used throughout this repo's own real runs
// today -- P2-01's final candidate. Chosen specifically because candidate^..candidate's diff is
// packages/fw-agent-only (no .agent/ forbidden-path hit), so tests can reach the checks under
// test without an unrelated earlier gate firing first.
const CANDIDATE_SHA = '94388bdeabc93f1ccf6227828ffac13d592089b1';
const BASE_SHA = '079322774e92a7d1d5aaf12128712afa130aa63b';

let passed = 0;
let failed = 0;
function check(name, fn) {
  try {
    fn();
    console.log('  ✓ ' + name);
    passed++;
  } catch (e) {
    console.error('  ✗ ' + name + '\n    ' + e.message);
    failed++;
  }
}

function mkRunDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-warden-test-'));
  return dir;
}

function writeReceipt(runDir, name, obj) {
  fs.writeFileSync(path.join(runDir, name), JSON.stringify(obj, null, 2));
}

function baseEngineerReceipt(overrides) {
  return Object.assign(
    {
      phase_id: 'RWTEST',
      agent: 'boundary-engineer',
      status: 'PASS',
      base_sha: BASE_SHA,
      candidate_sha: CANDIDATE_SHA,
      changed_files: [],
      tests_added: [],
      tests_run: [{ command: 'npm test', exit_code: 0 }],
      security_invariant: 'test fixture',
      known_limitations: [],
      evidence: [],
      forbidden_files_touched: [],
      timestamp: new Date(0).toISOString(),
    },
    overrides,
  );
}

function baseVerifierReceipt(overrides) {
  return Object.assign(
    {
      phase_id: 'RWTEST',
      agent: 'red-team-verifier',
      status: 'PASS',
      candidate_sha: CANDIDATE_SHA,
      clean_checkout: true,
      commands: [],
      controls: [],
      attacks: [],
      regressions: [],
      matrix_result: {},
      escape_probes: [],
      evidence: [],
      timestamp: new Date(0).toISOString(),
    },
    overrides,
  );
}

// Writes a real evidence bundle (matching collect-evidence.js's own format exactly, since
// evaluate()'s evidence-binding check reads these files directly) without spawning a real command
// -- these tests assert on release-warden.js's logic, not on the commands a real role would run.
function writeEvidence(runDir, id, { phaseId = 'RWTEST', runId, exitCode = 0 } = {}) {
  const dir = path.join(runDir, 'evidence');
  fs.mkdirSync(dir, { recursive: true });
  const record = {
    id,
    run_id: runId || path.basename(runDir),
    phase_id: phaseId,
    type: 'command',
    command: 'echo test',
    exit_code: exitCode,
    started_at: new Date(0).toISOString(),
    ended_at: new Date(0).toISOString(),
    cwd: REPO_ROOT,
    git_sha: CANDIDATE_SHA,
    stdout_sha256: crypto.createHash('sha256').update('').digest('hex'),
    stderr_sha256: crypto.createHash('sha256').update('').digest('hex'),
    stdout_excerpt: '',
    stderr_excerpt: '',
    timed_out: false,
  };
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(record, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, `${id}.stdout.log`), '');
  fs.writeFileSync(path.join(dir, `${id}.stderr.log`), '');
  const indexPath = path.join(dir, 'index.json');
  const index = fs.existsSync(indexPath) ? JSON.parse(fs.readFileSync(indexPath, 'utf8')) : [];
  index.push(id);
  fs.writeFileSync(indexPath, JSON.stringify(index, null, 2) + '\n');
}

function writeCheckpoint(runDir, label, sha) {
  const cpPath = path.join(runDir, 'checkpoints.json');
  const cps = fs.existsSync(cpPath) ? JSON.parse(fs.readFileSync(cpPath, 'utf8')) : [];
  cps.push({ label, timestamp: new Date(0).toISOString(), sha, branch: 'test', dirty: false, status: '' });
  fs.writeFileSync(cpPath, JSON.stringify(cps, null, 2) + '\n');
}

// Builds a fully valid, minimal PASS-shape run directory, then lets the caller override/omit
// specific pieces to trigger exactly one failure mode under test.
function makeValidRun({ phaseId = 'RWTEST', withCheckpoints = true } = {}) {
  const runDir = mkRunDir();
  if (withCheckpoints) {
    for (const label of ['a1-candidate', 'a2-verify-start', 'a2-verify-end']) {
      writeCheckpoint(runDir, label, CANDIDATE_SHA);
    }
  }
  writeEvidence(runDir, 'ev-1', { phaseId, runId: path.basename(runDir) });
  writeReceipt(runDir, 'engineer-receipt.json', baseEngineerReceipt({ phase_id: phaseId, evidence: ['ev-1'] }));
  writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ phase_id: phaseId, evidence: ['ev-1'] }));
  return runDir;
}

// ── Sanity: a fully valid run reaches PASS ─────────────────────────────────────────────────────
check('positive control: a fully valid run reaches PASS', () => {
  const runDir = makeValidRun();
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'PASS', `expected PASS, got ${result.status}: ${result.freeze_reason}`);
});

// ── Fix 1: checkpoint chain mandatory ──────────────────────────────────────────────────────────
check('checkpoints.json entirely absent FREEZEs, not vacuously passes', () => {
  const runDir = makeValidRun({ withCheckpoints: false });
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE');
  assert.ok(/checkpoints\.json missing required checkpoint/.test(result.freeze_reason), result.freeze_reason);
});

check('the original full-bypass construction (forged receipts, no checkpoints) FREEZEs', () => {
  // Reproduces the exact exploit: two receipts that only agree with each other, zero real
  // verification, no checkpoints.json. Before the fix this reached PASS.
  const runDir = mkRunDir();
  writeEvidence(runDir, 'cosmetic', { runId: path.basename(runDir) });
  writeReceipt(runDir, 'engineer-receipt.json', baseEngineerReceipt({ evidence: ['cosmetic'], security_invariant: 'FABRICATED' }));
  writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ evidence: ['cosmetic'] }));
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE', `bypass reached ${result.status} instead of FREEZE`);
});

check('one checkpoint present but not all three still FREEZEs', () => {
  const runDir = makeValidRun({ withCheckpoints: false });
  writeCheckpoint(runDir, 'a1-candidate', CANDIDATE_SHA);
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE');
  assert.ok(result.freeze_reason.includes('a2-verify-start'), result.freeze_reason);
  assert.ok(result.freeze_reason.includes('a2-verify-end'), result.freeze_reason);
});

check('checkpoint SHA mismatch across artifacts still FREEZEs (unchanged behavior)', () => {
  const runDir = makeValidRun();
  writeCheckpoint(runDir, 'a1-candidate', '0000000000000000000000000000000000000f');
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE');
  assert.ok(/candidate SHA mismatch/.test(result.freeze_reason), result.freeze_reason);
});

// ── Fix 2a: directive resolution exact match ───────────────────────────────────────────────────
check('a directive whose filename is a prefix-collision superset does not match', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const collisionFile = path.join(directivesDir, 'RWTEST-COLLISION-should-not-match.json');
  fs.writeFileSync(collisionFile, JSON.stringify({ phase_id: 'RWTEST-COLLISION', require_reliability_review: true }));
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST' });
    const result = evaluate(runDir, 'RWTEST'); // must NOT pick up RWTEST-COLLISION's require_reliability_review
    assert.strictEqual(result.status, 'PASS', `phase_id prefix collision leaked requirements onto an unrelated phase: ${result.status} / ${result.freeze_reason}`);
  } finally {
    fs.unlinkSync(collisionFile);
  }
});

check('a directive is matched by its own phase_id field, not by filename', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const oddNameFile = path.join(directivesDir, 'zzz-unrelated-filename-RWTEST-REAL.json');
  fs.writeFileSync(oddNameFile, JSON.stringify({ phase_id: 'RWTEST-REAL', require_reliability_review: true }));
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-REAL' });
    const result = evaluate(runDir, 'RWTEST-REAL'); // reliability-receipt.json is required and missing
    assert.strictEqual(result.status, 'FREEZE');
    assert.ok(/reliability-receipt\.json required by directive but missing/.test(result.freeze_reason), result.freeze_reason);
  } finally {
    fs.unlinkSync(oddNameFile);
  }
});

// ── Fix 2b: malformed JSON never crashes ───────────────────────────────────────────────────────
check('malformed JSON in a mandatory receipt FREEZEs instead of throwing', () => {
  const runDir = makeValidRun();
  fs.writeFileSync(path.join(runDir, 'engineer-receipt.json'), '{not valid json');
  assert.doesNotThrow(() => {
    const result = evaluate(runDir, 'RWTEST');
    assert.strictEqual(result.status, 'FREEZE');
    assert.ok(/engineer-receipt\.json is not valid JSON/.test(result.freeze_reason), result.freeze_reason);
  });
});

check('malformed JSON in an optional receipt FREEZEs instead of crashing the whole gate', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-MALFORMED-directive.json');
  fs.writeFileSync(directiveFile, JSON.stringify({ phase_id: 'RWTEST-MALFORMED', require_quality_review: true }));
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-MALFORMED' });
    fs.writeFileSync(path.join(runDir, 'quality-receipt.json'), '{bad');
    assert.doesNotThrow(() => {
      const result = evaluate(runDir, 'RWTEST-MALFORMED');
      assert.strictEqual(result.status, 'FREEZE');
      assert.ok(/quality-receipt\.json failed schema validation/.test(result.freeze_reason), result.freeze_reason);
    });
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

// ── Fix 3: required gates evaluated before verdict ─────────────────────────────────────────────
check('a required-but-missing reliability review FREEZEs even when the verifier already FAILed', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-GATEORDER-directive.json');
  fs.writeFileSync(directiveFile, JSON.stringify({ phase_id: 'RWTEST-GATEORDER', require_reliability_review: true }));
  try {
    const runDir = mkRunDir();
    for (const label of ['a1-candidate', 'a2-verify-start', 'a2-verify-end']) writeCheckpoint(runDir, label, CANDIDATE_SHA);
    writeEvidence(runDir, 'ev-1', { phaseId: 'RWTEST-GATEORDER', runId: path.basename(runDir) });
    writeReceipt(runDir, 'engineer-receipt.json', baseEngineerReceipt({ phase_id: 'RWTEST-GATEORDER', evidence: ['ev-1'] }));
    writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ phase_id: 'RWTEST-GATEORDER', status: 'FAIL', evidence: ['ev-1'] }));
    // no reliability-receipt.json written -- required by the directive, and must be checked
    // regardless of the verifier's own FAIL, not silently skipped by an early BLOCK return.
    const result = evaluate(runDir, 'RWTEST-GATEORDER');
    assert.strictEqual(result.status, 'FREEZE', `expected FREEZE on the missing required gate, got ${result.status}: ${JSON.stringify(result.reasons)}`);
    assert.ok(/reliability-receipt\.json required by directive but missing/.test(result.freeze_reason), result.freeze_reason);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

check('engineer receipt status !== PASS actually BLOCKs instead of being silently ignored', () => {
  const runDir = makeValidRun();
  writeReceipt(runDir, 'engineer-receipt.json', baseEngineerReceipt({ status: 'FAIL', evidence: ['ev-1'] }));
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'BLOCK', `expected BLOCK, got ${result.status}`);
  assert.ok(result.reasons.includes('engineer receipt status is not PASS'), JSON.stringify(result.reasons));
});

// ── Fix 4: evidence must be bound to the run/phase citing it ───────────────────────────────────
check('evidence recorded for a different run_id is rejected even though its ID is in the index', () => {
  const runDir = makeValidRun();
  writeEvidence(runDir, 'foreign-ev', { runId: 'some-other-run-entirely', phaseId: 'RWTEST' });
  writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ evidence: ['ev-1', 'foreign-ev'] }));
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE');
  assert.ok(/not recorded for this phase\/run/.test(result.freeze_reason), result.freeze_reason);
});

check('evidence recorded for a different phase_id is rejected even under the same run_id', () => {
  const runDir = makeValidRun();
  writeEvidence(runDir, 'wrong-phase-ev', { runId: path.basename(runDir), phaseId: 'SOME-OTHER-PHASE' });
  writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ evidence: ['ev-1', 'wrong-phase-ev'] }));
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE');
  assert.ok(/not recorded for this phase\/run/.test(result.freeze_reason), result.freeze_reason);
});

// ── Package deny patterns (pre-existing mechanical check, previously untested) ─────────────────
check('a release-audit receipt whose packaged_files contains a denied path FREEZEs regardless of its own status', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-PKGDENY-directive.json');
  fs.writeFileSync(directiveFile, JSON.stringify({ phase_id: 'RWTEST-PKGDENY', require_release_audit: true }));
  try {
    const runDir = mkRunDir();
    for (const label of ['a1-candidate', 'a2-verify-start', 'a2-verify-end']) writeCheckpoint(runDir, label, CANDIDATE_SHA);
    writeEvidence(runDir, 'ev-1', { phaseId: 'RWTEST-PKGDENY', runId: path.basename(runDir) });
    writeEvidence(runDir, 'ev-pack', { phaseId: 'RWTEST-PKGDENY', runId: path.basename(runDir) });
    writeReceipt(runDir, 'engineer-receipt.json', baseEngineerReceipt({ phase_id: 'RWTEST-PKGDENY', evidence: ['ev-1'] }));
    writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ phase_id: 'RWTEST-PKGDENY', evidence: ['ev-1'] }));
    writeReceipt(runDir, 'release-audit-receipt.json', {
      phase_id: 'RWTEST-PKGDENY',
      agent: 'release-auditor',
      status: 'PASS', // deliberately claims PASS -- the mechanical scan must not trust this
      candidate_sha: CANDIDATE_SHA,
      clean_checkout: true,
      package_name: 'test-pkg',
      npm_pack_dry_run_evidence_id: 'ev-pack',
      packaged_files: ['index.js', 'test/should-not-ship.spec.js'],
      checks: [],
      findings: [],
      evidence: ['ev-pack'],
      timestamp: new Date(0).toISOString(),
    });
    const result = evaluate(runDir, 'RWTEST-PKGDENY');
    assert.strictEqual(result.status, 'FREEZE', `expected FREEZE, got ${result.status}`);
    assert.ok(/packaged_files contains forbidden path/.test(result.freeze_reason), result.freeze_reason);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

// ── Round 2: fixes made in response to independent adversarial re-verification ──────────────────
// (attack-graph-again workflow, run against commit 52c63da). These specifically exercise the real
// CLI where the first round's tests only exercised evaluate() in-process, since that's exactly how
// the writeWardenReceipt() crash escaped the first round's coverage.

check('malformed engineer-receipt.json crashes neither evaluate() NOR the real CLI (writeWardenReceipt regression)', () => {
  const runDir = makeValidRun();
  fs.writeFileSync(path.join(runDir, 'engineer-receipt.json'), '{not valid json, truncated');
  const res = runCli(runDir, 'RWTEST');
  assert.strictEqual(res.status, 2, `expected exit 2 (FREEZE), got ${res.status} (signal ${res.signal}). stderr:\n${res.stderr}`);
  assert.strictEqual(res.stderr, '', `expected no uncaught-exception stderr, got:\n${res.stderr}`);
  assert.ok(fs.existsSync(path.join(runDir, 'warden-receipt.json')), 'warden-receipt.json was not written');
  const receipt = JSON.parse(fs.readFileSync(path.join(runDir, 'warden-receipt.json'), 'utf8'));
  assert.strictEqual(receipt.status, 'FREEZE');
});

check('malformed verifier-receipt.json crashes neither evaluate() NOR the real CLI (writeWardenReceipt regression)', () => {
  const runDir = makeValidRun();
  fs.writeFileSync(path.join(runDir, 'verifier-receipt.json'), '{not valid json, truncated');
  const res = runCli(runDir, 'RWTEST');
  assert.strictEqual(res.status, 2, `expected exit 2 (FREEZE), got ${res.status}. stderr:\n${res.stderr}`);
  assert.strictEqual(res.stderr, '', `expected no uncaught-exception stderr, got:\n${res.stderr}`);
  assert.ok(fs.existsSync(path.join(runDir, 'warden-receipt.json')), 'warden-receipt.json was not written');
});

check('a required-but-missing reliability review FREEZEs with an HONEST required:true in the persisted receipt', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-HONESTFREEZE-directive.json');
  fs.writeFileSync(directiveFile, JSON.stringify({ phase_id: 'RWTEST-HONESTFREEZE', require_reliability_review: true }));
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-HONESTFREEZE' });
    const result = evaluate(runDir, 'RWTEST-HONESTFREEZE');
    assert.strictEqual(result.status, 'FREEZE');
    // Before the fix, writeWardenReceipt()'s documented default {present:false,required:false}
    // silently overwrote this -- the freeze_reason said "required by directive" while the
    // structured field lied and said required:false.
    assert.strictEqual(result.reliability && result.reliability.required, true, `result.reliability.required lied: ${JSON.stringify(result.reliability)}`);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

check('docs-receipt citing evidence from a different run is rejected, not silently accepted', () => {
  const runDir = makeValidRun();
  writeEvidence(runDir, 'docs-foreign-ev', { runId: 'some-other-run-entirely', phaseId: 'RWTEST' });
  writeReceipt(runDir, 'docs-receipt.json', {
    phase_id: 'RWTEST',
    agent: 'docs-scribe',
    status: 'DRAFTED',
    candidate_sha: CANDIDATE_SHA,
    warden_status_at_draft_time: 'PASS',
    changed_files: ['README.md'],
    changelog_entry: 'test',
    source_receipts: { engineer_security_invariant: 'x', engineer_known_limitations: 'x', warden_sync_required: false },
    evidence: ['docs-foreign-ev'],
    timestamp: new Date(0).toISOString(),
  });
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE', `expected FREEZE, got ${result.status}`);
  assert.ok(/docs-receipt cites evidence/.test(result.freeze_reason), result.freeze_reason);
});

check('a malformed directive that plausibly belongs to the active phase FREEZEs instead of silently disabling its requirements', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-CORRUPT-directive.json');
  // Deliberately corrupted but still contains its own phase_id as a literal string, the way a
  // truncated-mid-write file realistically would.
  fs.writeFileSync(directiveFile, '{"phase_id": "RWTEST-CORRUPT", "require_reliability_revi');
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-CORRUPT' });
    // evaluate() itself may throw here (that's fine, main()'s catch-all handles it) -- what
    // matters is the real CLI never silently proceeds to PASS with the corrupted directive's
    // requirements simply vanishing.
    const res = runCli(runDir, 'RWTEST-CORRUPT');
    assert.strictEqual(res.status, 2, `expected exit 2 (FREEZE) on a corrupted directive for the active phase, got ${res.status}. stdout:\n${res.stdout}`);
    const receipt = JSON.parse(fs.readFileSync(path.join(runDir, 'warden-receipt.json'), 'utf8'));
    assert.strictEqual(receipt.status, 'FREEZE');
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

check('a corrupted directive for an UNRELATED phase does not freeze this phase (no over-correction)', () => {
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-UNRELATED-CORRUPT-directive.json');
  fs.writeFileSync(directiveFile, '{"phase_id": "SOME-COMPLETELY-DIFFERENT-PHASE", "require_rel');
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST' });
    const result = evaluate(runDir, 'RWTEST');
    assert.strictEqual(result.status, 'PASS', `an unrelated phase's corrupted directive should not affect this phase, got ${result.status}: ${result.freeze_reason}`);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

// ── Round 3: gaps found in round 2's own directive fail-closed heuristic ────────────────────────
// (a further independent adversarial pass against commit bc756d5, after the round-2 commit).

check('truncation MID-VALUE of phase_id itself (not just after it) still FREEZEs, not silently disables', () => {
  // The round-2 heuristic only matched a fully-intact phaseId substring anywhere in the file --
  // truncation partway through writing the value itself (the realistic crash point) evaded it.
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-MIDVALUE-directive.json');
  // "RWTEST-MIDVALUE-TARGET" truncated to "RWTEST-MIDV" -- a strict prefix, mid-value.
  fs.writeFileSync(directiveFile, '{"phase_id":"RWTEST-MIDV');
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-MIDVALUE-TARGET' });
    const res = runCli(runDir, 'RWTEST-MIDVALUE-TARGET');
    assert.strictEqual(res.status, 2, `expected exit 2 (FREEZE), got ${res.status}. stdout:\n${res.stdout}`);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

check('a directive whose UNRELATED content happens to mention another phase_id does not spuriously freeze that phase', () => {
  // The round-2 heuristic searched the WHOLE file body for phaseId -- a directive for a genuinely
  // different phase whose "notes"/cross-reference text happened to mention this phaseId elsewhere
  // spuriously froze this healthy, unrelated phase (a DoS-direction defect, not a bypass).
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-MENTIONS-directive.json');
  fs.writeFileSync(directiveFile, '{"phase_id":"SOME-OTHER-PHASE","notes":"see also RWTEST-MENTIONED-ELSEWHERE"}');
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-MENTIONED-ELSEWHERE' });
    const result = evaluate(runDir, 'RWTEST-MENTIONED-ELSEWHERE');
    assert.strictEqual(result.status, 'PASS', `an unrelated directive merely mentioning this phaseId should not freeze it, got ${result.status}: ${result.freeze_reason}`);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

// ── Partial checkpoint-forgery mitigation: verifier evidence must be genuinely bound to
// candidate_sha for at least one cited entry (disclosed as a bar-raising mitigation, not a full
// fix -- see the check's own comment in release-warden.js for the honest limit). ─────────────────

check('verifier evidence whose recorded git_sha never matches candidate_sha FREEZEs (naive forgery)', () => {
  const runDir = makeValidRun();
  // Overwrite ev-1's git_sha to something that is NOT the real candidate_sha -- simulating
  // evidence collected without ever actually being at the claimed candidate commit.
  const evPath = path.join(runDir, 'evidence', 'ev-1.json');
  const ev = JSON.parse(fs.readFileSync(evPath, 'utf8'));
  ev.git_sha = '0000000000000000000000000000000000000f';
  fs.writeFileSync(evPath, JSON.stringify(ev, null, 2));
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE', `expected FREEZE, got ${result.status}`);
  assert.ok(/no verifier-cited evidence was genuinely captured at candidate_sha/.test(result.freeze_reason), result.freeze_reason);
});

check('at least one genuinely-bound verifier evidence entry is sufficient, even alongside a mismatched one', () => {
  // Mirrors a real, legitimate pattern found in this repo's own history: a verifier's evidence
  // legitimately includes some main-tree-collected commands (e.g. confirming a file was read)
  // alongside worktree-collected ones -- only ONE genuinely-bound entry should be required, not
  // unanimity, or this would false-positive on real, honest verifier work.
  const runDir = makeValidRun();
  writeEvidence(runDir, 'ev-2', { runId: path.basename(runDir) }); // genuinely bound (default git_sha = CANDIDATE_SHA)
  const evPath = path.join(runDir, 'evidence', 'ev-1.json'); // ev-1 deliberately mismatched
  const ev = JSON.parse(fs.readFileSync(evPath, 'utf8'));
  ev.git_sha = '0000000000000000000000000000000000000f';
  fs.writeFileSync(evPath, JSON.stringify(ev, null, 2));
  writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ evidence: ['ev-1', 'ev-2'] }));
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'PASS', `one genuinely-bound entry should be sufficient, got ${result.status}: ${result.freeze_reason}`);
});

// ── Round 4: gaps found in round 3's own directive fail-closed heuristic (its SECOND rewrite) ────
// (a third independent adversarial pass against commit 06f2a1c, after the round-3 commit).

check('a corrupted directive for a DIFFERENT phase whose real ID is a string-prefix relation to the active phase does not spuriously match, in either direction', () => {
  // Round 3's bidirectional prefix check (`rawFragment.startsWith(phaseId) || phaseId.startsWith(rawFragment)`)
  // let a TERMINATED (complete, well-formed) value for a genuinely different phase match purely
  // because one string happened to be a prefix of the other -- e.g. real phases "RWTEST-PFX" and
  // "RWTEST-PFX-EXTRA" both legitimately exist; a corruption in EITHER one's own directive must
  // never be attributed to the other.
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-PFX-EXTRA-directive.json');
  // phase_id value is COMPLETE ("RWTEST-PFX-EXTRA", properly quote-terminated) -- only the
  // trailing fields are corrupted, so this is unambiguously that phase's own real, intact ID.
  fs.writeFileSync(directiveFile, '{"phase_id":"RWTEST-PFX-EXTRA","require_reliability_revi');
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-PFX' });
    const result = evaluate(runDir, 'RWTEST-PFX');
    assert.strictEqual(result.status, 'PASS', `a different, unrelated phase's complete directive should never match via prefix relation, got ${result.status}: ${result.freeze_reason}`);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

check('a duplicate phase_id key does not let a stale earlier occurrence mask the real, later one', () => {
  // Round 3's non-global regex only ever inspected the FIRST "phase_id" occurrence. Real
  // JSON.parse (had the file been well-formed) always resolves duplicate keys to the LAST one --
  // a stale key left behind by a botched copy/edit, or a crash mid-rewrite, must not hide the
  // genuine, later value from this fallback heuristic either.
  const directivesDir = path.join(REPO_ROOT, '.agent', 'directives');
  const directiveFile = path.join(directivesDir, 'RWTEST-DUPKEY-directive.json');
  fs.writeFileSync(directiveFile, '{"phase_id":"RWTEST-STALE","phase_id":"RWTEST-DUPKEY","require_reliability_review":true,,, broken json here!!!');
  try {
    const runDir = makeValidRun({ phaseId: 'RWTEST-DUPKEY' });
    const res = runCli(runDir, 'RWTEST-DUPKEY');
    assert.strictEqual(res.status, 2, `expected exit 2 (FREEZE) -- the real, later phase_id key must not be masked by the stale first one, got ${res.status}. stdout:\n${res.stdout}`);
  } finally {
    fs.unlinkSync(directiveFile);
  }
});

check('an empty verifier.evidence array does not vacuously satisfy the candidate-sha-binding check', () => {
  // Independent adversarial re-verification found the first version of this mitigation treated
  // verifier.evidence.length === 0 as an automatic pass -- an attacker could cite ALL evidence via
  // engineer.evidence (which the general evidence_present gate already accepts on its own) and
  // leave verifier.evidence empty, defeating the mitigation with ZERO real git access to the
  // candidate SHA at all -- strictly worse than the mitigation's own disclosed limit.
  const runDir = makeValidRun();
  writeReceipt(runDir, 'verifier-receipt.json', baseVerifierReceipt({ evidence: [] }));
  // engineer still cites real, bound evidence -- the general evidence_present gate is satisfied,
  // so this must fail specifically at the new verifier-evidence-binding check, not earlier.
  const result = evaluate(runDir, 'RWTEST');
  assert.strictEqual(result.status, 'FREEZE', `expected FREEZE, got ${result.status}`);
  assert.ok(/cites no evidence at all/.test(result.freeze_reason), result.freeze_reason);
});

console.log(`\n${passed} passed, ${failed} failed.`);
if (failed > 0) process.exit(1);
