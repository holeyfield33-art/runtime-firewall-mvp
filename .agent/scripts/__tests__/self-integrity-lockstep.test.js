// .agent/scripts/__tests__/self-integrity-lockstep.test.js
// Plain node+assert test (repo convention, no jest/mocha).
//
// F-01: the 10-file self-integrity list (index.js's own computeSelfHash(), the source of truth
// for the shipped .helios-baseline) is duplicated in four places that must be byte-identical in
// content AND order, or the release-warden's baseline-regeneration carve-out recomputes the
// wrong hash and either wrongly FREEZEs a legitimate baseline regen or wrongly excuses a bad one:
//   1. packages/fw-agent/index.js            (verifySelfIntegrity -> selfFiles)   -- runtime truth
//   2. scripts/generate-baseline.js           (SELF_FILES)                        -- what writes the baseline
//   3. .github/workflows/ci.yml               (inline node -e self-integrity check) -- what CI checks
//   4. .agent/scripts/release-warden.js       (HELIOS_SELF_INTEGRITY_FILES)        -- what the gate checks
//
// This test parses all four as text (regex extraction, not require()) specifically so it never
// executes index.js, which has top-level side effects (self-integrity check + process.exit paths)
// unsafe to trigger from a test runner.
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const AGENT_DIR = path.join(REPO_ROOT, 'packages', 'fw-agent');

let passed = 0;
let failed = 0;
function check(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok - ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`    ${e.message}`);
  }
}

// Pulls the ordered list of quoted string literals inside path.join(BASE_IDENT, 'a', 'b', ...)
// calls found within `blockText`, joined with '/' per call -- i.e. normalizes each call to the
// repo-relative-to-AGENT_DIR form ('src/detector.js', 'index.js', 'sync-worker.js', ...).
function extractPathJoinCalls(blockText) {
  const calls = [...blockText.matchAll(/path\.join\([A-Za-z_]+\s*((?:,\s*'[^']*')+)\)/g)];
  return calls.map((m) => [...m[1].matchAll(/'([^']*)'/g)].map((p) => p[1]).join('/'));
}

// Pulls the ordered list of quoted string literals inside a `[ ... ]` array literal, given the
// text immediately following a marker like "SELF_FILES = [" or "files = [".
function extractQuotedArray(fullText, startMarker) {
  const startIdx = fullText.indexOf(startMarker);
  if (startIdx === -1) throw new Error(`could not find marker "${startMarker}"`);
  const openBracket = fullText.indexOf('[', startIdx);
  const closeBracket = fullText.indexOf(']', openBracket);
  const block = fullText.slice(openBracket, closeBracket);
  return [...block.matchAll(/'([^']*)'/g)].map((m) => m[1]);
}

function readRepoFile(relPath) {
  return fs.readFileSync(path.join(REPO_ROOT, relPath), 'utf8');
}

// --- Copy 1: packages/fw-agent/index.js -------------------------------------------------------
const indexJsText = readRepoFile('packages/fw-agent/index.js');
const selfFilesBlockStart = indexJsText.indexOf('const selfFiles = [');
const selfFilesBlockEnd = indexJsText.indexOf('];', selfFilesBlockStart);
const indexJsList = extractPathJoinCalls(indexJsText.slice(selfFilesBlockStart, selfFilesBlockEnd));

// --- Copy 2: scripts/generate-baseline.js ------------------------------------------------------
const generateBaselineText = readRepoFile('scripts/generate-baseline.js');
const selfFilesBlockStart2 = generateBaselineText.indexOf('const SELF_FILES = [');
const selfFilesBlockEnd2 = generateBaselineText.indexOf('];', selfFilesBlockStart2);
const generateBaselineList = extractPathJoinCalls(
  generateBaselineText.slice(selfFilesBlockStart2, selfFilesBlockEnd2)
);

// --- Copy 3: .github/workflows/ci.yml (inline node -e block) -----------------------------------
const ciYmlText = readRepoFile('.github/workflows/ci.yml');
const ciYmlList = extractQuotedArray(ciYmlText, 'const files = [');

// --- Copy 4: .agent/scripts/release-warden.js ---------------------------------------------------
const { HELIOS_SELF_INTEGRITY_FILES } = require('../release-warden.js');
// release-warden.js's list is already normalized to `packages/fw-agent/<rel>` form (it maps
// each entry with `.map((f) => \`packages/fw-agent/${f}\`)`); strip that prefix back off so all
// four lists compare in the same AGENT_DIR-relative form.
const releaseWardenList = HELIOS_SELF_INTEGRITY_FILES.map((f) =>
  f.replace(/^packages\/fw-agent\//, '')
);

console.log('self-integrity-lockstep:');

check('all four copies are non-empty', () => {
  assert.ok(indexJsList.length > 0, 'index.js list parsed empty');
  assert.ok(generateBaselineList.length > 0, 'generate-baseline.js list parsed empty');
  assert.ok(ciYmlList.length > 0, 'ci.yml list parsed empty');
  assert.ok(releaseWardenList.length > 0, 'release-warden.js list parsed empty');
});

check('all four copies are deeply equal, order-sensitive', () => {
  assert.deepStrictEqual(
    generateBaselineList,
    indexJsList,
    `scripts/generate-baseline.js diverges from index.js:\n  index.js:            ${JSON.stringify(indexJsList)}\n  generate-baseline.js: ${JSON.stringify(generateBaselineList)}`
  );
  assert.deepStrictEqual(
    ciYmlList,
    indexJsList,
    `.github/workflows/ci.yml diverges from index.js:\n  index.js: ${JSON.stringify(indexJsList)}\n  ci.yml:   ${JSON.stringify(ciYmlList)}`
  );
  assert.deepStrictEqual(
    releaseWardenList,
    indexJsList,
    `.agent/scripts/release-warden.js diverges from index.js:\n  index.js:        ${JSON.stringify(indexJsList)}\n  release-warden.js: ${JSON.stringify(releaseWardenList)}`
  );
});

check('list is exactly 10 files and contains the previously-missing / Phase-3 files', () => {
  assert.strictEqual(indexJsList.length, 10, `expected 10 files, got ${indexJsList.length}: ${JSON.stringify(indexJsList)}`);
  assert.ok(indexJsList.includes('src/aho-corasick.js'), 'src/aho-corasick.js missing from index.js list');
  assert.ok(indexJsList.includes('src/ast-scan.js'), 'src/ast-scan.js missing from index.js list');
  assert.ok(indexJsList.includes('sync-worker.js'), 'sync-worker.js missing from index.js list');
  assert.ok(releaseWardenList.includes('src/aho-corasick.js'), 'src/aho-corasick.js missing from release-warden.js list (F-01)');
  assert.ok(releaseWardenList.includes('src/ast-scan.js'), 'src/ast-scan.js missing from release-warden.js list');
  assert.ok(releaseWardenList.includes('sync-worker.js'), 'sync-worker.js missing from release-warden.js list (F-01)');
});

check('recomputed 10-file hash matches the committed .helios-baseline', () => {
  const hash = crypto.createHash('sha256');
  for (const rel of indexJsList) {
    const content = fs.readFileSync(path.join(AGENT_DIR, rel), 'utf8').replace(/\r\n/g, '\n');
    hash.update(content, 'utf8');
  }
  const computed = hash.digest('hex');
  const stored = fs.readFileSync(path.join(AGENT_DIR, '.helios-baseline'), 'utf8').trim();
  assert.strictEqual(computed, stored, `computed ${computed} !== stored ${stored}`);
});

console.log(`\n${passed} passed, ${failed} failed.`);
if (failed > 0) process.exit(1);
