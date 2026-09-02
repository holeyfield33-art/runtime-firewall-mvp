const assert = require('assert');
const { Detector } = require('../src/detector');

const detector = new Detector(new Map());

const filler = ' /* benign filler to exceed pre-filter 512B threshold */ '.repeat(20);
let result = detector.scanModuleSync('test-package', 'const x = require("../mod"); const pool = "stratum+tcp://pool.hashvault.pro:8080";' + filler);
assert.strictEqual(result.action, 'QUARANTINE');
assert.strictEqual(result.detections.length, 1);
assert.strictEqual(result.detections[0].type, 'crypto-miner');

result = detector.scanModuleSync('test-package', 'const x = 1 + 2;' + filler);
assert.strictEqual(result.action, 'OBSERVE');
assert.deepStrictEqual(result.detections, []);

result = detector.scanModuleSync('test-package', 'const x = eval("2+2");' + filler);
// F-20: eval( moved from BLOCK to WARN — appears legitimately in build tools / test frameworks.
// Standalone eval signature is WARN only; action must be OBSERVE (no hard block).
assert.strictEqual(result.action, 'OBSERVE');
const evalWarn = result.detections.find(d => d.warnOnly && d.matched === 'eval(');
assert.ok(evalWarn, 'eval( must surface as a warnOnly detection (F-20)');

// Behavioral rule DYNAMIC_CODE_EXEC_CHAIN must still hard-block eval + exec in the same module.
detector.behaviorTracker.reset();
result = detector.scanModuleSync('test-package', 'eval(userInput); require("child_process").exec(userInput);' + filler);
assert.strictEqual(result.action, 'QUARANTINE');
const behavioralBlock = result.detections.find(d => d.type === 'behavioral' && d.rule === 'DYNAMIC_CODE_EXEC_CHAIN');
assert.ok(behavioralBlock, 'eval + exec combination must still hard-block via DYNAMIC_CODE_EXEC_CHAIN (F-20)');

// Non-string / empty content short-circuits to an OBSERVE no-op (defensive guard).
detector.behaviorTracker.reset();
const emptyResult = detector.scanModuleSync('empty', null);
assert.strictEqual(emptyResult.action, 'OBSERVE');
assert.deepStrictEqual(emptyResult.detections, []);

// isSuspicious static helper: truthy only for non-empty strings (returns the &&-chain value).
assert.ok(Detector.isSuspicious('x'), 'non-empty string is suspicious');
assert.ok(!Detector.isSuspicious(''), 'empty string is not suspicious');
assert.ok(!Detector.isSuspicious(null), 'null is not suspicious');

// Phase 3 AST integration (FW_ENABLE_AST=1) — exercises detector.js's AstScanner wiring
// specifically; ast-scan.js's own detection logic is covered by ast-scan-unit-test.js.
(() => {
  const prevAst = process.env.FW_ENABLE_AST;
  try {
    process.env.FW_ENABLE_AST = '1';

    // Standalone obfuscated-access finding -> block-tier detection, astResolved tagged.
    detector.behaviorTracker.reset();
    let r = detector.scanModuleSync('pkg', "const fn = this['ev' + 'al']; fn('x');" + filler, 'test.js', 'pkg');
    assert.strictEqual(r.action, 'QUARANTINE');
    const standalone = r.detections.find(d => d.type === 'obfuscated-dynamic-code');
    assert.ok(standalone && standalone.astResolved, 'bracket-eval must surface as an astResolved obfuscated-dynamic-code detection');

    // Folded literal re-matched against BLOCK_SIGNATURES (crypto-miner label + isCrypto hint).
    detector.behaviorTracker.reset();
    r = detector.scanModuleSync('pkg', "const brand = String.fromCharCode(99,111,105,110,104,105,118,101); module.exports = brand;" + filler, 'test.js', 'pkg');
    assert.strictEqual(r.action, 'QUARANTINE');
    const minerHit = r.detections.find(d => d.astResolved && d.type === 'crypto-miner');
    assert.ok(minerHit, 'folded "coinhive" literal must re-match BLOCK_SIGNATURES via the astResolved path');

    // Folded literal re-matched against BLOCK_REGEXES (an idiom too generic to be a safe literal,
    // e.g. netcat-exec, only expressible as an anchored regex).
    detector.behaviorTracker.reset();
    r = detector.scanModuleSync('pkg', "const cmd = 'nc ' + '-e /bin/sh'; module.exports = cmd;" + filler, 'test.js', 'pkg');
    assert.strictEqual(r.action, 'QUARANTINE');
    const regexHit = r.detections.find(d => d.astResolved && d.matched === 'netcat-exec');
    assert.ok(regexHit, 'folded "nc -e" literal must re-match BLOCK_REGEXES via the astResolved path');

    // A folded literal matching BLOCK_SIGNATURES without a crypto-brand hint labels
    // dynamic-code-exec/HIGH, not crypto-miner/CRITICAL (the isCrypto=false branch).
    detector.behaviorTracker.reset();
    r = detector.scanModuleSync('pkg', "const dest = '//paste' + 'bin'; module.exports = dest;" + filler, 'test.js', 'pkg');
    assert.strictEqual(r.action, 'QUARANTINE');
    const nonCryptoHit = r.detections.find(d => d.astResolved && d.type === 'dynamic-code-exec');
    assert.ok(nonCryptoHit, 'a non-crypto folded literal must label dynamic-code-exec/HIGH, not crypto-miner');

    // filename falls back to packageName when absent — same fallback the non-AST path already
    // relies on.
    detector.behaviorTracker.reset();
    r = detector.scanModuleSync('pkg', "const fn = this['ev' + 'al']; fn('x');" + filler, undefined, 'pkg');
    assert.strictEqual(r.action, 'QUARANTINE');

    // FW_ENABLE_BEHAVIORAL=0 alongside FW_ENABLE_AST=1: astSignalsForBehavior is computed but the
    // behaviorTracker call itself is skipped (the ternary's false branch).
    const prevBehavioral = process.env.FW_ENABLE_BEHAVIORAL;
    process.env.FW_ENABLE_BEHAVIORAL = '0';
    detector.behaviorTracker.reset();
    r = detector.scanModuleSync('pkg', "const fn = this['ev' + 'al']; fn('x');" + filler, 'test.js', 'pkg');
    assert.strictEqual(r.action, 'QUARANTINE', 'the standalone AST detection is independent of the behavioral tier');
    if (prevBehavioral === undefined) delete process.env.FW_ENABLE_BEHAVIORAL;
    else process.env.FW_ENABLE_BEHAVIORAL = prevBehavioral;

    // A module with no AST-relevant content behaves identically to AST disabled.
    detector.behaviorTracker.reset();
    r = detector.scanModuleSync('pkg', 'const x = 1 + 2;' + filler, 'test.js', 'pkg');
    assert.strictEqual(r.action, 'OBSERVE');
    assert.deepStrictEqual(r.detections, []);

    // AstScanner.scan() throwing must never propagate — detector.js's own try/catch is a second,
    // belt-and-suspenders guarantee on top of AstScanner.scan()'s internal fail-open.
    detector.behaviorTracker.reset();
    const originalScan = detector.astScanner.scan;
    detector.astScanner.scan = () => { throw new Error('simulated AST failure'); };
    assert.doesNotThrow(() => {
      r = detector.scanModuleSync('pkg', "const fn = this['ev' + 'al'];" + filler, 'test.js', 'pkg');
    });
    assert.strictEqual(r.action, 'OBSERVE', 'a thrown AST scan must degrade to OBSERVE, not crash or false-block');
    detector.astScanner.scan = originalScan;

    // ── F-91: incomplete-scan policy (FW_AST_INCOMPLETE_POLICY) ────────────────────────────────
    // A high-risk span flood exceeding the AST tier's high-risk budget forces an *incomplete* scan.
    // The three policy values must behave distinctly and unmistakably.
    const prevPolicy = process.env.FW_AST_INCOMPLETE_POLICY;
    try {
      const bigFiller = 'x'.repeat(2100); // > MAX_SPAN_CHARS so each decoy is its own span
      // >256 benign high-risk (concat bracket-access) spans: harmless by value, high-risk by shape,
      // so the high-risk budget is exhausted and the scan is reported incomplete — with NO real
      // payload present, so any block is attributable purely to the incompleteness policy.
      const incompleteFlood = Array.from({ length: 300 }, (_, i) => `const z${i} = obj['xx' + 'yy'];${bigFiller}`).join('\n');

      // observe (default): telemetry only — the module still runs (OBSERVE), the incomplete finding
      // is present but warnOnly, and its matched string unmistakably names the high-risk span counts.
      process.env.FW_AST_INCOMPLETE_POLICY = 'observe';
      detector.behaviorTracker.reset();
      r = detector.scanModuleSync('pkg', incompleteFlood, 'flood.js', 'pkg');
      assert.strictEqual(r.action, 'OBSERVE', 'observe policy must not block on incompleteness alone');
      const obs = r.detections.find(d => d.type === 'ast-scan-incomplete');
      assert.ok(obs, 'observe policy must still emit an ast-scan-incomplete telemetry detection');
      assert.strictEqual(obs.warnOnly, true, 'observe-policy incomplete detection must be warnOnly (telemetry, not a block)');
      assert.ok(/^ast-scan-incomplete:\d+-high-risk-spans-\d+-scanned$/.test(obs.matched),
        'incomplete telemetry must unmistakably carry the high-risk span counts, got: ' + obs.matched);

      // unset FW_AST_INCOMPLETE_POLICY defaults to observe (never fail-closed by accident).
      delete process.env.FW_AST_INCOMPLETE_POLICY;
      detector.behaviorTracker.reset();
      r = detector.scanModuleSync('pkg', incompleteFlood, 'flood.js', 'pkg');
      assert.strictEqual(r.action, 'OBSERVE', 'unset incomplete policy must default to observe (non-blocking)');
      assert.ok(r.detections.find(d => d.type === 'ast-scan-incomplete' && d.warnOnly),
        'unset policy still emits warnOnly incomplete telemetry');

      // quarantine and block both fail CLOSED: incompleteness becomes a block-tier, non-warnOnly,
      // astResolved HIGH detection and the module is quarantined.
      for (const policy of ['quarantine', 'block']) {
        process.env.FW_AST_INCOMPLETE_POLICY = policy;
        detector.behaviorTracker.reset();
        r = detector.scanModuleSync('pkg', incompleteFlood, 'flood.js', 'pkg');
        assert.strictEqual(r.action, 'QUARANTINE', `${policy} policy must fail closed (QUARANTINE) on an incomplete scan`);
        const blk = r.detections.find(d => d.type === 'ast-scan-incomplete');
        assert.ok(blk && !blk.warnOnly && blk.severity === 'HIGH' && blk.astResolved,
          `${policy} policy must produce a block-tier astResolved HIGH ast-scan-incomplete detection`);
      }

      // A benign ORDINARY-span flood (low-risk require()/(0,) noise) far exceeding the low-risk
      // budget must NOT be reported incomplete under any policy — no false positive on large bundles.
      process.env.FW_AST_INCOMPLETE_POLICY = 'quarantine';
      detector.behaviorTracker.reset();
      const benignFlood = Array.from({ length: 400 }, (_, i) => `const a${i} = (0, require)('m${i}');${bigFiller}`).join('\n');
      r = detector.scanModuleSync('pkg', benignFlood, 'bundle.js', 'pkg');
      assert.strictEqual(r.action, 'OBSERVE', 'ordinary low-risk bundle noise must never be flagged incomplete, even under quarantine policy');
      assert.ok(!r.detections.find(d => d.type === 'ast-scan-incomplete'),
        'low-risk bundle noise must not produce an ast-scan-incomplete detection');
    } finally {
      if (prevPolicy === undefined) delete process.env.FW_AST_INCOMPLETE_POLICY;
      else process.env.FW_AST_INCOMPLETE_POLICY = prevPolicy;
    }

    console.log('Detector AST integration (FW_ENABLE_AST=1) test passed.');
  } finally {
    if (prevAst === undefined) delete process.env.FW_ENABLE_AST;
    else process.env.FW_ENABLE_AST = prevAst;
  }
})();

// Async scanModule wrapper delegates to scanModuleSync.
(async () => {
  detector.behaviorTracker.reset();
  const asyncResult = await detector.scanModule('async-pkg', 'const pool = "stratum://pool.hashvault.pro:8080";' + filler);
  assert.strictEqual(asyncResult.action, 'QUARANTINE');
  assert.strictEqual(asyncResult.detections[0].type, 'crypto-miner');
  console.log('Detector unit test passed.');
})().catch((e) => { console.error(e.message); process.exit(1); });
