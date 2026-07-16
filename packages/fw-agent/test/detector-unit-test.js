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

// Async scanModule wrapper delegates to scanModuleSync.
(async () => {
  detector.behaviorTracker.reset();
  const asyncResult = await detector.scanModule('async-pkg', 'const pool = "stratum://pool.hashvault.pro:8080";' + filler);
  assert.strictEqual(asyncResult.action, 'QUARANTINE');
  assert.strictEqual(asyncResult.detections[0].type, 'crypto-miner');
  console.log('Detector unit test passed.');
})().catch((e) => { console.error(e.message); process.exit(1); });
