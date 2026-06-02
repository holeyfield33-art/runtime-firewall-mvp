const assert = require('assert');
const { Detector } = require('../src/detector');

const detector = new Detector(new Map());

const filler = ' /* benign filler to exceed pre-filter 512B threshold */ '.repeat(20);
let result = detector.scanModuleSync('test-package', 'const x = require("../mod"); // stratum' + filler);
assert.strictEqual(result.action, 'QUARANTINE');
assert.strictEqual(result.detections.length, 1);
assert.strictEqual(result.detections[0].type, 'crypto-miner');

result = detector.scanModuleSync('test-package', 'const x = 1 + 2;' + filler);
assert.strictEqual(result.action, 'OBSERVE');
assert.deepStrictEqual(result.detections, []);

result = detector.scanModuleSync('test-package', 'const x = eval("2+2");' + filler);
assert.strictEqual(result.action, 'QUARANTINE');
assert.strictEqual(result.detections[0].type, 'dynamic-code-exec');

console.log('Detector unit test passed.');
