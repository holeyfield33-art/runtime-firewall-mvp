// red-team/corpus/fixtures/sentinel-worker.js
// TEST FIXTURE — NOT MALWARE. Runs inside a worker_threads Worker and requires the sentinel
// module, reporting back to the parent whether the require() succeeded or was blocked.
'use strict';
const { parentPort } = require('worker_threads');
const path = require('path');

const sentinelPath = path.join(__dirname, 'sentinel-block.js');

try {
  require(sentinelPath);
  parentPort.postMessage({ status: 'ran' });
} catch (e) {
  parentPort.postMessage({ status: 'blocked', message: e && e.message });
}
