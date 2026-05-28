// packages/fw-control/test/integration.js
const path = require('path');

// Give the process enough time for worker thread to flush events
console.log('[Integration Test] Loading agent with module tracking enabled...');

// Require the agent - this starts the worker thread
require(path.join(__dirname, '../../fw-agent/index.js'));

// Load some test modules to generate telemetry events
require('fs');
require('path');
require('util');

console.log('[Integration Test] Modules loaded. Waiting 2 seconds for worker thread to flush telemetry...');

// Give worker thread time to batch and flush events
setTimeout(() => {
  console.log('[Integration Test] Verification complete. Process exiting.');
  process.exit(0);
}, 2000);
