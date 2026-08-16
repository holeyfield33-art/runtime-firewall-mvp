// packages/fw-agent/test/__agent-experiment-001-fixture.js
// Throwaway fixture for .agent/directives/P2-EXPERIMENT-001.json — proves the .agent/
// orchestration graph mechanics. Not a real product test; safe to delete after the experiment.
'use strict';
const assert = require('assert');
assert.strictEqual(1 + 1, 2, 'sanity check for P2-EXPERIMENT-001 PASS scenario');
console.log('P2-EXPERIMENT-001 fixture: OK');
