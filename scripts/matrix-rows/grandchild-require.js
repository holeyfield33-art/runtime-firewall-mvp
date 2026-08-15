// scripts/matrix-rows/grandchild-require.js
// Helper target spawned by child-fork.js / child-spawn.js. Just requires the sentinel and
// prints a machine-readable marker line to stdout so the parent row can tell "ran" apart from
// "blocked" without relying on exit codes. Deliberately its own file: it must NOT be combined
// with the child_process-using parent row files (see _shared.js header comment).
'use strict';
const path = require('path');
const { FIXTURES_DIR } = require('./_shared');

const SENTINEL_CJS = path.join(FIXTURES_DIR, 'sentinel-block.js');

try {
  require(SENTINEL_CJS);
  console.log('MATRIX_GRANDCHILD_RESULT: ran');
} catch (e) {
  console.log('MATRIX_GRANDCHILD_RESULT: blocked ' + (e && e.message));
}
