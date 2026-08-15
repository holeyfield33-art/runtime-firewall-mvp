// scripts/matrix-rows/native-addon.js
// Row: native .node addon load. No prebuilt native addon fixture exists in this environment, and
// architecturally native loads route through Module._extensions['.node']/process.dlopen(), which
// never calls Module.prototype._compile — this surface can't be covered by the current hook
// regardless of whether a working addon is available. Reported UNSUPPORTED, never skipped.
'use strict';
const { outfileReport } = require('./_shared');

const report = outfileReport(process.argv[2] || 'native-addon');

report(
  'UNSUPPORTED',
  'No prebuilt native .node addon fixture is available in this environment (no node-gyp build performed). ' +
  'Architecturally, native addon loads route through Module._extensions[\'.node\'] / process.dlopen(), which ' +
  'never calls Module.prototype._compile — this surface cannot be covered by the current hook regardless of ' +
  'whether a working addon is available to test with.'
);
