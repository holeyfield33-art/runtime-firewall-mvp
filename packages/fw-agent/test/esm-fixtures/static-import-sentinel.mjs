// packages/fw-agent/test/esm-fixtures/static-import-sentinel.mjs
// Genuine top-level static `import` declaration of the malicious sentinel fixture, outside any
// try/catch. If P2-01's esm-loader.mjs blocks it, this file's body below never runs at all — the
// whole process crashes with an uncaught exception (see esm-loader-test.js for how that's
// asserted). Reaching the console.log below means the import was NOT intercepted.
import sentinel from '../../../../red-team/corpus/fixtures/sentinel-block.mjs';

console.log('STATIC_IMPORT_COMPLETED:' + JSON.stringify({ ran: sentinel.ran, marked: globalThis.__SENTINEL_RAN__ }));
