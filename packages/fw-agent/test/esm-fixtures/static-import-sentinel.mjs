// packages/fw-agent/test/esm-fixtures/static-import-sentinel.mjs
// Genuine top-level static `import` declaration of the malicious sentinel fixture, outside any
// try/catch. If the agent's ESM load hook (packages/fw-agent/index.js via Module.registerHooks())
// blocks it, this file's body below never runs at all — the whole process crashes with an
// uncaught exception (see esm-loader-test.js for how that's asserted). Reaching the console.log
// below means the import was NOT intercepted.
//
// Imports the NAMED `ran` export (sentinel-block.mjs has no default export) — using a default
// import here was a latent bug: when the block DOES fire (registerHooks available), the firewall
// hook throws before Node ever checks whether the imported binding actually exists, masking the
// mismatch; but with the hook unavailable (older Node, an honest disclosed bypass), the import
// proceeds to real linking and Node itself throws an unrelated SyntaxError for the missing
// binding, misrepresenting an honest bypass as a crash.
import { ran } from '../../../../red-team/corpus/fixtures/sentinel-block.mjs';

console.log('STATIC_IMPORT_COMPLETED:' + JSON.stringify({ ran, marked: globalThis.__SENTINEL_RAN__ }));
