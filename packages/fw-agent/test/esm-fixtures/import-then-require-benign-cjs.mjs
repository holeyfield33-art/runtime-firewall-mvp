// packages/fw-agent/test/esm-fixtures/import-then-require-benign-cjs.mjs
// The picomatch false-positive shape: `import` a CJS module via ESM (interop populates
// Module._cache), then require() the SAME path (as vite/astro do: `import pm from "picomatch"` and
// `__require("picomatch")`). Pre-F-79 the interop entry was never marked verified, so under
// FW_CACHE_POLICY=block the require() was refused by the F-58 cache gate. F-79 scans+verifies the
// interop-CJS in the load hook, so the require() is a clean verified cache hit.
import { createRequire } from 'module';
import benign from './interop-cjs-benign.cjs';
const require = createRequire(import.meta.url);
const benign2 = require('./interop-cjs-benign.cjs');
console.log('INTEROP_CJS_BENIGN_OK:' + JSON.stringify({ i: typeof benign.hello, r: typeof benign2.hello }));
