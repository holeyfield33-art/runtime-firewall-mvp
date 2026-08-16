// packages/fw-agent/esm-loader.mjs
//
// Module Customization Hook (module.register) — the ESM counterpart to the CommonJS
// Module.prototype._compile hook in index.js. Node's ESM loader is an entirely separate pipeline
// that never invokes _compile, so static `import` declarations and dynamic import() both bypassed
// detection entirely before this file existed (P2-01 directive; execution-surface-matrix rows
// "ESM static import" / "dynamic import()" both reported BYPASS).
//
// This file MUST be a genuine ES module (hence .mjs, regardless of packages/fw-agent's own
// CommonJS package.json) — module.register() loads the hooks specifier through the ESM loader,
// and hooks run in a dedicated thread separate from the main thread's Module.prototype._compile
// context. Because of that thread boundary, this instantiates its OWN Detector rather than
// sharing index.js's in-process policyMap / behaviorTracker state.
//
// KNOWN LIMITATIONS (P2-01 scope; see engineer-receipt.json known_limitations for the record):
//   - Detector.scanModuleSync's `policyEngine` constructor arg is unused by the class itself (the
//     BLOCK/QUARANTINE/OBSERVE policy lookup lives in index.js's _compile wrapper, not in
//     Detector) — so this reproduces exactly _compile's default OBSERVE-tier signature/behavioral
//     scan, with no way to key a per-module BLOCK/QUARANTINE policy override for ESM modules yet.
//   - _compile resets behaviorTracker once per dependency-tree root (`this.parent === null`); the
//     load() hook below has no equivalent root signal, so behavioral state persists for the whole
//     hooks-thread lifetime instead of being scoped per import tree. This can only make cross-file
//     behavioral correlation MORE aggressive than the CJS path (never less), and ESM currently has
//     zero detection at all, so this is a conservative starting point, not a regression.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { Detector } = require('./src/detector.js');

const detector = new Detector(null);

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);

  // Only scan actual ES module source loaded from a local file. Non-'module' formats (builtins,
  // JSON, wasm, CJS-interop) either carry no usable text or are already covered by _compile.
  if (result.format !== 'module' || typeof result.source === 'undefined' || result.source === null) {
    return result;
  }
  if (!url.startsWith('file://')) {
    return result;
  }

  const source = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8');
  const filename = fileURLToPath(url);
  const requestName = filename.split(/[\\/]/).pop();

  const scanResult = detector.scanModuleSync(requestName, source, filename, null);
  const blockDetections = scanResult.detections.filter((d) => !d.warnOnly);

  if (blockDetections.length > 0) {
    const msg = `[Firewall] Detection in "${requestName}": ${blockDetections.map((d) => d.rule || d.type).join(', ')}`;
    throw new Error(msg);
  }

  return result;
}
