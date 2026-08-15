// red-team/corpus/fixtures/sentinel-block.mjs
//
// TEST FIXTURE — NOT MALWARE. ESM twin of ./sentinel-block.js, used to probe execution
// surfaces where the module is loaded through Node's ESM loader instead of the CommonJS
// `Module.prototype._compile` path the firewall hooks. Same BLOCK_SIGNATURE literal.
export const marker = 'stratum+tcp://sentinel.invalid';
export const ran = true;

if (typeof globalThis !== 'undefined') {
  globalThis.__SENTINEL_RAN__ = true;
}
