// packages/fw-agent/test/esm-fixtures/interop-cjs-sentinel.cjs
// F-79 true-positive fixture: a CommonJS module carrying a block-tier signature in its SOURCE, so
// the detector must quarantine it. Loaded via `import` from a .mjs, it reaches the firewall through
// Node's CJS-through-ESM interop (result.format === 'commonjs') -- the exact path that, before
// F-79, was early-returned unscanned. The body is INERT (it never opens a socket); it only sets a
// run-marker, so if the firewall FAILS to block it the test observes the marker rather than any
// real payload. The '/dev/tcp/' + 'bash -i >&' reverse-shell idiom below is a string literal only.
const REVSHELL = 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'; // block-tier signature; never executed
globalThis.__INTEROP_CJS_MALICIOUS_RAN__ = true;
module.exports = { ran: true, sigLen: REVSHELL.length };
