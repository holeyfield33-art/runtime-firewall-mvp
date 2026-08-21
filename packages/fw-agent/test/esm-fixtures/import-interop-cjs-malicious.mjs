// packages/fw-agent/test/esm-fixtures/import-interop-cjs-malicious.mjs
// Static `import` of the malicious CJS sentinel. If the firewall's ESM load hook scans the
// interop-CJS source (F-79) and blocks it, this file's body never runs -- the process crashes with
// an uncaught [Firewall] error. Reaching the console.log means the malicious CJS ran UNSCANNED.
import sentinel from './interop-cjs-sentinel.cjs';
console.log('INTEROP_CJS_MALICIOUS_RAN:' + JSON.stringify({ ran: sentinel && sentinel.ran }));
