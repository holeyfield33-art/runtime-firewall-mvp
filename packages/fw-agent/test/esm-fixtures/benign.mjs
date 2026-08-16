// packages/fw-agent/test/esm-fixtures/benign.mjs
// Ordinary, non-malicious ESM module — used to confirm the P2-01 ESM loader hook does not
// false-positive on legitimate ES modules.
export function add(a, b) {
  return a + b;
}
