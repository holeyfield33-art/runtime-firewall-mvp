// packages/fw-agent/test/esm-fixtures/dynamic-import-sentinel.mjs
// Dynamic import() of the malicious sentinel — unlike the static-import fixture, this CAN be
// wrapped in try/catch, since it's an expression, not a linking-time binding.
const sentinelUrl = new URL('../../../../red-team/corpus/fixtures/sentinel-block.mjs', import.meta.url);

try {
  const sentinel = await import(sentinelUrl.href);
  console.log('DYNAMIC_IMPORT_COMPLETED:' + JSON.stringify({ ran: sentinel.ran, marked: globalThis.__SENTINEL_RAN__ }));
} catch (e) {
  console.log('DYNAMIC_IMPORT_THREW:' + (e && e.message));
}
