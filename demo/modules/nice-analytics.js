// demo/modules/nice-analytics.js
//
// A legitimate analytics module. It reads a config value from the environment
// and makes an outbound network call to report a page-view metric. This is the
// exact shape of a benign library: the firewall records the network call as a
// WARN-level observation but allows the module to load and run.
//
// Result: OBSERVE / WARN only -> ALLOWED (no sensitive-file reads, no malware
// signatures).

const https = require('https');

const endpoint = process.env.ANALYTICS_ENDPOINT || 'metrics.example.com';

function track(event, props = {}) {
  const payload = JSON.stringify({ event, props, ts: Date.now() });
  const req = https.request({
    hostname: endpoint,
    method: 'POST',
    path: '/v1/collect',
    headers: { 'content-type': 'application/json' },
  });
  req.on('error', () => {}); // best-effort metrics; never crash the host app
  req.end(payload);
  return payload;
}

module.exports = { track };
