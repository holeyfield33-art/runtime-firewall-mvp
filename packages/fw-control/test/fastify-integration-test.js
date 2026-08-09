// packages/fw-control/test/fastify-integration-test.js
'use strict';

const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

function runChild(env = {}, callback) {
  const childPath = path.join(__dirname, '_fastify_child.js');
  const child = spawn(process.execPath, [childPath], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });

  let ready = false;
  child.stdout.on('data', (d) => {
    const s = String(d || '');
    if (s.startsWith('READY')) {
      ready = true;
      const parts = s.trim().split(/\s+/);
      const port = Number(parts[1]);
      callback(null, { child, port });
    }
  });

  child.on('exit', (code, sig) => {
    if (!ready) callback(new Error(`child exited prematurely: ${code || sig}`));
  });
}

function httpGet(port, path, cb) {
  const opts = { hostname: '127.0.0.1', port, path, method: 'GET' };
  const req = http.request(opts, (res) => {
    let body = '';
    res.setEncoding('utf8');
    res.on('data', c => body += c);
    res.on('end', () => cb(null, res, body));
  });
  req.on('error', cb);
  req.end();
}

// Test baseline: Fastify without agent
(async () => {
  console.log('\nFastify integration: baseline (no agent)');
  runChild({}, async (err, { child, port }) => {
    if (err) { console.error('Baseline child error', err); process.exit(1); }
    try {
      await new Promise((res, rej) => httpGet(port, '/ping', (e, r, body) => e ? rej(e) : res({ r, body })));
      console.log('  ✓ Baseline ping 200 OK');
    } catch (e) {
      console.error('Baseline request failed', e && e.stack);
      child.kill('SIGTERM');
      process.exit(1);
    }
    child.kill('SIGTERM');
  });

  // Test protected: Fastify with agent active
  console.log('\nFastify integration: protected (agent active)');
  runChild({ FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' }, async (err, { child, port }) => {
    if (err) { console.error('Protected child error', err); process.exit(1); }
    try {
      const { r, body } = await new Promise((res, rej) => httpGet(port, '/ping', (e, r, body) => e ? rej(e) : res({ r, body })));
      assert.strictEqual(r.statusCode, 200);
      const parsed = JSON.parse(body);
      assert.strictEqual(parsed.status, 'ok');
      console.log('  ✓ Protected ping 200 OK and firewall active');
    } catch (e) {
      console.error('Protected request failed', e && e.stack);
      child.kill('SIGTERM');
      process.exit(1);
    }
    child.kill('SIGTERM');
    console.log('Fastify integration tests passed.');
    process.exit(0);
  });
})();
