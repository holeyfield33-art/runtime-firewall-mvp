// packages/fw-control/test/control-plane-auth-test.js
// Tests for fw-control server authentication and bind behaviour.
// Uses Fastify's built-in inject() — no real HTTP port needed.
'use strict';

const assert = require('assert');

// Set token BEFORE requiring server so it is captured at module load time
process.env.HELIOS_DASHBOARD_TOKEN = 'test-secret-token-abc123';
process.env.FW_TELEMETRY_TOKEN = 'test-telemetry-token-xyz789';
process.env.FW_CONTROL_PORT = '3099'; // avoid conflicting with any real instance

const { fastify } = require('../src/server');

(async () => {
  // ── Test 1: /logs without Authorization header → 401 ─────────────────────
  {
    const res = await fastify.inject({ method: 'GET', url: '/logs' });
    assert.strictEqual(res.statusCode, 401, `Expected 401, got ${res.statusCode}`);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.error, 'Unauthorized');
    console.log('  ✓ GET /logs without token → 401 Unauthorized');
  }

  // ── Test 2: /logs with correct Bearer token → 200 ────────────────────────
  {
    const res = await fastify.inject({
      method: 'GET',
      url: '/logs',
      headers: { authorization: 'Bearer test-secret-token-abc123' },
    });
    assert.strictEqual(res.statusCode, 200, `Expected 200, got ${res.statusCode}`);
    const body = JSON.parse(res.body);
    assert.ok(Array.isArray(body.events), 'Response must have events array');
    console.log('  ✓ GET /logs with correct token → 200 OK');
  }

  // ── Test 3: /logs with wrong Bearer token → 401 ───────────────────────────
  {
    const res = await fastify.inject({
      method: 'GET',
      url: '/logs',
      headers: { authorization: 'Bearer wrong-token' },
    });
    assert.strictEqual(res.statusCode, 401, `Expected 401, got ${res.statusCode}`);
    console.log('  ✓ GET /logs with wrong token → 401 Unauthorized');
  }

  // ── Test 4: /v1/health is always accessible (no auth required) ───────────
  {
    const res = await fastify.inject({ method: 'GET', url: '/v1/health' });
    assert.strictEqual(res.statusCode, 200, `Expected 200, got ${res.statusCode}`);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.status, 'ONLINE');
    console.log('  ✓ GET /v1/health is unauthenticated and returns ONLINE');
  }

  console.log('All control-plane auth tests passed.');

  // ── Test 5 (F-19): /v1/telemetry without token → 401 when FW_TELEMETRY_TOKEN is set ─────
  {
    const payload = JSON.stringify({ agentId: 'test', schemaVersion: 1, events: [] });
    const res = await fastify.inject({
      method: 'POST',
      url: '/v1/telemetry',
      headers: { 'content-type': 'application/json' },
      payload,
    });
    assert.strictEqual(res.statusCode, 401, `Expected 401 when no telemetry token, got ${res.statusCode}`);
    console.log('  ✓ POST /v1/telemetry without token → 401 when FW_TELEMETRY_TOKEN set (F-19)');
  }

  // ── Test 6 (F-19): /v1/telemetry with correct token → 202 ────────────────
  {
    const payload = JSON.stringify({ agentId: 'test', schemaVersion: 1, events: [] });
    const res = await fastify.inject({
      method: 'POST',
      url: '/v1/telemetry',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer test-telemetry-token-xyz789',
      },
      payload,
    });
    assert.strictEqual(res.statusCode, 202, `Expected 202 with correct telemetry token, got ${res.statusCode}`);
    console.log('  ✓ POST /v1/telemetry with correct token → 202 (F-19)');
  }

  // ── Test 7 (F-19): /v1/telemetry with wrong token → 401 ──────────────────
  {
    const payload = JSON.stringify({ agentId: 'test', schemaVersion: 1, events: [] });
    const res = await fastify.inject({
      method: 'POST',
      url: '/v1/telemetry',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer wrong-token',
      },
      payload,
    });
    assert.strictEqual(res.statusCode, 401, `Expected 401 with wrong telemetry token, got ${res.statusCode}`);
    console.log('  ✓ POST /v1/telemetry with wrong token → 401 (F-19)');
  }

  console.log('All control-plane auth tests passed (including F-19 telemetry auth).');

  // Close fastify to release the log file descriptor, then exit cleanly.
  await fastify.close();
  process.exit(0);
})().catch(err => {
  console.error('Control-plane auth test FAILED:', err);
  process.exit(1);
});
