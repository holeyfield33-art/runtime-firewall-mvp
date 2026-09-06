// packages/fw-control/test/telemetry-queue-bounds-test.js
// P1 (Issue 4): byte-bounded telemetry ingestion and queue memory limits.
'use strict';

// Small, deterministic limits for this test process only -- must be set before requiring the
// server module, since MAX_* constants are read once from process.env at module load time.
// MAX_TELEMETRY_STRING_LENGTH (per-field length) is a fixed, non-configurable constant (2048).
process.env.FW_TELEMETRY_MAX_QUEUE_ITEMS = '10';
process.env.FW_TELEMETRY_MAX_QUEUE_BYTES = '3500';
process.env.FW_TELEMETRY_MAX_BODY_BYTES = '2500';
process.env.FW_TELEMETRY_MAX_EVENTS = '3';

const assert = require('assert');
const { fastify } = require('../src/server');

let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  \u2713 ' + name);
  } catch (e) {
    console.error('  \u2717 ' + name + '\n    ' + (e && e.stack || e));
    process.exit(1);
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function event(overrides = {}) {
  return { eventType: 'OBSERVE', packageName: 'pkg', parentPackage: null, timestamp: Date.now(), ...overrides };
}

function post(events, overrides = {}) {
  return fastify.inject({
    method: 'POST',
    url: '/v1/telemetry',
    payload: { agentId: 'agent-1', schemaVersion: 1, events, ...overrides },
  });
}

async function health() {
  const res = await fastify.inject({ method: 'GET', url: '/v1/health' });
  return JSON.parse(res.body);
}

// DRAIN_WAIT_MS must exceed the server's 1-second background drain interval so every group
// starts from an empty queue, independent of what an earlier group left behind.
const DRAIN_WAIT_MS = 1100;

(async () => {
  await check('normal telemetry under all limits is accepted', async () => {
    const res = await post([event()]);
    assert.strictEqual(res.statusCode, 202);
  });
  await sleep(DRAIN_WAIT_MS);

  await check('malformed payload (missing required field) is rejected', async () => {
    const res = await fastify.inject({
      method: 'POST',
      url: '/v1/telemetry',
      payload: { agentId: 'agent-1', events: [event()] }, // schemaVersion missing
    });
    assert.strictEqual(res.statusCode, 400);
  });

  await check('malformed payload (unknown eventType) is rejected', async () => {
    const res = await post([event({ eventType: 'NOT_A_REAL_EVENT' })]);
    assert.strictEqual(res.statusCode, 400);
  });

  await check('oversized individual field is rejected', async () => {
    const res = await post([event({ packageName: 'x'.repeat(2049) })]);
    assert.strictEqual(res.statusCode, 400);
  });

  await check('too many events in one batch is rejected', async () => {
    const events = [event(), event(), event(), event()]; // MAX_EVENTS_PER_BATCH is 3
    const res = await post(events);
    assert.strictEqual(res.statusCode, 400);
  });

  await check('request over the per-request body-size limit is rejected (413)', async () => {
    // Each event stays under the 2048-char per-field cap, but three of them together exceed
    // the 2500-byte MAX_TELEMETRY_MAX_BODY_BYTES -- isolates the body-size check from the
    // per-field and per-batch-count checks above (both of which would also reject this shape).
    const events = [
      event({ packageName: 'x'.repeat(1200) }),
      event({ packageName: 'x'.repeat(1200) }),
    ];
    const res = await post(events);
    assert.strictEqual(res.statusCode, 413);
  });

  await check('queue item-count ceiling is enforced', async () => {
    // MAX_QUEUE_ITEMS is 10; each of these requests is small, so the byte budget (3500) has
    // ample headroom and cannot be the cause of any rejection observed here.
    const results = [];
    for (let i = 0; i < 11; i++) {
      results.push((await post([event()])).statusCode);
    }
    const accepted = results.filter((code) => code === 202).length;
    const rejected = results.filter((code) => code === 503).length;
    assert.strictEqual(accepted, 10, `expected exactly 10 accepted, got ${accepted}: ${JSON.stringify(results)}`);
    assert.strictEqual(rejected, 1, `expected exactly 1 queue-full rejection, got ${rejected}: ${JSON.stringify(results)}`);
  });
  await sleep(DRAIN_WAIT_MS);

  await check('queue byte-count ceiling is enforced (memory-focused adversarial case)', async () => {
    // Each request is individually valid (under the 2500-byte body limit and 2048-char field
    // cap) and serializes to ~1538 bytes -- two of them (~3076 bytes) fit under the 3500-byte
    // queue budget, but a third (~4614 bytes) exceeds it well before the 10-item ceiling would.
    const bigEvent = () => event({ packageName: 'x'.repeat(1400) });
    const first = await post([bigEvent()]);
    const second = await post([bigEvent()]);
    const third = await post([bigEvent()]);
    assert.strictEqual(first.statusCode, 202, 'first large-but-valid request must be accepted');
    assert.strictEqual(second.statusCode, 202, 'second large-but-valid request must be accepted');
    assert.strictEqual(third.statusCode, 503, 'third request must be rejected once the byte budget is exhausted, not the item count');

    const stats = await health();
    assert.ok(stats.queueBytes <= stats.maxQueueBytes, 'reported queueBytes must never exceed maxQueueBytes');
    assert.ok(stats.queueDepth < stats.maxQueueSize, 'item ceiling must not be the limiting factor in this scenario');
  });

  await check('queue byte accounting decreases after processing, freeing budget for new requests', async () => {
    const before = await health();
    assert.ok(before.queueBytes > 0, 'queue must still hold bytes from the previous group');

    await sleep(DRAIN_WAIT_MS);

    const after = await health();
    assert.strictEqual(after.queueBytes, 0, 'queueBytes must return to 0 once the background drain processes all queued items');
    assert.strictEqual(after.queueDepth, 0, 'queueDepth must return to 0 once the background drain processes all queued items');

    const res = await post([event({ packageName: 'x'.repeat(1400) })]);
    assert.strictEqual(res.statusCode, 202, 'a request that previously would have been rejected must be accepted once budget is freed');
  });

  console.log(`\n${passed} telemetry-queue-bounds checks passed.`);
  process.exit(0);
})().catch((err) => {
  console.error(err.stack || err);
  process.exit(1);
});
