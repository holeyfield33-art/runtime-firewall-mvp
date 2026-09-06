'use strict';

const assert = require('assert');
const { TELEMETRY_EVENT_TYPES } = require('../../fw-agent/src/telemetry-protocol');
const { fastify } = require('../src/server');

function event(eventType) {
  return {
    eventType,
    packageName: 'contract-test-package',
    parentPackage: null,
    timestamp: Date.now(),
  };
}

(async () => {
  for (const eventType of TELEMETRY_EVENT_TYPES) {
    const response = await fastify.inject({
      method: 'POST',
      url: '/v1/telemetry',
      payload: { agentId: 'contract-test-agent', events: [event(eventType)], schemaVersion: 1 },
    });
    assert.strictEqual(response.statusCode, 202, `${eventType} was rejected: ${response.body}`);
  }

  const mixedResponse = await fastify.inject({
    method: 'POST',
    url: '/v1/telemetry',
    payload: {
      agentId: 'contract-test-agent',
      events: [event('FW_MODE_ENFORCE'), event('CACHE_SUBSTITUTION_BLOCKED'), event('QUARANTINE_BREACH')],
      schemaVersion: 1,
    },
  });
  assert.strictEqual(mixedResponse.statusCode, 202, `mixed batch was rejected: ${mixedResponse.body}`);

  const unknownResponse = await fastify.inject({
    method: 'POST',
    url: '/v1/telemetry',
    payload: { agentId: 'contract-test-agent', events: [event('NOT_A_REAL_EVENT')], schemaVersion: 1 },
  });
  assert.strictEqual(unknownResponse.statusCode, 400, 'unknown event types must remain rejected');

  console.log(`Telemetry contract test passed (${TELEMETRY_EVENT_TYPES.length} event types plus mixed batch).`);
})().catch((error) => {
  console.error(error.stack || error);
  process.exit(1);
});
