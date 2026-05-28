// packages/fw-control/src/server.js
const fastify = require('fastify')({ logger: false });

const PORT = process.env.FW_CONTROL_PORT || 3000;
const BODY_LIMIT = 1024 * 1024; // 1MB max payload

// Internal telemetry queue for async processing
const telemetryQueue = [];
const MAX_QUEUE_SIZE = 5000;
const serverStartTime = Date.now();

// Rigid structural schema validation definition
const telemetrySchema = {
  body: {
    type: 'object',
    required: ['agentId', 'events', 'schemaVersion'],
    properties: {
      agentId: { type: 'string' },
      schemaVersion: { type: 'integer', enum: [1] },
      events: {
        type: 'array',
        items: {
          type: 'object',
          required: ['eventType', 'packageName', 'timestamp'],
          properties: {
            eventType: { type: 'string', enum: ['OBSERVE', 'WARN', 'QUARANTINE_ACTIVE', 'QUARANTINE_BREACH', 'BLOCK'] },
            packageName: { type: 'string' },
            parentPackage: { type: ['string', 'null'] },
            timestamp: { type: 'number' }
          }
        }
      }
    }
  }
};

// High-Throughput Telemetry Ingress Endpoint (enqueue only, no processing)
fastify.post('/v1/telemetry', { schema: telemetrySchema }, async (request, reply) => {
  // Hard limit to prevent memory exhaustion
  if (telemetryQueue.length >= MAX_QUEUE_SIZE) {
    return reply.code(503).send({ status: 'QUEUE_FULL' });
  }

  telemetryQueue.push(request.body);
  
  // Instantly return 202 Accepted to clear the client agent's connection pool
  return reply.code(202).send({ status: 'ACCEPTED' });
});

// Structural Health Probe with operational metrics
fastify.get('/v1/health', async () => ({
  status: 'ONLINE',
  uptime: Math.round((Date.now() - serverStartTime) / 1000),
  queueDepth: telemetryQueue.length,
  maxQueueSize: MAX_QUEUE_SIZE
}));

// Background worker drains the queue asynchronously
setInterval(() => {
  if (telemetryQueue.length === 0) return;
  
  const batch = telemetryQueue.splice(0, 100);
  console.log(`[Background Worker] Processing ${batch.length} telemetry events (queue depth: ${telemetryQueue.length})`);
}, 1000);

// Initialize the control server instance
const startServer = async () => {
  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    console.log(`📡 [@fw/control] Ingestion Engine online at http://localhost:${PORT}`);
  } catch (err) {
    console.error('❌ Critical control plane startup failure:', err.message);
    process.exit(1);
  }
};

if (require.main === module) {
  startServer();
}

module.exports = { fastify, startServer };
