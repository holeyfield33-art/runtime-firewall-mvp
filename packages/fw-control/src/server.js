// packages/fw-control/src/server.js
const fastify = require('fastify')({ logger: false });
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const PORT = process.env.FW_CONTROL_PORT || 3000;
const DASHBOARD_TOKEN = process.env.HELIOS_DASHBOARD_TOKEN || null;

// Persistent audit log (mirrors agent-side writes for control-plane events)
const LOG_DIR = process.env.HELIOS_LOG_DIR ||
  (process.platform !== 'win32' ? '/var/log/helios' : path.join(os.tmpdir(), 'helios'));
const LOG_PATH = path.join(LOG_DIR, 'audit.log');

let logFd = null;
(function openLog() {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    logFd = fs.openSync(LOG_PATH, 'a');
  } catch (e) {
    const fallback = path.join(os.tmpdir(), 'helios');
    try {
      fs.mkdirSync(fallback, { recursive: true });
      logFd = fs.openSync(path.join(fallback, 'audit.log'), 'a');
    } catch (e2) {
      logFd = null;
    }
  }
})();

function persistEvent(event) {
  if (!logFd) return;
  try {
    const line = JSON.stringify({ ...event, _control_logged_at: new Date().toISOString() }) + '\n';
    fs.writeSync(logFd, Buffer.from(line, 'utf8'));
  } catch (e) {}
}

// In-memory queue for async processing
const telemetryQueue = [];
const MAX_QUEUE_SIZE = 5000;
const serverStartTime = Date.now();

// Keep a rolling window of the last 1000 events for the dashboard
const recentEvents = [];
const MAX_RECENT = 1000;

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
            eventType: {
              type: 'string',
              enum: [
                'OBSERVE', 'WARN', 'QUARANTINE_ACTIVE', 'QUARANTINE_BREACH', 'BLOCK',
                'DETECTION_TRIGGERED', 'QUARANTINE_BLOCK_REQUIRE', 'POLICY_TAMPER_LOCKDOWN',
                'SUSPICIOUS_SCRIPT', 'AGENT_START', 'AGENT_SHUTDOWN',
              ],
            },
            packageName: { type: 'string' },
            parentPackage: { type: ['string', 'null'] },
            timestamp: { type: 'number' },
          },
        },
      },
    },
  },
};

fastify.post('/v1/telemetry', { schema: telemetrySchema }, async (request, reply) => {
  if (telemetryQueue.length >= MAX_QUEUE_SIZE) {
    return reply.code(503).send({ status: 'QUEUE_FULL' });
  }

  telemetryQueue.push(request.body);

  // Persist each event to audit log immediately
  for (const event of request.body.events) {
    const enriched = { ...event, agentId: request.body.agentId };
    persistEvent(enriched);
    recentEvents.push(enriched);
    if (recentEvents.length > MAX_RECENT) recentEvents.shift();
  }

  return reply.code(202).send({ status: 'ACCEPTED' });
});

fastify.get('/v1/health', async () => ({
  status: 'ONLINE',
  uptime: Math.round((Date.now() - serverStartTime) / 1000),
  queueDepth: telemetryQueue.length,
  maxQueueSize: MAX_QUEUE_SIZE,
  logPath: logFd ? LOG_PATH : null,
}));

// Read-only dashboard: returns recent forensic events as JSON
fastify.get('/logs', async (request, reply) => {
  if (DASHBOARD_TOKEN) {
    const authHeader = request.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    const a = Buffer.from(token);
    const b = Buffer.from(DASHBOARD_TOKEN);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return reply.code(401).send({ error: 'Unauthorized' });
    }
  }

  const limit = Math.max(1, Math.min(parseInt(request.query.limit || '100', 10) || 100, MAX_RECENT));
  const events = recentEvents.slice(-limit);

  const accept = request.headers.accept || '';
  if (accept.includes('text/html')) {
    const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    const rows = events.map(e =>
      `<tr><td>${esc(new Date(e.timestamp).toISOString())}</td><td>${esc(e.eventType)}</td><td>${esc(e.packageName)}</td><td>${esc(e.agentId || '')}</td></tr>`
    ).join('\n');
    return reply
      .code(200)
      .header('Content-Type', 'text/html; charset=utf-8')
      .send(`<!DOCTYPE html><html><head><title>Helios Audit Log</title></head><body>
<h1>Helios Firewall — Recent Events</h1>
<table border="1"><thead><tr><th>Time</th><th>Event</th><th>Package</th><th>Agent</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`);
  }

  return reply.code(200).send({ events, total: recentEvents.length });
});

// Background drain: process the queue in batches
setInterval(() => {
  if (telemetryQueue.length === 0) return;
  const batch = telemetryQueue.splice(0, 100);
  console.log(`[Background Worker] Drained ${batch.length} events (queue depth: ${telemetryQueue.length})`);
}, 1000);

const startServer = async () => {
  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    console.log(`[@fw/control] Ingestion engine online at http://localhost:${PORT}`);
    if (logFd) console.log(`[@fw/control] Audit log: ${LOG_PATH}`);
  } catch (err) {
    console.error('Critical control plane startup failure:', err.message);
    process.exit(1);
  }
};

process.on('SIGTERM', async () => {
  if (logFd) { try { fs.closeSync(logFd); } catch (e) {} }
  await fastify.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  if (logFd) { try { fs.closeSync(logFd); } catch (e) {} }
  await fastify.close();
  process.exit(0);
});

if (require.main === module) {
  startServer();
}

module.exports = { fastify, startServer };
