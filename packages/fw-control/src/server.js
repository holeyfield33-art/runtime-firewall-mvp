// packages/fw-control/src/server.js
let fastify;
try {
  fastify = require('fastify')({ logger: false });
} catch (err) {
  if (err && err.code === 'MODULE_NOT_FOUND' && /'?fastify'?/.test(err.message)) {
    console.error('[@fw/control] Cannot start the control plane: the "fastify" dependency is not installed.');
    console.error('[@fw/control] Run "npm install" in the repository root, then start it again:');
    console.error('[@fw/control]     npm install && npm run start:control');
    process.exit(1);
  }
  throw err;
}
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { TELEMETRY_EVENT_TYPES } = require('../../fw-agent/src/telemetry-protocol');

const PORT = process.env.FW_CONTROL_PORT || 3000;
// Always enforce authentication on /logs.
// If no token is provided via HELIOS_DASHBOARD_TOKEN, generate a cryptographically
// strong random token for this process lifetime and print it once so operators can
// copy it. This makes the endpoint secure by default without requiring configuration.
const DASHBOARD_TOKEN = process.env.HELIOS_DASHBOARD_TOKEN || (() => {
  const generated = crypto.randomBytes(32).toString('hex');
  console.log(`[@fw/control] No HELIOS_DASHBOARD_TOKEN set — using auto-generated token for this session:`);
  console.log(`[@fw/control] Dashboard token: ${generated}`);
  console.log(`[@fw/control] Set HELIOS_DASHBOARD_TOKEN=${generated} to make it permanent.`);
  return generated;
})();

// Optional bearer-token auth for /v1/telemetry (F-19).
// When FW_TELEMETRY_TOKEN is set agents must send Authorization: Bearer <token>.
// When unset the endpoint is unauthenticated (backward-compatible default).
const TELEMETRY_TOKEN = process.env.FW_TELEMETRY_TOKEN || null;

// Persistent audit log (mirrors agent-side writes for control-plane events)
const LOG_DIR = process.env.HELIOS_LOG_DIR ||
  (process.platform !== 'win32' ? '/var/log/helios' : path.join(os.tmpdir(), 'helios'));
const LOG_PATH = path.join(LOG_DIR, 'audit.log');

// F-6.2 (P1-3): mirrors the same fix in packages/fw-agent/src/audit-log.js -- fs.openSync()
// defaults to mode 0o666 when omitted, leaving the actual on-disk permissions entirely
// dependent on the host's umask. 0600 (owner read/write only) is requested at open time and
// re-asserted with an explicit chmod, since `mode` is only honored when open() actually creates
// the file, not when it opens a pre-existing one with looser permissions.
const SECURE_FILE_MODE = 0o600;
function openSecure(filePath) {
  const fd = fs.openSync(filePath, 'a', SECURE_FILE_MODE);
  try { fs.chmodSync(filePath, SECURE_FILE_MODE); } catch (e) { /* best-effort on platforms without POSIX modes */ }
  return fd;
}

let logFd = null;
(function openLog() {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    logFd = openSecure(LOG_PATH);
  } catch (e) {
    const fallback = path.join(os.tmpdir(), 'helios');
    try {
      fs.mkdirSync(fallback, { recursive: true });
      logFd = openSecure(path.join(fallback, 'audit.log'));
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
let queueBytes = 0;
// P1 (Issue 4): bounded-resource controls, independent of item count. The audit accepted a
// single ~900 KB telemetry request; a queue full of similarly large-but-individually-valid
// bodies exhausts memory long before an item-count ceiling is reached. All limits are
// env-overridable; defaults are generous for every event shape fw-agent actually emits (see
// emitTelemetry() call sites) while closing the unbounded-field/unbounded-queue DoS.
const MAX_QUEUE_SIZE = parseInt(process.env.FW_TELEMETRY_MAX_QUEUE_ITEMS, 10) || 5000;
const MAX_QUEUE_BYTES = parseInt(process.env.FW_TELEMETRY_MAX_QUEUE_BYTES, 10) || 10 * 1024 * 1024; // 10 MB
const MAX_TELEMETRY_BODY_BYTES = parseInt(process.env.FW_TELEMETRY_MAX_BODY_BYTES, 10) || 256 * 1024; // 256 KB/request
const MAX_EVENTS_PER_BATCH = parseInt(process.env.FW_TELEMETRY_MAX_EVENTS, 10) || 500;
const MAX_TELEMETRY_STRING_LENGTH = 2048; // bounds named + unknown string-valued fields
const serverStartTime = Date.now();

// Keep a rolling window of the last 1000 events for the dashboard
const recentEvents = [];
const MAX_RECENT = 1000;

// additionalProperties bounds any UNKNOWN string-valued field (e.g. a future/optional
// "message"-shaped key) without constraining the non-string metadata shapes real event types
// already send (DETECTION_TRIGGERED's `detections` array, OBSERVE's `warnMatches` array,
// QUARANTINE_BREACH's nested forensic object). Explicit `anyOf` (not a bare `maxLength`) so
// ajv strict mode doesn't warn about an untyped keyword; non-string branches are otherwise
// unconstrained here. Nested string values several levels deep inside those shapes are bounded
// only by MAX_TELEMETRY_BODY_BYTES, not per-field -- a deliberate trade-off to avoid a
// brittle, hand-maintained per-event-type schema.
const telemetryEventSchema = {
  type: 'object',
  required: ['eventType', 'packageName', 'timestamp'],
  properties: {
    eventType: { type: 'string', enum: TELEMETRY_EVENT_TYPES },
    packageName: { type: 'string', maxLength: MAX_TELEMETRY_STRING_LENGTH },
    parentPackage: { type: ['string', 'null'], maxLength: MAX_TELEMETRY_STRING_LENGTH },
    timestamp: { type: 'number' },
  },
  additionalProperties: {
    anyOf: [
      { type: 'string', maxLength: MAX_TELEMETRY_STRING_LENGTH },
      { type: 'number' },
      { type: 'boolean' },
      { type: 'null' },
      { type: 'object' },
      { type: 'array' },
    ],
  },
};

const telemetrySchema = {
  body: {
    type: 'object',
    required: ['agentId', 'events', 'schemaVersion'],
    additionalProperties: false,
    properties: {
      agentId: { type: 'string', maxLength: MAX_TELEMETRY_STRING_LENGTH },
      schemaVersion: { type: 'integer', enum: [1] },
      events: {
        type: 'array',
        maxItems: MAX_EVENTS_PER_BATCH,
        items: telemetryEventSchema,
      },
    },
  },
};

fastify.post('/v1/telemetry', { schema: telemetrySchema, bodyLimit: MAX_TELEMETRY_BODY_BYTES }, async (request, reply) => {
  // F-19: Optional bearer-token auth. Active only when FW_TELEMETRY_TOKEN is set.
  if (TELEMETRY_TOKEN) {
    const authHeader = request.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    const a = Buffer.from(token);
    const b = Buffer.from(TELEMETRY_TOKEN);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return reply.code(401).send({ error: 'Unauthorized' });
    }
  }

  // Admission requires both an item-count budget AND a byte budget -- a queue full of
  // large-but-individually-valid requests must not exhaust memory before MAX_QUEUE_SIZE is
  // reached (the ~900 KB single-request case the audit reproduced).
  const incomingBytes = Buffer.byteLength(JSON.stringify(request.body));
  if (telemetryQueue.length >= MAX_QUEUE_SIZE || queueBytes + incomingBytes > MAX_QUEUE_BYTES) {
    return reply.code(503).send({ status: 'QUEUE_FULL' });
  }

  telemetryQueue.push({ body: request.body, bytes: incomingBytes });
  queueBytes += incomingBytes;

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
  queueBytes,
  maxQueueBytes: MAX_QUEUE_BYTES,
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

// Background drain: process the queue in batches. Queued-byte accounting must decrease as
// items are drained, or the byte budget would only ever grow and permanently wedge admission.
const _drainTimer = setInterval(() => {
  if (telemetryQueue.length === 0) return;
  const batch = telemetryQueue.splice(0, 100);
  for (const item of batch) queueBytes -= item.bytes;
  console.log(`[Background Worker] Drained ${batch.length} events (queue depth: ${telemetryQueue.length}, queue bytes: ${queueBytes})`);
}, 1000);
if (_drainTimer.unref) _drainTimer.unref();

const startServer = async () => {
  try {
    await fastify.listen({ port: PORT, host: '127.0.0.1' });
    console.log(`[@fw/control] Ingestion engine online at http://127.0.0.1:${PORT}`);
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
