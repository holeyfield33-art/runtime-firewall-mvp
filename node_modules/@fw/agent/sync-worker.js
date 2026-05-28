// packages/fw-agent/sync-worker.js
const { parentPort } = require('worker_threads');
const http = require('http');

let eventBuffer = [];
const FLUSH_INTERVAL_MS = 1000;
let flushTimer = null;

// Unique agent tracking descriptor generated for the application lifecycle instance
const agentId = `agent_${Math.random().toString(36).substring(2, 11)}`;

function flushEvents() {
  if (eventBuffer.length === 0) return;

  const batch = [...eventBuffer];
  eventBuffer = [];
  flushTimer = null;

  const payload = JSON.stringify({ agentId, events: batch, schemaVersion: 1 });

  const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/v1/telemetry',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };

  // Dispatch fire-and-forget network transaction out-of-band
  const req = http.request(options, (res) => {
    res.resume(); // Flush network stream buffers cleanly
  });

  req.on('error', (err) => {
    // Fail-Open Guardrail: Swallow connection drop anomalies silently. 
    // The client host application must never experience service execution friction 
    // due to a metrics reporting failure.
    console.warn(`[Worker Network Warning] Ingestion connection failed: ${err.message}`);
  });

  req.write(payload);
  req.end();
}

parentPort.on('message', (message) => {
  if (message.type === 'TELEMETRY_EVENT') {
    eventBuffer.push(message.payload);
    if (!flushTimer) {
      flushTimer = setTimeout(flushEvents, FLUSH_INTERVAL_MS);
    }
  }

  if (message.type === 'FORCE_FLUSH') {
    if (flushTimer) clearTimeout(flushTimer);
    flushEvents();
  }
});
