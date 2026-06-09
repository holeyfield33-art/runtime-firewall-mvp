// packages/fw-agent/sync-worker.js
// Telemetry worker thread: batches events and forwards them to the control plane.
// Supports graceful shutdown via TERMINATE message.

const { parentPort } = require('worker_threads');
const http = require('http');

let eventBuffer = [];
const FLUSH_INTERVAL_MS = 1000;
let flushTimer = null;
let terminating = false;

const agentId = `agent_${Math.random().toString(36).substring(2, 11)}`;

function flushEvents(callback) {
  if (eventBuffer.length === 0) {
    if (callback) callback();
    return;
  }

  const batch = [...eventBuffer];
  eventBuffer = [];
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  const payload = JSON.stringify({ agentId, events: batch, schemaVersion: 1 });

  const options = {
    hostname: 'localhost',
    port: process.env.FW_CONTROL_PORT || 3000,
    path: '/v1/telemetry',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    },
  };

  const req = http.request(options, (res) => {
    res.resume();
    if (callback) callback();
  });

  req.on('error', () => {
    // Fail-open: swallow network errors silently; never friction the host app
    if (callback) callback();
  });

  req.setTimeout(3000, () => {
    req.destroy();
    if (callback) callback();
  });

  req.write(payload);
  req.end();
}

parentPort.on('message', (message) => {
  if (message.type === 'TELEMETRY_EVENT') {
    if (terminating) return;
    eventBuffer.push(message.payload);
    if (!flushTimer) {
      flushTimer = setTimeout(flushEvents, FLUSH_INTERVAL_MS);
    }
  }

  if (message.type === 'FORCE_FLUSH') {
    if (flushTimer) clearTimeout(flushTimer);
    flushEvents();
  }

  if (message.type === 'TERMINATE') {
    terminating = true;
    if (flushTimer) clearTimeout(flushTimer);
    flushEvents(() => {
      parentPort.postMessage({ type: 'TERMINATED' });
      process.exit(0);
    });
  }
});
