'use strict';

const assert = require('assert');
const http = require('http');
const path = require('path');
const { Worker } = require('worker_threads');

(async () => {
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(400, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ error: 'unsupported event' }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  assert.strictEqual(server.address().address, '127.0.0.1', 'delivery fixture must use the same loopback family as the worker');

  const worker = new Worker(path.join(__dirname, '..', 'sync-worker.js'), {
    env: { ...process.env, FW_CONTROL_PORT: String(server.address().port) },
  });
  const failure = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for delivery failure')), 5000);
    worker.once('message', (message) => {
      if (message.type === 'TELEMETRY_DELIVERY_FAILURE') {
        clearTimeout(timer);
        resolve(message);
      }
    });
    worker.once('error', reject);
    worker.postMessage({
      type: 'TELEMETRY_EVENT',
      payload: { eventType: 'OBSERVE', packageName: 'delivery-test', parentPackage: null, timestamp: Date.now() },
    });
    worker.postMessage({ type: 'FORCE_FLUSH' });
  });

  assert.strictEqual(failure.statusCode, 400);
  assert.strictEqual(failure.eventCount, 1);
  worker.postMessage({ type: 'TERMINATE' });
  await worker.terminate();
  await new Promise((resolve) => server.close(resolve));
  console.log('Telemetry non-2xx delivery failure test passed.');
})().catch((error) => {
  console.error(error.stack || error);
  process.exit(1);
});
