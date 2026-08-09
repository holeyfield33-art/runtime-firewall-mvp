// Lightweight Fastify child process used by fastify-integration-test.js
const fastify = require('fastify');
const path = require('path');

// Configure audit log dir for test inspection
process.env.HELIOS_LOG_DIR = process.env.HELIOS_LOG_DIR || path.join(__dirname, 'logs');

// Optionally enable detection when parent sets FW_ENABLE_DETECTION=1
if (process.env.FW_ENABLE_DETECTION === '1') {
  // Allow using the dev policy key in tests
  process.env.FW_ALLOW_DEV_POLICY_KEY = '1';
  // Load the agent package from workspace packages (relative)
  try {
    require(path.resolve(__dirname, '..', '..', 'fw-agent'));
  } catch (e) {
    console.error('Agent failed to load:', e && e.stack);
    process.exit(2);
  }
}

const PORT = (typeof process.env.FW_CONTROL_PORT !== 'undefined') ? Number(process.env.FW_CONTROL_PORT) : 0;
const app = fastify({ logger: false });

app.get('/ping', async () => ({ status: 'ok', protected: !!process.env.FW_ENABLE_DETECTION }));

app.listen({ port: PORT, host: '127.0.0.1' }).then(() => {
  // Determine the actual bound port (useful when port 0 ephemeral was requested)
  const addr = app.server && app.server.address && app.server.address();
  const boundPort = (addr && addr.port) ? addr.port : PORT;
  // Notify parent that we're ready and which port we bound to
  process.stdout.write(`READY ${boundPort}\n`);
}).catch(err => {
  console.error('Fastify failed to listen:', err && err.stack);
  process.exit(3);
});

// Keep process alive until parent kills it
process.on('SIGTERM', () => process.exit(0));
