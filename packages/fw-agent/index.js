// packages/fw-agent/index.js
const Module = require('module');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Worker } = require('worker_threads');

// Exit early and export nothing if detection is not enabled - zero overhead for baseline runs
if (process.env.FW_ENABLE_DETECTION !== '1') {
  module.exports = {};
  return;
}

const { Detector } = require('./src/detector');
const { QuarantineStub } = require('./src/quarantine');
const { PolicyWatcher } = require('./src/policy-watcher');
const { getAuditLog } = require('./src/audit-log');

// ── Runtime detection: fail closed if running under Bun or Deno without preload ──────────────
(function detectRuntime() {
  if (typeof process.versions.bun !== 'undefined') {
    const preload = process.env.BUN_PRELOAD || '';
    if (!preload.includes('fw-agent') && !preload.includes('helios')) {
      console.error('[CRITICAL] Helios is not preloaded in Bun runtime. Set BUN_PRELOAD=fw-agent. Exiting.');
      process.exit(1);
    }
  }
  if (typeof process.versions.deno !== 'undefined') {
    const preload = process.env.DENO_PRELOAD || '';
    if (!preload.includes('fw-agent') && !preload.includes('helios')) {
      console.error('[CRITICAL] Helios is not preloaded in Deno runtime. Exiting.');
      process.exit(1);
    }
  }
})();

// ── Preload verification ──────────────────────────────────────────────────────────────────────
// Strict mode (FW_STRICT_PRELOAD=1) exits if agent was not injected via --require.
// Default mode warns so programmatic loading (and tests) still work.
(function verifyPreloadManifold() {
  const execArgsJoin = (process.execArgv || []).join(' ').replace(/\\/g, '/');
  const isPreloaded = execArgsJoin.includes('fw-agent') || execArgsJoin.includes('helios');
  if (!isPreloaded) {
    if (process.env.FW_STRICT_PRELOAD === '1') {
      console.error('[CRITICAL] Helios was not injected via --require. Set --require=fw-agent to ensure all modules are intercepted from startup. Exiting.');
      process.exit(1);
    } else {
      console.warn('[Helios] Warning: agent loaded via require() rather than --require. Modules loaded before this point are not protected.');
    }
  }
})();

// ── Primitive prototype lockdown ──────────────────────────────────────────────────────────────
(function primitiveLockdown() {
  const intrinsicPrototypes = [Object.prototype, Array.prototype, Function.prototype, Promise.prototype, RegExp.prototype];
  for (const proto of intrinsicPrototypes) {
    try {
      Object.freeze(proto);
      Object.getOwnPropertyNames(proto).forEach(prop => {
        try { Object.defineProperty(proto, prop, { writable: false, configurable: false }); } catch (e) {}
      });
    } catch (e) {}
  }
})();

// ── Self-integrity check ──────────────────────────────────────────────────────────────────────
(function verifySelfIntegrity() {
  const baselineFile = path.join(__dirname, '.helios-baseline');
  const selfFiles = [
    path.join(__dirname, 'index.js'),
    path.join(__dirname, 'src', 'detector.js'),
    path.join(__dirname, 'src', 'behavior-tracker.js'),
    path.join(__dirname, 'src', 'policy-watcher.js'),
    path.join(__dirname, 'src', 'quarantine.js'),
    path.join(__dirname, 'src', 'audit-log.js'),
  ];

  function computeSelfHash() {
    const hash = crypto.createHash('sha256');
    for (const f of selfFiles) {
      try { hash.update(fs.readFileSync(f)); } catch (e) {}
    }
    return hash.digest('hex');
  }

  if (fs.existsSync(baselineFile)) {
    const stored = fs.readFileSync(baselineFile, 'utf8').trim();
    const current = computeSelfHash();
    if (stored !== current) {
      console.error('[CRITICAL] Firewall self-integrity check FAILED. Helios code has been tampered with. Refusing to run.');
      process.exit(1);
    }
  } else {
    // First run: establish baseline
    try {
      fs.writeFileSync(baselineFile, computeSelfHash() + '\n', 'utf8');
    } catch (e) {}
  }
})();

// ── npm lifecycle script scanning ────────────────────────────────────────────────────────────
(function scanNpmLifecycleScripts() {
  const pkgPath = path.join(process.cwd(), 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  const SUSPICIOUS_SCRIPT_PATTERNS = [
    /curl\s+.*\|\s*(ba)?sh/i,
    /wget\s+.*\|\s*(ba)?sh/i,
    /node\s+.*download/i,
    /python\s+.*http/i,
    /bash\s+-c\s+['"]/i,
    /eval\s*\$/i,
    /base64\s+--decode/i,
  ];

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch (e) { return; }
  if (!pkg.scripts) return;

  for (const [scriptName, cmd] of Object.entries(pkg.scripts)) {
    if (typeof cmd !== 'string') continue;
    if (SUSPICIOUS_SCRIPT_PATTERNS.some(p => p.test(cmd))) {
      console.error(`[HELIOS] Suspicious npm lifecycle script blocked: "${scriptName}" = "${cmd}"`);
      getAuditLog().write({ eventType: 'SUSPICIOUS_SCRIPT', scriptName, command: cmd });
      if (process.env.HELIOS_BLOCK_SCRIPTS !== '0') {
        process.exit(1);
      }
    }
  }
})();

// ── Telemetry worker thread ───────────────────────────────────────────────────────────────────
const telemetryEnabled = process.env.FW_TELEMETRY === '1';
const telemetryWorkerPath = path.join(__dirname, 'sync-worker.js');
const telemetryWorker = telemetryEnabled ? (() => {
  const w = new Worker(telemetryWorkerPath);
  w.unref();
  return w;
})() : null;

// ── Audit log (persistent) ────────────────────────────────────────────────────────────────────
const auditLog = getAuditLog();

// ── Policy loading & continuous integrity watcher ────────────────────────────────────────────
let policyMap = new Map();
const POLICY_PATH = path.join(process.cwd(), 'policy.signed.json');

function loadPolicy() {
  if (!fs.existsSync(POLICY_PATH)) return;
  try {
    const raw = fs.readFileSync(POLICY_PATH, 'utf8');
    const policy = JSON.parse(raw);
    policyMap = new Map(Object.entries(policy.rules || {}));
  } catch (e) {
    console.warn('[PolicyLoader] Failed to parse policy file:', e.message);
  }
}

loadPolicy();

// Emergency lockdown: block ALL module loads
let emergencyLockdown = false;

const policyWatcher = new PolicyWatcher(POLICY_PATH, () => {
  emergencyLockdown = true;
  auditLog.write({ eventType: 'POLICY_TAMPER_LOCKDOWN', timestamp: Date.now() });
  emitTelemetry('POLICY_TAMPER_LOCKDOWN', 'policy.signed.json', null);
});
policyWatcher.start();

// ── Detector ─────────────────────────────────────────────────────────────────────────────────
const detector = new Detector(policyMap);

// ── Telemetry helpers ─────────────────────────────────────────────────────────────────────────
function emitTelemetry(eventType, packageName, parentPackage, metadata = {}) {
  if (!telemetryWorker) return;
  telemetryWorker.postMessage({
    type: 'TELEMETRY_EVENT',
    payload: { eventType, packageName, parentPackage, timestamp: Date.now(), ...metadata },
  });
}

// ── Compilation metrics ───────────────────────────────────────────────────────────────────────
const compileMetrics = { filesCompiled: 0, lockdownsEnforced: 0, quarantined: 0 };
const verifiedCompilationsCache = new Set();
const quarantinedModules = new Set();

// ── Core module interception hook ─────────────────────────────────────────────────────────────
const originalCompile = Module.prototype._compile;

Module.prototype._compile = function (content, filename) {
  // Emergency lockdown: block everything
  if (emergencyLockdown) {
    throw new Error('[Firewall] Emergency lockdown active. All module loads blocked.');
  }

  // Block loads initiated by a quarantined module
  if (this.parent && quarantinedModules.has(this.parent.filename)) {
    const requestName = path.basename(filename);
    const event = { eventType: 'QUARANTINE_BLOCK_REQUIRE', blockedModule: requestName, origin: path.basename(this.parent.filename), timestamp: Date.now() };
    auditLog.write(event);
    emitTelemetry('QUARANTINE_BLOCK_REQUIRE', requestName, path.basename(this.parent.filename));
    throw new Error(`[Firewall] Quarantined module "${path.basename(this.parent.filename)}" cannot load "${requestName}"`);
  }

  const requestName = path.basename(filename);
  const configuredRule = policyMap.get(requestName) || 'OBSERVE';

  if (configuredRule === 'BLOCK') {
    const event = { eventType: 'BLOCK', packageName: requestName, timestamp: Date.now() };
    auditLog.write(event);
    emitTelemetry('BLOCK', requestName, null);
    throw new Error(`[Firewall] Compilation denied for module: "${requestName}"`);
  }

  if (configuredRule === 'QUARANTINE') {
    compileMetrics.quarantined++;
    const event = { eventType: 'QUARANTINE_ACTIVE', packageName: requestName, source: 'policy', timestamp: Date.now() };
    auditLog.write(event);
    emitTelemetry('QUARANTINE_ACTIVE', requestName, null, { source: 'policy' });
    quarantinedModules.add(filename);
    // Return a stub without executing the module's code
    const stub = new QuarantineStub(requestName, { emit: (t, d) => emitTelemetry(t, requestName, null, d) });
    this.exports = stub.createProxy();
    return;
  }

  if (configuredRule === 'OBSERVE') {
    if (verifiedCompilationsCache.has(filename)) {
      return originalCompile.apply(this, arguments);
    }

    compileMetrics.filesCompiled++;
    const scanResult = detector.scanModuleSync(requestName, content, filename);

    if (scanResult.detections.length > 0) {
      compileMetrics.lockdownsEnforced++;
      const event = {
        eventType: 'DETECTION_TRIGGERED',
        packageName: requestName,
        detections: scanResult.detections,
        timestamp: Date.now(),
      };
      auditLog.write(event);
      emitTelemetry('DETECTION_TRIGGERED', requestName, null, { detections: scanResult.detections });

      // MEDIUM detections (DYNAMIC_MODULE_LOAD) → quarantine silently; HIGH/CRITICAL → hard block
      const hasMediumOnly = scanResult.detections.every(d => d.severity === 'MEDIUM');
      if (hasMediumOnly) {
        quarantinedModules.add(filename);
        const stub = new QuarantineStub(requestName, { emit: (t, d) => emitTelemetry(t, requestName, null, d) });
        this.exports = stub.createProxy();
        return;
      }

      const msg = `[Firewall] Detection in "${requestName}": ${scanResult.detections.map(d => d.rule || d.type).join(', ')}`;
      console.error(`\n[COMPILATION LOCKDOWN] Threat detected in "${requestName}"`);
      throw new Error(msg);
    }

    verifiedCompilationsCache.add(filename);
  }

  return originalCompile.apply(this, arguments);
};

// ── Graceful shutdown ─────────────────────────────────────────────────────────────────────────
async function shutdown(signal) {
  console.log(`\n[Helios] Received ${signal}. Flushing telemetry and shutting down workers...`);

  policyWatcher.stop();

  if (telemetryWorker) {
    telemetryWorker.postMessage({ type: 'FORCE_FLUSH' });
    // Give the worker a moment to flush before terminating
    await new Promise(resolve => setTimeout(resolve, 500));
    try { await telemetryWorker.terminate(); } catch (e) {}
  }

  auditLog.write({ eventType: 'AGENT_SHUTDOWN', signal, timestamp: Date.now() });
  auditLog.close();

  console.log(`[Helios] Shutdown complete. Monitored: ${compileMetrics.filesCompiled}, Quarantined: ${compileMetrics.quarantined}, Blocked: ${compileMetrics.lockdownsEnforced}`);
}

process.on('SIGTERM', () => shutdown('SIGTERM').then(() => process.exit(0)));
process.on('SIGINT', () => shutdown('SIGINT').then(() => process.exit(0)));

process.on('exit', (code) => {
  if (code !== 9) {
    console.log(`\n[Helios] Exit ${code} | Compilations: ${compileMetrics.filesCompiled} | Quarantined: ${compileMetrics.quarantined} | Blocked: ${compileMetrics.lockdownsEnforced}`);
  }
  if (telemetryWorker) {
    telemetryWorker.postMessage({ type: 'FORCE_FLUSH' });
  }
  // Sync close - safe on exit event
  try { auditLog.close(); } catch (e) {}
});

// Log startup
auditLog.write({ eventType: 'AGENT_START', timestamp: Date.now(), logPath: auditLog.filePath });

module.exports = { policyMap, compileMetrics, quarantinedModules };
