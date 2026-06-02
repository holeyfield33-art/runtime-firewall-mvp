// packages/fw-agent/index.js
const Module = require('module');
const path = require('path');

// Exit early if detection is not enabled—zero overhead for baseline runs
if (process.env.FW_ENABLE_DETECTION !== '1') {
  module.exports = {};
}

// Only execute security infrastructure if explicitly enabled
const { Worker } = require('worker_threads');

const compileMetrics = { filesCompiled: 0, lockdownsEnforced: 0 };
const verifiedCompilationsCache = new Set();

const telemetryEnabled = process.env.FW_TELEMETRY === '1';
const telemetryWorker = telemetryEnabled ? (() => {
  const workerPath = path.join(__dirname, 'sync-worker.js');
  const worker = new Worker(workerPath);
  worker.unref();
  return worker;
})() : null;

(function primitiveLockdown() {
  const intrinsicPrototypes = [Object.prototype, Array.prototype, Function.prototype, Promise.prototype, RegExp.prototype];
  for (const proto of intrinsicPrototypes) {
    try {
      Object.freeze(proto);
      Object.getOwnPropertyNames(proto).forEach(prop => {
        try { Object.defineProperty(proto, prop, { writable: false, configurable: false }); } catch(e){}
      });
    } catch(e){}
  }
})();

(function verifyPreloadManifold() {
  const execArgsJoin = (process.execArgv || []).join(' ').replace(/\\/g, '/');
  const isPreloaded = execArgsJoin.includes('fw-agent') || execArgsJoin.includes('index.js');
  
  if (!isPreloaded) {
    console.error('[CRITICAL] Structural Integrity Fracture: Preload requirement bypassed.');
    process.exit(1);
  }
})();

let policyMap = new Map();
const POLICY_PATH = path.join(process.cwd(), 'policy.signed.json');

const { Detector } = require('./src/detector');
const detector = new Detector(policyMap);

function emitTelemetry(eventType, packageName, parentPackage, metadata = {}) {
  if (!telemetryWorker) return;
  telemetryWorker.postMessage({
    type: 'TELEMETRY_EVENT',
    payload: { eventType, packageName, parentPackage, timestamp: Date.now(), ...metadata }
  });
}

const originalCompile = Module.prototype._compile;

Module.prototype._compile = function (content, filename) {
  const requestName = path.basename(filename);
  const configuredRule = policyMap.get(requestName) || 'OBSERVE';

  if (configuredRule === 'BLOCK') {
    emitTelemetry('BLOCK', requestName, null);
    throw new Error(`[Firewall Block] Compilation explicitly denied for module: "${requestName}"`);
  }

  if (configuredRule === 'OBSERVE') {
    if (verifiedCompilationsCache.has(filename)) {
      return originalCompile.apply(this, arguments);
    }

    compileMetrics.filesCompiled++;
    const scanResult = detector.scanModuleSync(requestName, content);

    if (scanResult.detections.length > 0) {
      compileMetrics.lockdownsEnforced++;
      console.error(`\n[🔒 COMPILATION LOCKDOWN] Critical Violation Prevented in "${requestName}"`);
      emitTelemetry('DETECTION_TRIGGERED', requestName, null, { detections: scanResult.detections });
      process.exit(9);
    }

    verifiedCompilationsCache.add(filename);
  }

  return originalCompile.apply(this, arguments);
};

process.on('exit', (code) => {
  if (code !== 9) {
    console.log(`\n📊 [Compilation Engine Telemetry] Monitored Compilations: ${compileMetrics.filesCompiled}`);
  }
  if (telemetryWorker) {
    telemetryWorker.postMessage({ type: 'FORCE_FLUSH' });
  }
});
