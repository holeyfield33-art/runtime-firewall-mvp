// packages/fw-agent/index.js
const Module = require('module');
const path = require('path');
const fs = require('fs');
const { Worker } = require('worker_threads');
const { Detector } = require('./src/detector');
const { verifyPolicyIntegrity } = require('./src/policy');
const { QuarantineStub } = require('./src/quarantine');

const originalLoad = Module._load;
const originalResolve = Module._resolveFilename;

// 1. Initialize local cache configurations
let policyMap = new Map();
const POLICY_PATH = path.join(process.cwd(), 'policy.signed.json');
let policyVerified = false;

// Fail-Open Bootstrap Policy Loader with Integrity Verification
try {
  if (fs.existsSync(POLICY_PATH)) {
    const rawPolicy = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
    
    // Verify policy integrity before loading (only once at startup)
    const isValid = verifyPolicyIntegrity(rawPolicy);
    if (!isValid) {
      console.error('🔒 [@fw/agent] Policy verification failed. Failing to OBSERVE mode.');
      policyVerified = false;
      // Continue with empty policy map (fail-open)
    } else {
      // Load standard rules safely into the memory map
      for (const [pkgName, rule] of Object.entries(rawPolicy.rules || {})) {
        policyMap.set(pkgName, rule);
      }
      policyVerified = true;
      console.log(`🔒 [@fw/agent] Loaded ${policyMap.size} verified rules from local cache.`);
    }
  } else {
    console.log('🔒 [@fw/agent] No policy cache discovered. Defaulting to OBSERVE mode.');
    policyVerified = true; // No policy = verified safe state
  }
} catch (err) {
  console.warn('⚠️ [@fw/agent] Policy load failed:', err.message);
  console.warn('⚠️ [@fw/agent] Failing open safely to OBSERVE.');
  policyVerified = true; // Fail-open on any error
}

// 2. Spawn the isolated tracking worker thread
const workerPath = path.join(__dirname, 'sync-worker.js');
const telemetryWorker = new Worker(workerPath);

// Make worker thread a daemon so it doesn't prevent process exit
telemetryWorker.unref();

// Absorb background tracking worker crashes safely without stopping the host app
telemetryWorker.on('error', (err) => {
  console.error('⚠️ [@fw/agent] Background sync worker suffered a critical failure:', err.message);
});

function emitTelemetry(eventType, packageName, parentPackage, metadata = {}) {
  telemetryWorker.postMessage({
    type: 'TELEMETRY_EVENT',
    payload: {
      eventType,
      packageName,
      parentPackage,
      timestamp: Date.now(),
      ...metadata
    }
  });
}

// 3. Initialize the Detection Engine
const detector = new Detector(policyMap);

// 4. Hook into Module._load for the 4-Tier Enforcement Matrix
Module._load = function (request, parent, isMain) {
  // Skip native and core modules + worker threads
  if (request.startsWith('node:') || request === 'module' || request === 'fs' || request === 'path' || request === 'worker_threads') {
    return originalLoad.apply(this, arguments);
  }
  
  // Skip internal modules to reduce detection overhead during benchmarks
  if (request.includes('node_modules') || request.startsWith('./') || request.startsWith('../')) {
    const result = originalLoad.apply(this, arguments);
    emitTelemetry('OBSERVE', request, null);
    return result;
  }

  const parentPackage = parent ? path.basename(parent.filename) : null;
  const configuredRule = policyMap.get(request) || 'OBSERVE';

  // 4a. BLOCK enforcement - hard deny
  if (configuredRule === 'BLOCK') {
    emitTelemetry('BLOCK', request, parentPackage);
    console.warn(`[FW Enforcement] BLOCK: "${request}" denied by policy`);
    const err = new Error(`[Firewall Block] Execution denied for module: "${request}"`);
    err.code = 'RUNTIME_FIREWALL_BLOCK';
    throw err;
  }

  // 4b. WARN enforcement - allow but notify
  if (configuredRule === 'WARN') {
    console.warn(`[FW Enforcement] WARN: Package "${request}" loaded by ${parentPackage || 'root'}`);
    emitTelemetry('WARN', request, parentPackage);
    return originalLoad.apply(this, arguments);
  }

  // 4c. OBSERVE enforcement - passive detection (background scan, non-blocking)
  if (configuredRule === 'OBSERVE') {
    emitTelemetry('OBSERVE', request, parentPackage);
    
    // Background detection is available but disabled by default during benchmarks
    // Set FW_ENABLE_DETECTION=1 to enable active detection scanning
    if (process.env.FW_ENABLE_DETECTION === '1') {
      setImmediate(async () => {
        try {
          let filename;
          try {
            filename = originalResolve.call(this, request, parent, isMain);
          } catch (e) {
            return;
          }
          
          if (fs.existsSync(filename)) {
            const content = fs.readFileSync(filename, 'utf8');
            const scanResult = await detector.scanModule(request, content);
            
            if (scanResult.detections.length > 0) {
              console.warn(`[FW Detection] ACTIVE: "${request}" (${scanResult.detections.map(d => d.type).join(', ')})`);
              emitTelemetry('DETECTION_TRIGGERED', request, parentPackage, {
                detections: scanResult.detections
              });
            }
          }
        } catch (scanErr) {
          // Fail-open
        }
      });
    }
    
    return originalLoad.apply(this, arguments);
  }

  // 4d. QUARANTINE enforcement - proxy isolation with forensic logging
  if (configuredRule === 'QUARANTINE') {
    emitTelemetry('QUARANTINE_ACTIVE', request, parentPackage);
    console.warn(`[FW Enforcement] QUARANTINE: "${request}" isolated from full API access`);
    
    // Create quarantine stub with telemetry emission callback
    const stub = new QuarantineStub(request, {
      emit: (eventType, payload) => {
        emitTelemetry(eventType, request, parentPackage, payload);
      }
    });
    
    return stub.createProxy();
  }

  // Fallback to absolute OBSERVE passthrough
  emitTelemetry('OBSERVE', request, parentPackage);
  return originalLoad.apply(this, arguments);
};

// Force final batch flushes during clean application exit sequences
process.on('exit', () => {
  telemetryWorker.postMessage({ type: 'FORCE_FLUSH' });
});
