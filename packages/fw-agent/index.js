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
const { PolicyWatcher, assertProductionKeyConfig } = require('./src/policy-watcher');
const { getAuditLog } = require('./src/audit-log');

// ── Runtime detection: fail closed if running under Bun or Deno without preload ──────────────
(function detectRuntime() {
  if (typeof process.versions.bun !== 'undefined') {
    const preload = process.env.BUN_PRELOAD || '';
    if (!preload.includes('aletheia-firewall') && !preload.includes('fw-agent') && !preload.includes('helios')) {
      console.error('[CRITICAL] Helios is not preloaded in Bun runtime. Set BUN_PRELOAD=aletheia-firewall. Exiting.');
      process.exit(1);
    }
  }
  if (typeof process.versions.deno !== 'undefined') {
    const preload = process.env.DENO_PRELOAD || '';
    if (!preload.includes('aletheia-firewall') && !preload.includes('fw-agent') && !preload.includes('helios')) {
      console.error('[CRITICAL] Helios is not preloaded in Deno runtime. Exiting.');
      process.exit(1);
    }
  }
})();

// ── Preload verification ──────────────────────────────────────────────────────────────────────
// Strict mode (FW_STRICT_PRELOAD=1) exits if agent was not injected via --require.
// Default mode warns so programmatic loading (and tests) still work.
//
// Detection parses process.execArgv for an actual --require / -r flag whose value resolves
// to THIS agent module. The earlier implementation did a substring search over the joined
// execArgv for "fw-agent"/"helios"/"aletheia-firewall" — trivially spoofed: `node -e
// "require('./packages/fw-agent')"` puts the whole inline script (containing "fw-agent")
// into execArgv, so the check reported "preloaded" and silently no-op'd, defeating the very
// guarantee it exists to enforce. We now require a genuine preload flag pointing at us.
//
// ── Enforcement mode (P0-3) ─────────────────────────────────────────────────────────────────
// FW_MODE=enforce      → not preloaded via --require is fatal: process.exit(1).
// FW_MODE=dev          → not preloaded via --require warns loudly and continues.
// FW_STRICT_PRELOAD=1  → backward-compatible alias for FW_MODE=enforce.
// FW_MODE unset        → defaults to 'dev' (fail-OPEN, not fail-closed). This is the honest,
//   currently-shipped guarantee — see README.md "Enforcement mode vs Development mode" before
//   relying on this in production. To ship enforce-by-default instead, flip the single line
//   below (DEFAULT_FW_MODE) and nothing else needs to change.
const DEFAULT_FW_MODE = 'dev'; // ← flip to 'enforce' to make fail-closed the default
function resolveFwMode() {
  const raw = (process.env.FW_MODE || '').toLowerCase();
  if (raw === 'enforce') return 'enforce';
  if (raw === 'dev') return 'dev';
  if (process.env.FW_STRICT_PRELOAD === '1') return 'enforce';
  return DEFAULT_FW_MODE;
}
const fwMode = resolveFwMode();

(function verifyPreloadManifold() {
  const execArgv = process.execArgv || [];

  // Resolve a --require/-r value the same way Node would (relative to cwd), then compare its
  // resolved module path to this agent. A failure to resolve is simply "not us".
  const resolvesToAgent = (value) => {
    if (!value) return false;
    try {
      const resolved = require.resolve(value, { paths: [process.cwd()] });
      // __dirname is packages/fw-agent; index.js (this file) is the package entry point.
      return resolved === __filename || resolved.startsWith(__dirname + path.sep);
    } catch (e) {
      // Bare specifier form (e.g. --require aletheia-firewall) that can't be resolved from
      // cwd here still counts if it names this package.
      return /(?:^|[\\/])(?:aletheia-firewall|fw-agent)(?:[\\/]|$)/.test(value);
    }
  };

  let isPreloaded = false;
  for (let i = 0; i < execArgv.length; i++) {
    const arg = execArgv[i];
    if (arg === '--require' || arg === '-r') {
      if (resolvesToAgent(execArgv[i + 1])) { isPreloaded = true; break; }
    } else if (arg.startsWith('--require=') || arg.startsWith('-r=')) {
      if (resolvesToAgent(arg.slice(arg.indexOf('=') + 1))) { isPreloaded = true; break; }
    }
  }

  if (!isPreloaded) {
    if (fwMode === 'enforce') {
      console.error('[CRITICAL] Helios was not injected via --require (FW_MODE=enforce / FW_STRICT_PRELOAD=1). Set --require=<path to packages/fw-agent> to ensure all modules are intercepted from startup. Exiting.');
      process.exit(1);
    } else {
      // One loud, high-visibility warning — this is a security-relevant fact, not a debug log.
      console.warn(
        '\n[Helios] ================================================================\n' +
        '[Helios]  WARNING: running in DEVELOPMENT mode (FW_MODE=dev, the default).\n' +
        '[Helios]  The agent was loaded via require() rather than --require, so any\n' +
        '[Helios]  module loaded before this point is NOT protected, and this process\n' +
        '[Helios]  will NOT exit if preload is missing entirely.\n' +
        '[Helios]  Set FW_MODE=enforce to fail closed instead (refuses to start unless\n' +
        '[Helios]  genuinely preloaded via --require). See README.md: "Enforcement mode\n' +
        '[Helios]  vs Development mode".\n' +
        '[Helios] ================================================================\n'
      );
    }
  }
})();


// ── Primitive prototype lockdown (opt-in via FW_FREEZE_PROTOTYPES=1) ───────────────────────────
// Disabled by default: freezing built-in prototypes breaks legitimate libraries
// (older polyfills, some ORMs, test frameworks) with confusing downstream errors.
// Set FW_FREEZE_PROTOTYPES=1 to enable. See F-11 in the security audit.
(function primitiveLockdown() {
  if (process.env.FW_FREEZE_PROTOTYPES !== '1') return;
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
    path.join(__dirname, 'src', 'policy.js'),
  ];

  function computeSelfHash() {
    const hash = crypto.createHash('sha256');
    for (const f of selfFiles) {
      try {
        const content = fs.readFileSync(f, 'utf8').replace(/\r\n/g, '\n');
        hash.update(content, 'utf8');
      } catch (e) {}
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
    // Baseline is committed to the repo and shipped in the npm manifest.
    // A missing baseline means the file was deleted or the package was tampered with.
    // Never silently re-baseline — fail closed so the operator knows something is wrong.
    console.error('[CRITICAL] Firewall self-integrity baseline (.helios-baseline) is missing. Cannot verify agent integrity. Refusing to run.');
    process.exit(1);
  }
})();

// ── Production policy-key sanity check (F-33) ──────────────────────────────────────────────────
// Runs regardless of whether a policy.signed.json exists on disk. Refuses to start in
// production when the bundled (public) dev key would be used to verify policies.
assertProductionKeyConfig();

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

// Build a policyMap from a rules object (called on startup and on hot-reload).
function buildPolicyMap(rules) {
  return new Map(Object.entries(rules || {}));
}

// Emergency lockdown: block ALL module loads
let emergencyLockdown = false;

// PolicyWatcher verifies the Ed25519 signature on every interval tick.
// onTamperDetected  → invalid/missing signature  → lockdown
// onValidChange     → valid signature + new rules → hot-reload policyMap
const policyWatcher = new PolicyWatcher(POLICY_PATH, {
  onTamperDetected: () => {
    emergencyLockdown = true;
    auditLog.write({ eventType: 'POLICY_TAMPER_LOCKDOWN', timestamp: Date.now() });
    emitTelemetry('POLICY_TAMPER_LOCKDOWN', 'policy.signed.json', null);
  },
  onValidChange: (rules) => {
    policyMap = buildPolicyMap(rules);
  },
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
// Cache keyed by filename → SHA-256 of content (not filename alone).
// Re-scans the file if its content changed between require() calls in a long-lived process.
const verifiedCompilationsCache = new Map();
const quarantinedModules = new Set();

// ── Core module interception hook ─────────────────────────────────────────────────────────────
const originalCompile = Module.prototype._compile;

// Derive the npm-package key for a filename so cross-file correlation stays scoped to ONE
// package. The behavioral tracker is reset per dependency-tree root (below), which spans the
// whole app — without this scoping, cross-file rules would pair a config-reading module with any
// unrelated http module in the tree and false-positive. Returns null for first-party app code
// (no node_modules segment): the developer's own files reading config and making network calls
// across files is normal, not the split-attack threat model, so cross-file is skipped for them.
function packageKeyForFilename(filename) {
  const norm = String(filename).replace(/\\/g, '/');
  const idx = norm.lastIndexOf('/node_modules/');
  if (idx === -1) return null;
  const rest = norm.slice(idx + '/node_modules/'.length).split('/');
  if (rest[0] && rest[0][0] === '@') return rest[0] + '/' + (rest[1] || '');
  return rest[0] || null;
}

// ── P0-2: canonical package identity ──────────────────────────────────────────────────────────
// The _compile policy lookup below historically keyed ONLY on path.basename(filename) — every
// package's index.js collapses to the same policy key "index.js", so a rule meant for one
// package's entry point applied to every package's entry point. resolveModuleIdentity() walks up
// from the file's directory to the nearest package.json for name+version, producing a canonical
// "name@version:relativePath" identity that disambiguates packages sharing a basename.
//
// Cache keyed on directory, not per file: this runs on every _compile call, so re-reading and
// re-parsing package.json for every file in a package would add a stat+parse per require() call
// instead of one per package directory (path-compressed: every directory walked on the way to a
// resolved package.json is memoized to the same result).
const packageJsonCache = new Map(); // dir -> { name, version, pkgDir } | null

function findPackageJsonInfo(startDir) {
  const visitedDirs = [];
  let dir = startDir;
  let result = null;
  for (;;) {
    if (packageJsonCache.has(dir)) {
      result = packageJsonCache.get(dir);
      break;
    }
    visitedDirs.push(dir);
    let pkg = null;
    try {
      const pkgPath = path.join(dir, 'package.json');
      if (fs.existsSync(pkgPath)) pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    } catch (e) {
      pkg = null;
    }
    if (pkg) {
      result = {
        name: typeof pkg.name === 'string' ? pkg.name : null,
        version: typeof pkg.version === 'string' ? pkg.version : null,
        pkgDir: dir,
      };
      break;
    }
    const parent = path.dirname(dir);
    if (parent === dir) { result = null; break; } // reached filesystem root without finding one
    dir = parent;
  }
  for (const d of visitedDirs) packageJsonCache.set(d, result);
  return result;
}

// Returns a canonical "name@version:relativePath" identity when a package.json is resolvable by
// walking up from the file's directory; otherwise falls back to the normalized absolute path
// (never throws — first-party app files with no ancestor package.json still get a sane, stable
// identity string rather than crashing the hot path).
function resolveModuleIdentity(filename) {
  const info = findPackageJsonInfo(path.dirname(filename));
  if (info && info.name) {
    const relPath = path.relative(info.pkgDir, filename).replace(/\\/g, '/');
    const version = info.version ? `@${info.version}` : '';
    return `${info.name}${version}:${relPath}`;
  }
  return String(filename).replace(/\\/g, '/');
}

Module.prototype._compile = function (content, filename) {
  // Reset cross-module behavioral state at each new dependency-tree root so that
  // benign modules in one tree cannot poison detection in an unrelated tree.
  if (this.parent === null) {
    detector.behaviorTracker.reset();
  }

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
  const canonicalIdentity = resolveModuleIdentity(filename);
  const packageKey = packageKeyForFilename(filename);

  // Policy lookup precedence (first hit wins, default OBSERVE):
  //   (a) canonical identity "name@version:relPath" — disambiguates packages sharing a basename
  //   (b) package-key form ("@scope/name" or "name") — same rule for every file in a package
  //   (c) bare basename — compat shim so any hand-written basename-keyed policy still resolves
  let configuredRule = 'OBSERVE';
  if (policyMap.has(canonicalIdentity)) {
    configuredRule = policyMap.get(canonicalIdentity);
  } else if (packageKey && policyMap.has(packageKey)) {
    configuredRule = policyMap.get(packageKey);
  } else if (policyMap.has(requestName)) {
    configuredRule = policyMap.get(requestName);
  }

  if (configuredRule === 'BLOCK') {
    const event = { eventType: 'BLOCK', packageName: canonicalIdentity, timestamp: Date.now() };
    auditLog.write(event);
    emitTelemetry('BLOCK', canonicalIdentity, null);
    throw new Error(`[Firewall] Compilation denied for module: "${requestName}"`);
  }

  if (configuredRule === 'QUARANTINE') {
    compileMetrics.quarantined++;
    const event = { eventType: 'QUARANTINE_ACTIVE', packageName: canonicalIdentity, source: 'policy', timestamp: Date.now() };
    auditLog.write(event);
    emitTelemetry('QUARANTINE_ACTIVE', canonicalIdentity, null, { source: 'policy' });
    quarantinedModules.add(filename);
    // Return a stub without executing the module's code
    const stub = new QuarantineStub(requestName, { emit: (t, d) => emitTelemetry(t, canonicalIdentity, null, d) });
    this.exports = stub.createProxy();
    return;
  }

  if (configuredRule === 'OBSERVE') {
    const contentHash = crypto.createHash('sha256').update(content).digest('hex');
    if (verifiedCompilationsCache.get(filename) === contentHash) {
      return originalCompile.apply(this, arguments);
    }

    compileMetrics.filesCompiled++;
    const scanResult = detector.scanModuleSync(requestName, content, filename, packageKey);

    // Split block-tier detections from WARN-only observations. WARN-tier matches (e.g.
    // https.request, buffer.from) and MEDIUM behavioral findings never reach blockDetections:
    // the detector marks anything below HIGH as warnOnly (see detector.js — only CRITICAL/HIGH
    // behavioral violations are pushed as non-warnOnly). So blockDetections holds exactly the
    // HIGH/CRITICAL findings, which hard-block. DYNAMIC_MODULE_LOAD (MEDIUM, require(variable))
    // is intentionally NOT quarantined here — non-literal require() is pervasive in legitimate
    // code (lazy loads, plugin systems, require(path.join(...))), so it surfaces as an OBSERVE
    // telemetry signal only. (F-34: removed a dead `hasMediumOnly` quarantine branch that could
    // never fire because no non-warnOnly MEDIUM detection is ever produced.)
    const blockDetections = scanResult.detections.filter(d => !d.warnOnly);
    const warnDetections  = scanResult.detections.filter(d => d.warnOnly);

    if (warnDetections.length > 0) {
      emitTelemetry('OBSERVE', canonicalIdentity, null, { warnMatches: warnDetections.map(d => d.matched) });
    }

    if (blockDetections.length > 0) {
      compileMetrics.lockdownsEnforced++;
      const event = {
        eventType: 'DETECTION_TRIGGERED',
        packageName: canonicalIdentity,
        detections: blockDetections,
        timestamp: Date.now(),
      };
      auditLog.write(event);
      emitTelemetry('DETECTION_TRIGGERED', canonicalIdentity, null, { detections: blockDetections });

      const msg = `[Firewall] Detection in "${requestName}": ${blockDetections.map(d => d.rule || d.type).join(', ')}`;
      console.error(`\n[COMPILATION LOCKDOWN] Threat detected in "${requestName}"`);
      throw new Error(msg);
    }

    verifiedCompilationsCache.set(filename, contentHash);
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

// Record the active enforcement mode (P0-3) so an operator can audit which guarantee a given
// run actually had — this fires regardless of whether the not-preloaded branch above triggered,
// since a preloaded process is *also* in one mode or the other.
const fwModeEvent = fwMode === 'enforce' ? 'FW_MODE_ENFORCE' : 'FW_MODE_DEV';
auditLog.write({ eventType: fwModeEvent, mode: fwMode, timestamp: Date.now() });
emitTelemetry(fwModeEvent, null, null, { mode: fwMode });

// Export via getter so consumers always see the live map after hot-reload (F-21).
const _exports = { compileMetrics, quarantinedModules, resolveModuleIdentity, packageKeyForFilename };
Object.defineProperty(_exports, 'policyMap', { get: () => policyMap, enumerable: true });
module.exports = _exports;
