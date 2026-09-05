// packages/fw-agent/index.js
const Module = require('module');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Worker } = require('worker_threads');
const { fileURLToPath } = require('url');

// ── F-62: pristine crypto.createHash capture ──────────────────────────────────────────────────
// require('crypto') returns the same cached module object to every caller in the process,
// including any allowed code that runs after this file loads. Every createHash() call below
// participates in a real trust/integrity decision (self-integrity tamper detection, and the
// verified-compilation content-hash cache that decides whether a file gets re-scanned) rather
// than diagnostic output, so a monkeypatch on crypto.createHash installed later by allowed code
// must not be able to defeat them. Captured here, at the very top of the module, before any
// later-loaded code has had a chance to run — a later `crypto.createHash = () => fakeHash`
// mutates the crypto module's OWN property, not this local binding.
const pristineCreateHash = crypto.createHash;

// ── F-82 (PENTEST-003 finding, F-74 follow-on): pristine Object.freeze capture ──────────────────
// getCompileMetrics() (below) returns Object.freeze({...compileMetrics}) as a tamper-proof
// snapshot. Object.freeze is an ambient global exactly like crypto.createHash above: allowed code
// running after this module loads can monkeypatch it to a no-op (`Object.freeze = (x) => x`),
// which silently defeats the snapshot's immutability guarantee -- Object.isFrozen() on the
// returned object then reports false, and it is fully mutable. Confirmed live (PENTEST-003).
// Low impact (compileMetrics is telemetry-only; no enforcement decision reads getCompileMetrics()'s
// return value -- shutdown()/the exit handler read the private, non-exported compileMetrics object
// directly), but it breaks the one guarantee this accessor exists to provide, via the exact same
// ambient-global class of bug F-62/F-71 already established the fix for. Captured here, at the
// very top of the module, before any later-loaded code has a chance to run.
const pristineFreeze = Object.freeze;

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

// P0-4 note: process.execArgv only reflects flags passed literally on the CLI — Node does NOT
// surface NODE_OPTIONS-derived flags there (verified empirically). Since P0-4 re-injects the
// agent into child processes via NODE_OPTIONS, a re-injected child genuinely IS preloaded (Node
// really does --require it before running user code) but would otherwise look "not preloaded"
// to this check and, under FW_STRICT_PRELOAD=1, would incorrectly refuse to start. So this also
// scans NODE_OPTIONS tokens with the exact same resolvesToAgent() check — not a relaxation of
// the guard, since a bogus/unrelated value in NODE_OPTIONS still fails to resolve to this file.
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

  const argsHaveAgentRequire = (args) => {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '--require' || arg === '-r') {
        if (resolvesToAgent(args[i + 1])) return true;
      } else if (arg.startsWith('--require=') || arg.startsWith('-r=')) {
        if (resolvesToAgent(arg.slice(arg.indexOf('=') + 1))) return true;
      }
    }
    return false;
  };

  // Minimal shell-like tokenizer for NODE_OPTIONS (space-separated, double-quoted segments kept
  // intact for paths containing spaces).
  const tokenizeNodeOptions = (str) => {
    const tokens = [];
    const re = /"([^"]*)"|(\S+)/g;
    let m;
    while ((m = re.exec(str))) tokens.push(m[1] !== undefined ? m[1] : m[2]);
    return tokens;
  };

  let isPreloaded = argsHaveAgentRequire(execArgv);
  if (!isPreloaded && process.env.NODE_OPTIONS) {
    isPreloaded = argsHaveAgentRequire(tokenizeNodeOptions(process.env.NODE_OPTIONS));
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
    // aho-corasick.js is the signature-matching engine required by both detector.js and
    // behavior-tracker.js; sync-worker.js is the telemetry worker loaded at runtime. Both ship
    // in the npm manifest and are security-critical, so they must be covered here — omitting
    // them let a tampered aho-corasick silently defeat detection while self-integrity passed.
    path.join(__dirname, 'src', 'aho-corasick.js'),
    // ast-scan.js (Phase 3) is required by detector.js and feeds signal positions directly into
    // detector.js's block-tier decisions — equally security-critical, same reasoning as
    // aho-corasick.js above. This list is duplicated in three other places that must stay in
    // lockstep — see the self-integrity-lockstep test in .agent/scripts/__tests__/.
    path.join(__dirname, 'src', 'ast-scan.js'),
    path.join(__dirname, 'sync-worker.js'),
  ];

  function computeSelfHash() {
    const hash = pristineCreateHash('sha256');
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

// F-6.1 (P1-4): the lifecycle scanner below used to log the full, unmodified script command
// text verbatim -- to both stderr and the persistent audit log. A lifecycle script legitimately
// embedding a credential (a private-registry auth token piped to curl, an inline NPM_TOKEN=...
// env assignment, a Bearer header) had that secret permanently captured on disk and printed to
// the console the moment it happened to also match one of the suspicious-shape patterns below.
// redactSecrets() scrubs known credential SHAPES (never full-command omission, so operators keep
// enough context to understand what was blocked and why) before the command reaches either sink;
// sanitizeScriptForLogging() also bounds the logged length and attaches a SHA-256 of the ORIGINAL
// (pre-redaction) command so an operator can still confirm two log entries are the same script,
// or hash-compare against a known-leaked secret's script, without the raw text ever being
// persisted. This hash has no integrity/trust role (unlike pristineCreateHash's uses elsewhere
// in this file) -- it is a forensic convenience computed before any code from the scanned
// package.json has had a chance to run, so the ambient crypto.createHash binding is fine here.
function redactSecrets(text) {
  return String(text)
    // Authorization header, however it's spelled in a shell command -- consumes an optional
    // "Bearer " prefix as PART of this same match (preserved in the replacement) so it can never
    // overlap with the standalone Bearer rule below and double-process the same token. Value
    // char class excludes quote characters so it stops before a closing '"'/"'" instead of
    // eating it, which would otherwise corrupt the surrounding shell quoting.
    .replace(/Authorization\s*[:=]\s*['"]?(Bearer\s+)?[^\s'"]+/gi, (_m, bearer) => `Authorization: ${bearer ? 'Bearer ' : ''}[REDACTED]`)
    // A bearer token appearing WITHOUT a preceding "Authorization:" (e.g. a custom header name).
    // Idempotent against the rule above: re-matching an already-redacted "Bearer [REDACTED]" just
    // reproduces the same text.
    .replace(/\bBearer\s+[^\s'"]+/gi, 'Bearer [REDACTED]')
    // .npmrc-style and common env-var-style token/password/secret assignments.
    .replace(/(_authToken|_auth|_password|npm_token|api[_-]?key|access[_-]?token|secret|token)\s*[:=]\s*['"]?[^\s'"]+/gi, '$1=[REDACTED]')
    // Basic-auth credentials embedded in a URL (https://user:pass@host/...).
    .replace(/(https?:\/\/[^:@/\s]+):[^@/\s]+@/gi, '$1:[REDACTED]@')
    // curl/wget basic-auth flags (-u user:pass, -uuser:pass, --user user:pass,
    // --user=user:pass) -- a credential passed this way never touches a vendor-prefix or
    // key=value shape, so without this rule it only got redacted if it happened to also match
    // one of the other patterns. Requires the flag be preceded by start-of-string/whitespace so
    // it doesn't misfire inside an unrelated flag that merely contains "-u" (e.g. "--url").
    .replace(/(^|\s)(-u|--user)([= ]?)['"]?([^:\s'"]+):[^\s'"]+/gi, (_m, pre, flag, sep, user) => `${pre}${flag}${sep}${user}:[REDACTED]`)
    // Common vendor token prefixes, redacted even outside a key=value shape.
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g, '[REDACTED-TOKEN]')
    .replace(/\bsk-[A-Za-z0-9]{20,}\b/g, '[REDACTED-TOKEN]')
    .replace(/\bAKIA[A-Z0-9]{12,}\b/g, '[REDACTED-AWS-KEY]')
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/gi, '[REDACTED-SLACK-TOKEN]');
}

const MAX_LOGGED_SCRIPT_LENGTH = 500;

function sanitizeScriptForLogging(cmd) {
  const commandHash = crypto.createHash('sha256').update(cmd).digest('hex');
  const redacted = redactSecrets(cmd);
  const command = redacted.length > MAX_LOGGED_SCRIPT_LENGTH
    ? redacted.slice(0, MAX_LOGGED_SCRIPT_LENGTH) + '…[truncated]'
    : redacted;
  return { command, commandHash };
}

// ── npm lifecycle script scanning ────────────────────────────────────────────────────────────
(function scanNpmLifecycleScripts() {
  const pkgPath = path.join(process.cwd(), 'package.json');
  if (!fs.existsSync(pkgPath)) return;

  // F-6.1: each pattern now carries a detectionCategory so the audit record stays understandable
  // to an operator (what kind of thing tripped this?) without needing the raw command text.
  const SUSPICIOUS_SCRIPT_PATTERNS = [
    { category: 'pipe-to-shell', pattern: /curl\s+.*\|\s*(ba)?sh/i },
    { category: 'pipe-to-shell', pattern: /wget\s+.*\|\s*(ba)?sh/i },
    { category: 'node-download', pattern: /node\s+.*download/i },
    { category: 'python-http', pattern: /python\s+.*http/i },
    { category: 'inline-shell-exec', pattern: /bash\s+-c\s+['"]/i },
    { category: 'shell-eval', pattern: /eval\s*\$/i },
    { category: 'base64-decode', pattern: /base64\s+--decode/i },
  ];

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch (e) { return; }
  if (!pkg.scripts) return;

  for (const [scriptName, cmd] of Object.entries(pkg.scripts)) {
    if (typeof cmd !== 'string') continue;
    const hit = SUSPICIOUS_SCRIPT_PATTERNS.find(({ pattern }) => pattern.test(cmd));
    if (hit) {
      const { command, commandHash } = sanitizeScriptForLogging(cmd);
      console.error(`[HELIOS] Suspicious npm lifecycle script blocked: "${scriptName}" (${hit.category}) = "${command}"`);
      getAuditLog().write({ eventType: 'SUSPICIOUS_SCRIPT', scriptName, detectionCategory: hit.category, command, commandHash });
      if (process.env.HELIOS_BLOCK_SCRIPTS !== '0') {
        process.exit(1);
      }
    }
  }
})();

// ── P0-4: child process + worker re-injection ────────────────────────────────────────────────
// Without this, the firewall only ever protects the process it was loaded into: a spawned
// `node` child (child_process.spawn/exec/execFile) or a worker_threads Worker runs completely
// unhooked, silently escaping detection even though the parent is "protected". child_process
// .fork() is not actually part of this gap in practice — Node defaults fork()'s execArgv to
// process.execArgv, so a forked child already inherits a --require flag the parent was launched
// with — but spawn()/exec()/execFile() only inherit env, not execArgv, and Workers default their
// execArgv to process.execArgv too, which is empty whenever the agent was loaded via NODE_OPTIONS
// or require() rather than a literal --require CLI flag. Two independent mechanisms close this:
//
//   1. NODE_OPTIONS: any node CLI options in this env var are honored by every node process that
//      inherits it, regardless of how it was launched (spawn/exec/execFile/fork, or even a
//      shebang'd `node` script run directly). Appending `--require <agent>` here means "any node
//      process descended from this one, launched any way, preloads the firewall" — for free,
//      with no child_process patching required. Non-node children (spawn('ls'), spawn('python'))
//      are unaffected: they never read NODE_OPTIONS.
//   2. worker_threads: Workers never read NODE_OPTIONS (they're threads in the same process, not
//      a fresh node invocation) and only inherit execArgv when the caller doesn't override it.
//      We wrap the Worker constructor so every file-based Worker gets `--require <agent>`
//      explicitly injected into execArgv, merged with (never replacing) whatever the caller
//      passed. Eval-string workers (`new Worker(code, { eval: true })`) have no file to preload
//      into — left UNSUPPORTED, with a one-time warning.
//
// Mode-aware: whether a propagation failure is a security event (audit + telemetry) or just a
// warning is decided by fwMode (P0-3), now that both branches are merged together.
const AGENT_ABS_PATH = __filename;
let childReinjectionOk = true;
let childReinjectionError = null;

function requireFlagFor(agentPath) {
  // Quote the path if it contains whitespace (spaces in usernames, "Program Files", etc.) so
  // NODE_OPTIONS' shell-like tokenizer treats it as a single argument.
  return /\s/.test(agentPath) ? `--require "${agentPath}"` : `--require ${agentPath}`;
}

function propagateViaNodeOptions(agentPath) {
  const requireFlag = requireFlagFor(agentPath);
  const existing = process.env.NODE_OPTIONS || '';
  // De-dupe: NODE_OPTIONS is inherited across arbitrarily many generations of children. A child
  // that already has our flag (inherited from its parent) must not stack another copy when ITS
  // own agent bootstrap runs this same code again.
  if (existing.includes(requireFlag)) return;
  process.env.NODE_OPTIONS = existing ? `${existing} ${requireFlag}` : requireFlag;
}

function execArgvHasAgentRequire(execArgv, agentPath) {
  if (!Array.isArray(execArgv)) return false;
  for (let i = 0; i < execArgv.length; i++) {
    const arg = execArgv[i];
    if ((arg === '--require' || arg === '-r') && execArgv[i + 1] === agentPath) return true;
    if (arg.startsWith('--require=') && arg.slice('--require='.length) === agentPath) return true;
    if (arg.startsWith('-r=') && arg.slice('-r='.length) === agentPath) return true;
  }
  return false;
}

let warnedEvalWorkerUnsupported = false;

// Built from the ORIGINAL Worker class captured at module load (the `Worker` binding destructured
// at the top of this file, before any patching happens below) — this is what the constructor
// extends, and it is also what the telemetry worker section further down still uses via that
// same top-level `Worker` binding, so the agent's own telemetry worker is never re-preloaded
// into itself.
function buildReinjectingWorkerClass(OriginalWorker, agentPath) {
  return class ReinjectingWorker extends OriginalWorker {
    constructor(filenameOrUrl, options) {
      const opts = options ? Object.assign({}, options) : {};
      if (opts.eval === true) {
        // Cannot preload the agent into an eval-string worker body — there is no file to
        // --require into. UNSUPPORTED, not silently BYPASS: warn once so it's visible.
        if (!warnedEvalWorkerUnsupported) {
          warnedEvalWorkerUnsupported = true;
          console.warn('[Helios] Warning: new Worker(code, { eval: true }) cannot be re-injected with the firewall (no file to preload into). This worker runs UNPROTECTED.');
        }
        super(filenameOrUrl, options);
        return;
      }
      const execArgv = Array.isArray(opts.execArgv) ? opts.execArgv.slice() : (process.execArgv || []).slice();
      if (!execArgvHasAgentRequire(execArgv, agentPath)) {
        execArgv.push('--require', agentPath);
      }
      opts.execArgv = execArgv;
      super(filenameOrUrl, opts);
    }
  };
}

try {
  propagateViaNodeOptions(AGENT_ABS_PATH);
} catch (e) {
  childReinjectionOk = false;
  childReinjectionError = e;
}

try {
  const workerThreadsModule = require('worker_threads');
  workerThreadsModule.Worker = buildReinjectingWorkerClass(workerThreadsModule.Worker, AGENT_ABS_PATH);
} catch (e) {
  childReinjectionOk = false;
  childReinjectionError = childReinjectionError || e;
}

// ── Telemetry worker thread ───────────────────────────────────────────────────────────────────
const telemetryEnabled = process.env.FW_TELEMETRY === '1';
const telemetryWorkerPath = path.join(__dirname, 'sync-worker.js');
// Mutable: F-21.1/F-21.2 degrade this to null on construction failure or a later worker crash.
// Telemetry is optional/best-effort observability, never an enforcement mechanism — nothing in
// the block/quarantine/lockdown decision path reads this, so degrading it never weakens
// enforcement, only observability.
let telemetryWorker = null;

// ── Audit log (persistent) ────────────────────────────────────────────────────────────────────
const auditLog = getAuditLog();

// F-21.1/F-21.2: telemetry construction failure or a later async worker crash must degrade
// telemetry, not the protected host. Logs (once — never spammed on repeated failures) and audits,
// then leaves telemetryWorker null so emitTelemetry() below silently no-ops from then on.
let telemetryDegradedLogged = false;
function degradeTelemetry(reason, err) {
  const worker = telemetryWorker;
  telemetryWorker = null;
  if (worker) {
    // worker.terminate() returns a Promise (rejects if the worker is already dead/mid-teardown);
    // an unhandled rejection here would itself crash the process -- the exact hazard this whole
    // function exists to close. try/catch alone only covers a synchronous throw.
    try {
      const result = worker.terminate();
      if (result && typeof result.catch === 'function') result.catch(() => {});
    } catch (e) { /* already dead; nothing to clean up */ }
  }
  if (telemetryDegradedLogged) return;
  telemetryDegradedLogged = true;
  console.warn(`[Firewall] Telemetry worker ${reason} — continuing without telemetry (enforcement unaffected).${err ? ' ' + err.message : ''}`);
  try {
    auditLog.write({ eventType: 'TELEMETRY_DEGRADED', timestamp: Date.now(), reason, error: err ? err.message : null });
  } catch (e) {
    // Never let a forensic-logging failure cascade into a second crash.
  }
}

if (telemetryEnabled) {
  try {
    // Uses the top-level `Worker` binding captured before the patch above ran — the agent's own
    // telemetry worker must never be re-injected with a fresh copy of the agent.
    const w = new Worker(telemetryWorkerPath);
    w.unref();
    // F-21.2: an uncaught exception inside the worker thread surfaces here as an 'error' event.
    // Without a listener attached, Node treats a Worker 'error' as fatal to the *parent* process
    // (an EventEmitter 'error' with no listener throws) — a telemetry-only failure must never take
    // the protected host down with it.
    w.on('error', (err) => degradeTelemetry('crashed', err));
    telemetryWorker = w;
  } catch (err) {
    // F-21.1: synchronous Worker construction can itself throw (resource exhaustion, missing
    // worker file, sandboxing/permission errors, etc.) — telemetry is optional/best-effort and
    // must never take down the protected host on startup.
    degradeTelemetry('failed to start', err);
  }
}

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
  try {
    telemetryWorker.postMessage({
      type: 'TELEMETRY_EVENT',
      payload: { eventType, packageName, parentPackage, timestamp: Date.now(), ...metadata },
    });
  } catch (err) {
    // F-21.1/F-21.2 defense-in-depth: postMessage() can itself throw (e.g. a terminated worker).
    // emitTelemetry() is called from the hot enforcement path (_compile, ESM hooks) — a telemetry
    // failure here must degrade telemetry, never propagate into and crash that path.
    degradeTelemetry('failed', err);
  }
}

// ── Compilation metrics ───────────────────────────────────────────────────────────────────────
const compileMetrics = { filesCompiled: 0, lockdownsEnforced: 0, quarantined: 0 };
// Cache keyed by filename → SHA-256 of content (not filename alone).
// Re-scans the file if its content changed between require() calls in a long-lived process.
const verifiedCompilationsCache = new Map();
const quarantinedModules = new Set();
// F-58: absolute paths the firewall's OWN _compile/ESM-load hooks have reached a definitive,
// non-throwing outcome for. See the Module._load wrap below — this is what distinguishes a
// legitimate require.cache hit from an entry the firewall never saw.
const verifiedModulePaths = new Set();

// ── Core module interception hook ─────────────────────────────────────────────────────────────
const originalCompile = Module.prototype._compile;

// Shared by packageKeyForFilename() and the install-identity check below: given a normalized
// ('/'-separated) path, returns the package name owning its LAST node_modules segment — nested
// node_modules is naturally resolved correctly since lastIndexOf finds the one closest to the
// leaf, i.e. the actual installed package, not some ancestor's private copy of a dependency — or
// null if the path is not under any node_modules directory at all.
function packageNameFromNodeModulesPath(norm) {
  const idx = norm.lastIndexOf('/node_modules/');
  if (idx === -1) return null;
  const rest = norm.slice(idx + '/node_modules/'.length).split('/');
  if (rest[0] && rest[0][0] === '@') {
    // A scope directory with no package segment underneath it (e.g. the path ends at
    // ".../node_modules/@scope") is not a real installed package — reporting "@scope/" would be a
    // malformed identity, so treat it as "not a package" (null) rather than a real name.
    return rest[1] ? rest[0] + '/' + rest[1] : null;
  }
  return rest[0] || null;
}

// Derive the npm-package key for a filename so cross-file correlation stays scoped to ONE
// package. The behavioral tracker is reset per dependency-tree root (below), which spans the
// whole app — without this scoping, cross-file rules would pair a config-reading module with any
// unrelated http module in the tree and false-positive. Returns null for first-party app code
// (no node_modules segment): the developer's own files reading config and making network calls
// across files is normal, not the split-attack threat model, so cross-file is skipped for them.
function packageKeyForFilename(filename) {
  return packageNameFromNodeModulesPath(String(filename).replace(/\\/g, '/'));
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
const packageJsonCache = new Map(); // dir -> { name, version, pkgDir, installName } | null

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
      const name = typeof pkg.name === 'string' ? pkg.name : null;
      // F-1.2 (P0-2): the name a package installed under node_modules claims for itself in its
      // OWN package.json is attacker-controlled — a malicious dependency can self-report a
      // trusted package's name to try to outrank the filesystem-derived identity that policy
      // (BLOCK/QUARANTINE) rules are keyed on. installName is derived purely from *where npm put
      // it on disk*, which the package's own manifest cannot influence, and is the required
      // invariant: filesystem/install identity must not be overridden merely because the package
      // claims another name.
      const installName = packageNameFromNodeModulesPath(String(dir).replace(/\\/g, '/'));
      if (installName && name && installName !== name) {
        // Best-effort forensic signal, not an enforcement decision by itself — resolveModuleIdentity()
        // below already refuses to trust the claimed name regardless of whether this fires.
        try {
          auditLog.write({
            eventType: 'PACKAGE_IDENTITY_MISMATCH',
            timestamp: Date.now(),
            installName,
            claimedName: name,
            pkgDir: dir,
          });
          emitTelemetry('PACKAGE_IDENTITY_MISMATCH', installName, null, { claimedName: name });
        } catch (e) {
          // Never let a forensic-logging failure break module resolution.
        }
      }
      result = { name, version: typeof pkg.version === 'string' ? pkg.version : null, pkgDir: dir, installName };
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
//
// F-1.2 (P0-2): the identity's *name* component is the filesystem/install-derived name
// (info.installName) whenever one is available, never the package's own self-reported
// package.json `name` — otherwise a malicious package could spoof a trusted package's name in
// its manifest to dodge a BLOCK/QUARANTINE rule keyed on its real, installed identity, or to
// piggyback on an unrelated rule scoped to the name it claims. First-party app code and packages
// resolved outside any node_modules tree (installName is null — e.g. an npm-workspace symlink
// Node has already resolved to its real, non-node_modules path) have no install identity to
// defer to, so the manifest name is used as before.
function resolveModuleIdentity(filename) {
  const info = findPackageJsonInfo(path.dirname(filename));
  if (info && (info.installName || info.name)) {
    const relPath = path.relative(info.pkgDir, filename).replace(/\\/g, '/');
    const version = info.version ? `@${info.version}` : '';
    const name = info.installName || info.name;
    return `${name}${version}:${relPath}`;
  }
  return String(filename).replace(/\\/g, '/');
}

// F-1.2 follow-up (npm aliases): an alias install (`"my-react": "npm:react@18.0.0"` in the
// CONSUMING project's own package.json — npm docs: "package-spec#aliases") legitimately installs
// a package under a folder name that differs from its own registry-published package.json `name`.
// Unlike spoofing, the alias is chosen by the trusted consuming project, not by the dependency
// itself, so an operator rule keyed on the package's true, manifest-declared identity (e.g.
// "react@18.0.0:index.js") must keep applying to an aliased install. resolveModulePolicy() below
// uses this only to ESCALATE a verdict, never to de-escalate one — so it can restore a rule an
// alias would otherwise dodge, without reopening the F-1.2 spoofing bypass this file just closed.
function resolveManifestIdentity(filename) {
  const info = findPackageJsonInfo(path.dirname(filename));
  if (info && info.name) {
    const relPath = path.relative(info.pkgDir, filename).replace(/\\/g, '/');
    const version = info.version ? `@${info.version}` : '';
    return `${info.name}${version}:${relPath}`;
  }
  return null;
}

const RULE_SEVERITY = { BLOCK: 3, QUARANTINE: 2, OBSERVE: 1 };
function moreRestrictiveRule(a, b) {
  return (RULE_SEVERITY[b] || 0) > (RULE_SEVERITY[a] || 0) ? b : a;
}

// ── F-79: shared scan-and-policy core (CJS _compile, ESM load, ESM-interop-CJS) ────────────────
// One implementation for all three so the hook sites cannot drift (the engine-sync discipline).
// resolveModulePolicy() does the identical policy lookup; scanModuleAndEnforce() does the identical
// OBSERVE-tier detector scan and the identical detection-triggered throw. The callers keep only
// their path-specific actions (CJS's silent stub, ESM's throw, plain compile/return), which
// genuinely differ.
function resolveModulePolicy(filename) {
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

  // npm-alias follow-up to F-1.2: escalate-only check against the package's manifest-declared
  // (registry) identity when it differs from the install-derived one above. Never de-escalates —
  // that would reopen the exact spoofing bypass F-1.2 closed — but a rule an operator pinned on
  // the package's TRUE name (e.g. an alias's registry name) must still apply to it.
  const manifestIdentity = resolveManifestIdentity(filename);
  if (manifestIdentity && manifestIdentity !== canonicalIdentity && policyMap.has(manifestIdentity)) {
    configuredRule = moreRestrictiveRule(configuredRule, policyMap.get(manifestIdentity));
  }

  return { requestName, canonicalIdentity, packageKey, configuredRule };
}

// Runs the OBSERVE-tier detector scan on `source` and enforces block-tier findings by throwing the
// identical compilation-lockdown error both hooks use (`esm` only tags the audit/telemetry event).
// Honors the per-content verified-hash cache: on identical, already-scanned content it returns
// without re-scanning or re-counting; on a fresh clean scan it records the content hash. It never
// touches verifiedModulePaths — the CALLER adds that on its non-throwing return, exactly as before,
// because "verified" means "this specific hook reached a definitive non-throwing outcome".
function scanModuleAndEnforce(filename, source, meta, esm) {
  const { requestName, canonicalIdentity, packageKey } = meta;
  const contentHash = pristineCreateHash('sha256').update(source).digest('hex');
  if (verifiedCompilationsCache.get(filename) === contentHash) return;

  compileMetrics.filesCompiled++;
  const scanResult = detector.scanModuleSync(requestName, source, filename, packageKey);
  // WARN-tier and MEDIUM findings are marked warnOnly by the detector and never hard-block; only
  // CRITICAL/HIGH reach blockDetections. See detector.js and the removed F-34 dead branch.
  const blockDetections = scanResult.detections.filter((d) => !d.warnOnly);
  const warnDetections = scanResult.detections.filter((d) => d.warnOnly);

  if (warnDetections.length > 0) {
    emitTelemetry('OBSERVE', canonicalIdentity, null, { warnMatches: warnDetections.map((d) => d.matched) });
  }

  if (blockDetections.length > 0) {
    compileMetrics.lockdownsEnforced++;
    const event = { eventType: 'DETECTION_TRIGGERED', packageName: canonicalIdentity, detections: blockDetections, timestamp: Date.now() };
    if (esm) event.esm = true;
    auditLog.write(event);
    emitTelemetry('DETECTION_TRIGGERED', canonicalIdentity, null, { detections: blockDetections });

    const msg = `[Firewall] Detection in "${requestName}": ${blockDetections.map((d) => d.rule || d.type).join(', ')}`;
    console.error(`\n[COMPILATION LOCKDOWN] Threat detected in "${requestName}"`);
    throw new Error(msg);
  }

  verifiedCompilationsCache.set(filename, contentHash);
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

  const { requestName, canonicalIdentity, packageKey, configuredRule } = resolveModulePolicy(filename);

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
    // F-58: this was a deliberate, definitive decision by our own hook -- verified.
    verifiedModulePaths.add(filename);
    return;
  }

  if (configuredRule === 'OBSERVE') {
    // Shared scan-and-enforce (identical for CJS/ESM/ESM-interop-CJS): throws on a block-tier
    // detection, no-ops on an already-verified identical-content cache hit, records the hash
    // otherwise. DYNAMIC_MODULE_LOAD (MEDIUM, require(variable)) is warnOnly and never blocks here.
    scanModuleAndEnforce(filename, content, { requestName, canonicalIdentity, packageKey }, false);
  }

  // F-58: reached only on a definitive, non-throwing outcome (OBSERVE-pass, or an unrecognized
  // policy value falling through to plain compilation) -- verified.
  verifiedModulePaths.add(filename);
  return originalCompile.apply(this, arguments);
};

// ── F-58: Module._load / require.cache pre-seeding enforcement ──────────────────────────────
// Module._load() -- the actual require() entry point -- checks Module._cache[resolvedPath]
// BEFORE Module.prototype._compile (patched above) ever runs. Confirmed live, pre-fix: allowed
// code constructs a Module (or even a bare `{ exports }` object -- Node's cache-hit path only
// reads `.loaded`/`.exports` off whatever is there, it never requires a real Module instance)
// and inserts it directly into require.cache[resolvedPath]; require() returns the forged
// exports, the target's real code never executes, and compileMetrics.filesCompiled never
// increments -- the _compile hook never sees the file at all.
//
// Three-state model, not binary verified/not-verified:
//   VERIFIED -- resolvedPath is in verifiedModulePaths, populated only by this file's own
//     _compile/ESM-load hooks above reaching a definitive, non-throwing outcome. Allow.
//   UNKNOWN  -- a require.cache entry exists for this path, but the firewall never verified it.
//     Could be legitimate cache pre-seeding (test-mocking/HMR tooling) or an attack -- cache
//     state alone cannot distinguish these. Policy-controlled via FW_CACHE_POLICY below. This is
//     also where a SYNTHETIC entry with no real module body (require.cache[t] = { exports: x },
//     nothing to _compile at all) gets caught -- the check happens at the cache-hit point,
//     before anything assumes there is source to scan.
//   BLOCKED  -- explicit policy decision (FW_CACHE_POLICY=block) to refuse.
//
// Deliberately does NOT delete-and-reload an unverified cache entry. That was considered and
// rejected: deletion risks double-execution if the entry was created by already-scanned code
// for a legitimate reason, and risks an infinite loop if the reload path re-consults the same
// cache state before this bookkeeping updates. Detect-and-decide, never detect-and-silently-fix.
//
// Scoped to .js/.cjs only -- the two extensions Module.prototype._compile actually handles
// (confirmed empirically: .json and .node route through their own Module._extensions handlers
// and never call _compile, so there is nothing for a cache entry to have bypassed for them; a
// package legitimately require()-ing the same config.json twice must not be treated as
// cache-substitution). Every other extension keeps its pre-existing, ungated cache behavior.
const CACHE_GATED_EXTENSIONS = new Set(['.js', '.cjs']);

function resolveCachePolicy() {
  const raw = (process.env.FW_CACHE_POLICY || '').toLowerCase();
  if (raw === 'block' || raw === 'audit' || raw === 'allow') return raw;
  // Same enforce/dev split used throughout this file (P0-3's fwMode): fail closed by default
  // only once the operator has opted into FW_MODE=enforce. Left at the dev-mode default,
  // 'audit' (not 'block') keeps legitimate cache-pre-seeding tooling (test mocks, HMR) working
  // out of the box while still making every occurrence visible, rather than breaking dev/test
  // workflows on first contact with this feature.
  return fwMode === 'enforce' ? 'block' : 'audit';
}

// This file's OWN require() chain (Module, path, fs, crypto, worker_threads, url, and every
// ./src/* dependency required above) already populated Module._cache before this patch had a
// chance to install -- Node compiled all of them via the ORIGINAL, unpatched _compile, so
// verifiedModulePaths never saw them. Without this seed, the very next require() of any of
// those same paths (trivially: a test or an app requiring this agent module a second time) would
// look exactly like an UNKNOWN cache entry and get gated. Snapshot everything already cached at
// patch-install time as implicitly trusted: it was loaded through Node's normal pipeline before
// this firewall began watching, which is the agent's own bootstrap chain, not attacker-reachable
// code -- the same trust boundary FW_MODE=dev's disclosed "loaded before this point is NOT
// protected" gap already describes for the pre-preload window in general.
for (const cachedPath of Object.keys(Module._cache)) {
  verifiedModulePaths.add(cachedPath);
}

// F-70 scope (disclosure, see SECURITY.md): this wrap closes require.cache PRE-SEEDING that
// bypasses the scan path. It does NOT close reassignment of the loader functions themselves --
// `Module._load` (this very property), `Module.prototype._compile`, and `module.registerHooks()`
// are all writable/installable by same-privilege code running after this patch, which can capture
// the wrapped version and install a replacement that skips the check. Freezing them is neither
// cheap nor low-risk (it recreates the opt-in `_compile`-freeze compatibility problem) and does
// not escape the same-privilege domain. That is the same-process ceiling, not a closable gap.
const originalModuleLoad = Module._load;
Module._load = function (request, parent, isMain) {
  let resolvedPath;
  try {
    resolvedPath = Module._resolveFilename(request, parent, isMain);
  } catch (e) {
    // Unresolvable (a core module like 'fs', or a genuine resolution failure) -- core modules
    // never populate Module._cache in the first place, so there is nothing to cache-check; defer
    // entirely to the original behavior (including its own, unmodified resolution error).
    return originalModuleLoad.apply(this, arguments);
  }

  if (CACHE_GATED_EXTENSIONS.has(path.extname(resolvedPath))) {
    const cacheEntry = Module._cache[resolvedPath];
    if (cacheEntry !== undefined && !verifiedModulePaths.has(resolvedPath)) {
      const policy = resolveCachePolicy();
      const event = {
        eventType: 'CACHE_SUBSTITUTION_DETECTED',
        path: resolvedPath,
        request: String(request),
        origin: (parent && parent.filename) || null,
        policy,
        timestamp: Date.now(),
      };

      if (policy === 'block') {
        auditLog.write(Object.assign({ action: 'BLOCK' }, event));
        emitTelemetry('CACHE_SUBSTITUTION_BLOCKED', resolvedPath, (parent && parent.filename) || null, { request: String(request) });
        throw new Error(
          `[Firewall] Refused to load "${request}" (resolved: "${resolvedPath}") from an ` +
          `unverified require.cache entry (possible cache-substitution attack -- this path was ` +
          `never scanned by _compile). Set FW_CACHE_POLICY=audit or FW_CACHE_POLICY=allow if ` +
          `this is expected (e.g. test-mocking or HMR pre-seeding the cache).`
        );
      }

      if (policy === 'audit') {
        auditLog.write(Object.assign({ action: 'AUDIT_ALLOW' }, event));
        emitTelemetry('CACHE_SUBSTITUTION_AUDITED', resolvedPath, (parent && parent.filename) || null, { request: String(request) });
        console.warn(
          `\n[Helios] AUDIT: unverified require.cache entry for "${resolvedPath}" was allowed ` +
          `(FW_CACHE_POLICY=audit). This load bypassed _compile scanning. Set FW_CACHE_POLICY=block ` +
          `to refuse these, or FW_CACHE_POLICY=allow to silence this warning.`
        );
      } else {
        // policy === 'allow' -- least-safe, silent, documented opt-in only. Still audited to
        // disk (never silent in the persistent log), just not to the console.
        auditLog.write(Object.assign({ action: 'ALLOW' }, event));
      }
    }
  }

  return originalModuleLoad.apply(this, arguments);
};

// ── Narrow _compile freeze (opt-in via FW_HARDEN_MODULE_PRIMITIVES=1) ──────────────────────────
// Freezes Module.prototype._compile to the (already-patched, by this point) function value
// currently installed, raising the cost of the classic "monkeypatch Module.prototype._compile to
// something else" bypass specifically. Complementary to, not a substitute for, the Module._load
// hardening above: this does nothing against require.cache poisoning (F-58's target), which never
// touches _compile at all -- a cache-substitution attack returns before _compile would ever run.
//
// Default-on was considered and rejected, matching FW_FREEZE_PROTOTYPES' existing opt-in posture
// for the same class of change (see primitiveLockdown() above): freezing a foundational Node
// internal can break loaders, instrumentation agents, and some test frameworks that legitimately
// re-patch _compile (source-map support, coverage instrumentation, ts-node-style transpilers).
// Even without throwing, silently changing this mutability is a real compatibility risk a
// try/catch around the freeze call does not address -- making a narrower version of this same
// hardening default-on while the broader FW_FREEZE_PROTOTYPES stays opt-in would be inconsistent
// with this project's own established risk posture for this exact class of change.
(function freezeCompilePrimitive() {
  if (process.env.FW_HARDEN_MODULE_PRIMITIVES !== '1') return;
  try {
    Object.defineProperty(Module.prototype, '_compile', {
      value: Module.prototype._compile,
      writable: false,
      configurable: false,
    });
  } catch (_) {}
})();

// ── P2-01: ESM static/dynamic import interception ────────────────────────────────────────────
// Module.prototype._compile (above) is never invoked for ES module evaluation — Node's ESM
// loader is an entirely separate pipeline. module.registerHooks() (the SYNCHRONOUS Module
// Customization Hooks variant, added in Node 22.15.0 / 23.5.0) intercepts ESM source before
// evaluation via a `load` hook that runs on THIS SAME MAIN THREAD — unlike the older, now
// Stability-0-Deprecated module.register() (which runs its hooks off-thread), this reuses the
// exact same `detector`, `policyMap`, `verifiedCompilationsCache`, `auditLog`, and
// `emitTelemetry` the CJS path above uses directly, rather than needing a separate detector
// instance with separate, disconnected state. On Node versions without registerHooks() (older
// than the 22.15.0/23.5.0 floor), ESM stays an architecturally UNSUPPORTED bypass — not silently
// claimed as protected. fw-agent's declared package floor (>=18.0.0) covers its CJS
// functionality; ESM protection specifically requires the newer floor — see README's coverage
// table for the honest breakdown, not a blanket "ESM protected" claim.
//
// KNOWN LIMITATIONS (disclosed, not hidden):
//   - QUARANTINE has no ESM equivalent to CJS's `this.exports = stub` silent substitution — there
//     is no live module object to swap mid-evaluation from inside a `load` hook. An ESM module
//     policy-configured to QUARANTINE is treated as BLOCK instead: it still never runs, it just
//     doesn't get the silent-stub-with-a-fake-export treatment CJS QUARANTINE does.
//   - _compile's per-dependency-tree behaviorTracker reset (`this.parent === null`, above) has no
//     equivalent signal available inside a `load` hook — ESM module evaluation doesn't expose an
//     "is this a tree root" concept the way `this.parent` does for CJS. Cross-file behavioral
//     state is only ever reset when a CJS root triggers the reset above; this can only make
//     ESM-involving correlation MORE conservative over a process's lifetime, never silently miss
//     a detection it would otherwise have made.
let esmHookOk = true;
let esmHookError = null;
if (typeof Module.registerHooks === 'function') {
  try {
    Module.registerHooks({
      load(url, context, nextLoad) {
        const result = nextLoad(url, context);

        // F-79: scan BOTH real ES modules ('module') AND CommonJS loaded THROUGH the ESM loader
        // ('commonjs' -- Node's `import x from "some-cjs-package"` CJS-through-ESM interop). The
        // interop populates Module._cache as a side effect but NEVER calls Module.prototype._compile,
        // so this load hook is the only place the interop-CJS source is ever seen. Skipping it (the
        // old `format !== 'module'` early return) had two consequences, both closed here:
        //   1. Detection gap: a genuinely malicious CJS module imported via ESM ran UNSCANNED (it
        //      was blocked via require() but ran free via import). Marking it "verified" without
        //      scanning -- the naive fix -- would cement that gap, so we SCAN, then mark verified.
        //   2. False positive: because the interop path never added the file to verifiedModulePaths,
        //      the later require() of that same CJS package (vite/astro reference picomatch as both
        //      `import pm from "picomatch"` and `__require("picomatch")`) hit F-58's cache gate as an
        //      "unverified" entry and was refused under FW_CACHE_POLICY=block. Scanning here marks it
        //      verified, so the subsequent require() is a clean verified cache hit.
        // Formats with no scannable source (builtins, JSON, wasm, or source absent) keep their
        // existing pass-through. Interop-CJS does provide result.source (a Buffer) -- confirmed live.
        const scannable = result.format === 'module' || result.format === 'commonjs';
        if (!scannable || typeof result.source === 'undefined' || result.source === null) {
          return result;
        }
        if (!url.startsWith('file://')) {
          return result;
        }

        if (emergencyLockdown) {
          throw new Error('[Firewall] Emergency lockdown active. All module loads blocked.');
        }

        const filename = fileURLToPath(url);
        const meta = resolveModulePolicy(filename);
        const { requestName, canonicalIdentity, configuredRule } = meta;

        if (configuredRule === 'BLOCK' || configuredRule === 'QUARANTINE') {
          // A load hook cannot do CJS's silent stub substitution, so QUARANTINE degrades to BLOCK
          // here (see KNOWN LIMITATIONS above) -- for real ESM and for interop-CJS alike.
          const eventType = configuredRule === 'BLOCK' ? 'BLOCK' : 'QUARANTINE_ACTIVE';
          const event = { eventType, packageName: canonicalIdentity, timestamp: Date.now(), esm: true };
          auditLog.write(event);
          emitTelemetry(eventType, canonicalIdentity, null, configuredRule === 'QUARANTINE' ? { source: 'policy', esmDegradedToBlock: true } : {});
          throw new Error(`[Firewall] Compilation denied for module: "${requestName}"`);
        }

        const source = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8');
        // Same scan-and-enforce path as CJS _compile (esm=true only tags the audit event); throws
        // on a block-tier detection, no-ops on a verified identical-content cache hit.
        scanModuleAndEnforce(filename, source, meta, true);
        verifiedModulePaths.add(filename);
        return result;
      },
    });
  } catch (e) {
    esmHookOk = false;
    esmHookError = e;
  }
} else {
  esmHookOk = false;
  esmHookError = new Error(`module.registerHooks() unavailable on Node ${process.version} (requires >=22.15.0 or >=23.5.0)`);
}

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

// Report the outcome of P0-4 child/worker re-injection now that auditLog + emitTelemetry exist.
// Reuses fwMode (P0-3) rather than FW_STRICT_PRELOAD directly, now that both branches are merged
// together — FW_MODE=enforce and FW_STRICT_PRELOAD=1 are both already folded into fwMode.
if (!childReinjectionOk) {
  const message = `Failed to set up child/worker re-injection (NODE_OPTIONS propagation and/or Worker patch): ${childReinjectionError && childReinjectionError.message}`;
  if (fwMode === 'enforce') {
    auditLog.write({ eventType: 'CHILD_REINJECTION_FAILURE', message, timestamp: Date.now() });
    emitTelemetry('CHILD_REINJECTION_FAILURE', null, null, { message });
    console.error(`[CRITICAL] [Helios] ${message}`);
  } else {
    console.warn(`[Helios] Warning: ${message}. Children/workers spawned from this process may run unprotected.`);
  }
}

// Report the outcome of P2-01 ESM hook registration, same enforce/dev split as P0-4 above: on an
// unsupported Node version or a registration failure, ESM stays an honest, documented bypass
// rather than a silently-broken guarantee.
if (!esmHookOk) {
  const message = `ESM static/dynamic import interception not active: ${esmHookError && esmHookError.message}. CommonJS require() coverage is unaffected.`;
  // FW_REQUIRE_ESM_COVERAGE=1 is a separate, more specific assertion than FW_MODE=enforce: "I
  // require ESM coverage specifically," not just "I require the agent to be preloaded." A
  // deployer who genuinely depends on ESM interception can opt into failing closed even in dev
  // mode; leaving the flag unset (the default) keeps behavior byte-identical to before.
  if (process.env.FW_REQUIRE_ESM_COVERAGE === '1') {
    auditLog.write({ eventType: 'ESM_HOOK_UNAVAILABLE', message, timestamp: Date.now() });
    emitTelemetry('ESM_HOOK_UNAVAILABLE', null, null, { message });
    console.error(`[CRITICAL] [Helios] ${message} FW_REQUIRE_ESM_COVERAGE=1 is set. Refusing to start.`);
    process.exit(1);
  } else if (fwMode === 'enforce') {
    auditLog.write({ eventType: 'ESM_HOOK_UNAVAILABLE', message, timestamp: Date.now() });
    emitTelemetry('ESM_HOOK_UNAVAILABLE', null, null, { message });
    console.error(`[CRITICAL] [Helios] ${message}`);
  } else {
    console.warn(`[Helios] Warning: ${message}. ESM modules loaded via import/import() in this process run unprotected.`);
  }
}

// ── F-57: read-only policy/quarantine query surface ──────────────────────────────────────────
// policyMap and quarantinedModules used to be exported directly (policyMap via a getter, so
// reassignment was blocked, but the live Map object itself was still handed out; quarantinedModules
// as a plain property export of the live Set). Either one let any allowed code call
// `.set()`/`.delete()`/`.clear()`/`.add()` on the REAL object and mutate live enforcement state.
// Only these read-only query functions are exported now — none of them returns the live
// Map/Set or an iterable view of it.
function hasPolicy(key) {
  return policyMap.has(key);
}

function getPolicyDecision(key) {
  if (!policyMap.has(key)) return undefined;
  const value = policyMap.get(key);
  // Policy values are strings today ('BLOCK'/'OBSERVE'/'QUARANTINE'), but if a value is ever an
  // object, hand back a frozen deep copy rather than the live reference.
  if (value !== null && typeof value === 'object') {
    return Object.freeze(JSON.parse(JSON.stringify(value)));
  }
  return value;
}

function isQuarantined(filename) {
  return quarantinedModules.has(filename);
}

// ── F-74: compileMetrics read-only accessor ──────────────────────────────────────────────────
// compileMetrics was exported as the live mutable object — the same shape F-57 fixed for
// policyMap/quarantinedModules. It's telemetry only (no enforcement branch reads it, so mutating
// it is not a security bypass), but any allowed code could do `fw.compileMetrics.filesCompiled = 0`
// and corrupt the monitoring/shutdown summary the operator relies on. Same treatment: export a
// read-only accessor, not the live object. compileMetrics is flat (all-number counters), so a
// frozen shallow copy is a complete, tamper-proof snapshot; each call returns a fresh frozen copy
// reflecting the counters at call time. Uses pristineFreeze (F-82 above) so a post-load
// monkeypatch of the global Object.freeze cannot defeat the snapshot's immutability.
function getCompileMetrics() {
  return pristineFreeze({ ...compileMetrics });
}

const _exports = { getCompileMetrics, resolveModuleIdentity, packageKeyForFilename, hasPolicy, getPolicyDecision, isQuarantined };
module.exports = _exports;
