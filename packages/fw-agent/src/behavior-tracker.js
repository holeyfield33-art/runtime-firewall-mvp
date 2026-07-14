// packages/fw-agent/src/behavior-tracker.js
// Behavioral analyzer for sequence-based threat detection.
// Tracks dangerous action sequences within a single module.

// Signal detection patterns for each behavioral category
const SIGNAL_PATTERNS = {
  // Reads sensitive credential files (fs-based). process.env is tracked separately
  // via ENV_READ to avoid false-positive CREDENTIAL_EXFILTRATION on normal HTTP libraries.
  SENSITIVE_READ: [
    /fs\s*\.\s*readFile/,
    /fs\s*\.\s*readFileSync/,
    /fs\s*\.\s*open(?:Sync)?\s*\(/,
  ],
  // Bare environment variable access — common in normal apps; escalates to WARN only
  // unless a SENSITIVE_PATH is also present (genuine credential file access).
  ENV_READ: [
    /process\s*\.\s*env\b/,
  ],
  SENSITIVE_PATH: [
    /\.npmrc/i,
    // Match .env only as a file-path reference (preceded by quote, slash, or backtick),
    // not as a property access like `process.env.FOO` (F-16 false-positive fix).
    /['"\/`]\.env\b/i,
    /credentials/i,
    /\.ssh\b/,
    /id_rsa/,
    /\.netrc/,
    /\.aws\b/,
    /secret/i,
    /passwd/i,
    /shadow/i,
  ],
  // Makes outbound network connections
  NETWORK_EGRESS: [
    /http\s*\.\s*request\s*\(/,
    /https\s*\.\s*request\s*\(/,
    /http\s*\.\s*get\s*\(/,
    /https\s*\.\s*get\s*\(/,
    /\bfetch\s*\(/,
    /net\s*\.\s*connect\s*\(/,
    /net\s*\.\s*createConnection\s*\(/,
    /socket\s*\.\s*connect\s*\(/,
    /new\s+WebSocket\s*\(/,
    /XMLHttpRequest/,
    /tls\s*\.\s*connect\s*\(/,
    /dgram\s*\.\s*createSocket/,
    // Inline require("https").get/request — not caught by the patterns above
    /require\s*\(\s*['"]https?['"]\s*\)\s*\.\s*(?:get|request)\s*\(/,
  ],
  // Generates or evaluates code at runtime
  DYNAMIC_CODE: [
    /\beval\s*\(/,
    /new\s+Function\s*\(/,
    /\bFunction\s*\(\s*['"`]/,
    /vm\s*\.\s*runIn(?:This|New|)Context\s*\(/,
    /vm\s*\.\s*Script\s*\(/,
    /\bsetTimeout\s*\(\s*['"`]/,
    /\bsetInterval\s*\(\s*['"`]/,
    /Script\s*\.\s*runInNewContext/,
  ],
  // Executes external processes
  PROCESS_EXEC: [
    /child_process/,
    /\bexecSync\s*\(/,
    /\bspawnSync\s*\(/,
    /\bexecFile\s*\(/,
    /\bexecFileSync\s*\(/,
    /ShellString/,
  ],
  // Loads modules dynamically or via non-literal paths
  DYNAMIC_REQUIRE: [
    /require\s*\.\s*resolve\s*\(/,
    /module\s*\._load\s*\(/,
    /require\s*\(\s*(?!['"`])[^)]+\)/,  // require(variable)
  ],
};

function matchesAny(content, patterns) {
  return patterns.some(p => p.test(content));
}

class BehaviorTracker {
  constructor() {
    // Per-module signal cache
    this.moduleSignals = new Map();
    // Accumulated violations for telemetry
    this.violations = [];
  }

  /**
   * Analyze a module and return any behavioral violations found.
   * Checks intra-module signal sequences.
   */
  analyzeModule(filename, content) {
    if (!content) return [];

    const signals = {
      sensitiveRead: matchesAny(content, SIGNAL_PATTERNS.SENSITIVE_READ),
      sensitivePath: matchesAny(content, SIGNAL_PATTERNS.SENSITIVE_PATH),
      envRead: matchesAny(content, SIGNAL_PATTERNS.ENV_READ),
      networkEgress: matchesAny(content, SIGNAL_PATTERNS.NETWORK_EGRESS),
      dynamicCode: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_CODE),
      processExec: matchesAny(content, SIGNAL_PATTERNS.PROCESS_EXEC),
      dynamicRequire: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_REQUIRE),
    };

    this.moduleSignals.set(filename, signals);

    const found = [];

    // Intra-module rule: credential file read OR sensitive path + network egress → CRITICAL exfiltration.
    // Bare process.env reads are intentionally excluded here (F-16: false-positive on axios, dotenv, etc.)
    // and handled by the ENV_NETWORK_EGRESS WARN rule below.
    if ((signals.sensitiveRead || signals.sensitivePath) && signals.networkEgress) {
      found.push({
        rule: 'CREDENTIAL_EXFILTRATION',
        severity: 'CRITICAL',
        description: 'Module reads sensitive credentials and makes network calls',
      });
    }

    // Intra-module rule: bare env read + network egress → WARN only (common in normal apps).
    // Escalates to CRITICAL only if a sensitive credential path is also detected (handled above).
    if (signals.envRead && signals.networkEgress && !signals.sensitiveRead && !signals.sensitivePath) {
      found.push({
        rule: 'ENV_NETWORK_EGRESS',
        severity: 'WARN',
        description: 'Module reads process.env and makes network calls (common pattern; monitor for credential paths)',
      });
    }

    // Intra-module rule: dynamic code generation + process execution → code injection chain
    if (signals.dynamicCode && signals.processExec) {
      found.push({
        rule: 'DYNAMIC_CODE_EXEC_CHAIN',
        severity: 'CRITICAL',
        description: 'Module generates code dynamically and executes system processes',
      });
    }

    // Standalone rule: dynamic require with non-literal path → module injection risk
    if (signals.dynamicRequire) {
      found.push({
        rule: 'DYNAMIC_MODULE_LOAD',
        severity: 'MEDIUM',
        description: 'Module uses dynamic require() or module._load with a non-literal path',
      });
    }

    if (found.length > 0) {
      this.violations.push({ filename, violations: found, timestamp: Date.now() });
    }

    return found;
  }

  reset() {
    this.moduleSignals.clear();
    this.violations = [];
  }
}

module.exports = { BehaviorTracker };
