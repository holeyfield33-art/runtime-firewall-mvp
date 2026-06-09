// packages/fw-agent/src/behavior-tracker.js
// State machine behavioral analyzer for sequence-based threat detection.
// Tracks dangerous action sequences both within a single module and across module loads.

// Signal detection patterns for each behavioral category
const SIGNAL_PATTERNS = {
  // Reads sensitive credential files or environment variables
  SENSITIVE_READ: [
    /fs\s*\.\s*readFile/,
    /fs\s*\.\s*readFileSync/,
    /fs\s*\.\s*open(?:Sync)?\s*\(/,
    /process\s*\.\s*env\b/,
  ],
  SENSITIVE_PATH: [
    /\.npmrc/i,
    /\.env\b/i,
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
    /\bexec\s*\(/,
    /\bspawn\s*\(/,
    /\bexecSync\s*\(/,
    /\bspawnSync\s*\(/,
    /\bexecFile\s*\(/,
    /\bexecFileSync\s*\(/,
    /\bfork\s*\(/,
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
    // Cross-module global state machine
    this.globalState = {
      sensitiveRead: false,
      networkEgress: false,
      dynamicCode: false,
      processExec: false,
    };
    // Per-module signal cache
    this.moduleSignals = new Map();
    // Accumulated violations for telemetry
    this.violations = [];
  }

  /**
   * Analyze a module and return any behavioral violations found.
   * Checks both intra-module sequences and cross-module state machine transitions.
   */
  analyzeModule(filename, content) {
    if (!content || content.length < 100) return [];

    const signals = {
      sensitiveRead: matchesAny(content, SIGNAL_PATTERNS.SENSITIVE_READ),
      sensitivePath: matchesAny(content, SIGNAL_PATTERNS.SENSITIVE_PATH),
      networkEgress: matchesAny(content, SIGNAL_PATTERNS.NETWORK_EGRESS),
      dynamicCode: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_CODE),
      processExec: matchesAny(content, SIGNAL_PATTERNS.PROCESS_EXEC),
      dynamicRequire: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_REQUIRE),
    };

    this.moduleSignals.set(filename, signals);

    const found = [];

    // Intra-module rule: credential read + network egress in same module → exfiltration
    if ((signals.sensitiveRead || signals.sensitivePath) && signals.networkEgress) {
      found.push({
        rule: 'CREDENTIAL_EXFILTRATION',
        severity: 'CRITICAL',
        description: 'Module reads sensitive credentials and makes network calls',
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

    // Cross-module rule: prior sensitive-read + this module makes network calls
    if (this.globalState.sensitiveRead && signals.networkEgress && !signals.sensitiveRead && !signals.sensitivePath) {
      found.push({
        rule: 'CROSS_MODULE_EXFILTRATION',
        severity: 'HIGH',
        description: 'Network egress detected after sensitive file access in prior module',
      });
    }

    // Cross-module rule: prior dynamic-code + this module executes processes
    if (this.globalState.dynamicCode && signals.processExec && !signals.dynamicCode) {
      found.push({
        rule: 'CROSS_MODULE_CODE_EXEC',
        severity: 'HIGH',
        description: 'Process execution after dynamic code generation in prior module',
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

    // Update global state for subsequent modules
    if (signals.sensitiveRead || signals.sensitivePath) this.globalState.sensitiveRead = true;
    if (signals.networkEgress) this.globalState.networkEgress = true;
    if (signals.dynamicCode) this.globalState.dynamicCode = true;
    if (signals.processExec) this.globalState.processExec = true;

    if (found.length > 0) {
      this.violations.push({ filename, violations: found, timestamp: Date.now() });
    }

    return found;
  }

  reset() {
    this.globalState = { sensitiveRead: false, networkEgress: false, dynamicCode: false, processExec: false };
    this.moduleSignals.clear();
    this.violations = [];
  }
}

module.exports = { BehaviorTracker };
