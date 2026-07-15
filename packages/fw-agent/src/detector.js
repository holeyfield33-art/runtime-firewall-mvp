// packages/fw-agent/src/detector.js
const { AhoCorasick } = require('./aho-corasick');
const { BehaviorTracker } = require('./behavior-tracker');

// Extended signature set covers crypto-miners, dynamic code execution, network abuse,
// and supply-chain worm patterns (postinstall fetchers, credential harvesters).
// High-confidence malicious signatures — trigger QUARANTINE/BLOCK on match.
const BLOCK_SIGNATURES = [
  '/dev/tcp/',
  // Reverse-shell redirect idiom (F-29): bare 'bash -i' / 'sh -i' also match ordinary
  // interactive-shell invocations of unrelated tools (push -i, fish -i, wash -i, ...).
  // Real reverse shells redirect stdio via '>&' — require that too.
  'bash -i >&',
  'sh -i >&',
  // Crypto-miner pool identifiers. F-29: bare 'stratum' matches the mining-protocol word
  // wherever it occurs in English prose (e.g. dictionary/word-list packages containing
  // "stratum", "substratum", "stratus"), so match the pool-URL scheme instead — that's
  // what real miner configs actually contain.
  'stratum+tcp',
  'stratum://',
  'pool.hashvault',
  'coin-hive',
  'xmr-stak',
  'nicehash',
  'coinhive',
  'cryptonight',
  // Supply-chain worm indicators
  '//pastebin',
  '//paste.ee',
  '| bash',
];

// Indicative patterns common in legitimate code — emit WARN/OBSERVE only, never block.
// Also includes patterns (exec, eval) that are caught by the behavioral DYNAMIC_CODE_EXEC_CHAIN
// rule when used dangerously — so static-only matches on these produce WARN, not hard block.
const WARN_SIGNATURES = [
  'buffer.from',
  'atob(',
  'btoa(',
  'https.request',
  'http.request',
  'net.createconnection',
  'socket.connect',
  // Broad exec/eval literals — moved from BLOCK (F-20): appear in legitimate build tools
  // and test frameworks. Behavioral DYNAMIC_CODE_EXEC_CHAIN still hard-blocks the
  // dangerous eval+exec combination.
  'eval(',
  'child_process.exec',
  'execsync',
  // Legitimate capabilities that false-positive on lodash/axios/express — warn, don't block.
  'new function',
  'process.binding',
  // Legitimate capabilities in bundlers/process libs (esbuild, execa, cross-spawn, ws, undici) — F-26
  'child_process.spawn',
  'spawnsync',
  'vm.runinnewcontext',
  'vm.runinthiscontext',
  // Bare words that also match prose/comments — F-26
  'curl ',
  'wget ',
];

class Detector {
  constructor(/** @reserved - future policy integration */ policyEngine) {
    this.policyEngine = policyEngine;
    this.blockMatcher = new AhoCorasick(BLOCK_SIGNATURES);
    this.warnMatcher = new AhoCorasick(WARN_SIGNATURES);
    this.behaviorTracker = new BehaviorTracker();

    this.stats = {
      calls: 0,
      automatonScans: 0,
      behaviorViolations: 0,
      warnOnlyDetections: 0,
    };
  }

  async scanModule(packageName, moduleContent) {
    return this.scanModuleSync(packageName, moduleContent);
  }

  /**
   * Synchronous O(N) compilation screening combining signature matching and behavioral analysis.
   */
  scanModuleSync(packageName, moduleContent, filename) {
    this.stats.calls++;

    if (!moduleContent || typeof moduleContent !== 'string') {
      return { action: 'OBSERVE', detections: [], packageName, scanTime: Date.now() };
    }

    // Full-content scan: Aho-Corasick is O(N) so scanning the entire module is safe.
    const searchContent = moduleContent;

    this.stats.automatonScans++;
    const detections = [];

    // BLOCK-tier: high-confidence malicious patterns — always quarantine on match
    const blockMatch = this.blockMatcher.searchInsensitive(searchContent);
    if (blockMatch) {
      const isCrypto = blockMatch.includes('stratum') || blockMatch.includes('pool') || blockMatch.includes('nicehash') || blockMatch.includes('cryptonight');
      detections.push({
        type: isCrypto ? 'crypto-miner' : 'dynamic-code-exec',
        severity: isCrypto ? 'CRITICAL' : 'HIGH',
        matched: blockMatch,
        timestamp: Date.now(),
      });
    }

    // WARN-tier: common in benign code — log for visibility but never block on these alone
    const warnMatch = this.warnMatcher.searchInsensitive(searchContent);
    if (warnMatch) {
      this.stats.warnOnlyDetections++;
      detections.push({
        type: 'indicative-pattern',
        severity: 'WARN',
        matched: warnMatch,
        timestamp: Date.now(),
        warnOnly: true,
      });
    }

    // Behavioral sequence analysis on full content (skipped when FW_ENABLE_BEHAVIORAL=0)
    const behaviorEnabled = process.env.FW_ENABLE_BEHAVIORAL !== '0';
    const behaviorViolations = behaviorEnabled
      ? this.behaviorTracker.analyzeModule(filename || packageName, moduleContent)
      : [];
    if (behaviorViolations.length > 0) {
      this.stats.behaviorViolations++;
      for (const v of behaviorViolations) {
        // CRITICAL/HIGH behavioral violations are block-tier — escalate to quarantine
        if (v.severity === 'CRITICAL' || v.severity === 'HIGH') {
          detections.push({
            type: 'behavioral',
            severity: v.severity,
            rule: v.rule,
            description: v.description,
            timestamp: Date.now(),
          });
        } else {
          // WARN/MEDIUM violations are surfaced for logging and telemetry but never trigger QUARANTINE
          detections.push({
            type: 'behavioral',
            severity: v.severity,
            rule: v.rule,
            description: v.description,
            timestamp: Date.now(),
            warnOnly: true,
          });
        }
      }
    }

    // Only escalate to QUARANTINE if at least one non-WARN detection exists
    const hasBlockDetection = detections.some(d => !d.warnOnly);
    const action = hasBlockDetection ? 'QUARANTINE' : 'OBSERVE';
    return { action, detections, packageName, scanTime: Date.now(), behaviorViolations };
  }

  static isSuspicious(content) {
    return content && typeof content === 'string' && content.length > 0;
  }
}

module.exports = { Detector };
