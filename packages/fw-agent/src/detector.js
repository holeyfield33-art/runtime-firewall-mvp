// packages/fw-agent/src/detector.js
const { AhoCorasick } = require('./aho-corasick');
const { BehaviorTracker } = require('./behavior-tracker');

// Extended signature set covers crypto-miners, dynamic code execution, network abuse,
// and supply-chain worm patterns (postinstall fetchers, credential harvesters).
// High-confidence malicious signatures — trigger QUARANTINE/BLOCK on match.
const BLOCK_SIGNATURES = [
  // Crypto-miner pool identifiers
  'stratum',
  'pool.hashvault',
  'coin-hive',
  'xmr-stak',
  'nicehash',
  'coinhive',
  'cryptonight',
  // Dynamic code execution (unambiguous in production code)
  'eval(',
  'new function',
  // Process/shell execution
  'child_process.exec',
  'child_process.spawn',
  'execsync',
  'spawnsync',
  // Supply-chain worm indicators
  'curl ',
  'wget ',
  '//pastebin',
  '//paste.ee',
  // Native binding / VM escape (sandbox bypass vectors)
  'process.binding',
  'vm.runinnewcontext',
  'vm.runinthiscontext',
];

// Indicative patterns common in legitimate code — emit WARN/OBSERVE only, never block.
const WARN_SIGNATURES = [
  'buffer.from',
  'atob(',
  'btoa(',
  'https.request',
  'http.request',
  'net.createconnection',
  'socket.connect',
];

class Detector {
  constructor(policyEngine) {
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
        // Only escalate CRITICAL/HIGH behavioral violations to detections
        if (v.severity === 'CRITICAL' || v.severity === 'HIGH') {
          detections.push({
            type: 'behavioral',
            severity: v.severity,
            rule: v.rule,
            description: v.description,
            timestamp: Date.now(),
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
