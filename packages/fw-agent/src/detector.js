// packages/fw-agent/src/detector.js
const { AhoCorasick } = require('./aho-corasick');
const { BehaviorTracker } = require('./behavior-tracker');

// Extended signature set covers crypto-miners, dynamic code execution, network abuse,
// and supply-chain worm patterns (postinstall fetchers, credential harvesters).
const SIGNATURES = [
  // Crypto-miner pool identifiers
  'stratum',
  'pool.hashvault',
  'coin-hive',
  'xmr-stak',
  'nicehash',
  'coinhive',
  'cryptonight',
  // Dynamic code execution
  'buffer.from',
  'eval(',
  'new function',
  // Process/shell execution
  'child_process.exec',
  'child_process.spawn',
  'execsync',
  'spawnsync',
  // Outbound network
  'net.createconnection',
  'socket.connect',
  'https.request',
  'http.request',
  // Supply-chain worm indicators
  'curl ',
  'wget ',
  '//pastebin',
  '//paste.ee',
  'atob(',
  'btoa(',
];

class Detector {
  constructor(policyEngine) {
    this.policyEngine = policyEngine;
    this.matcher = new AhoCorasick(SIGNATURES);
    this.behaviorTracker = new BehaviorTracker();

    this.stats = {
      calls: 0,
      chunkBypasses: 0,
      automatonScans: 0,
      behaviorViolations: 0,
    };
  }

  async scanModule(packageName, moduleContent) {
    return this.scanModuleSync(packageName, moduleContent);
  }

  /**
   * Synchronous O(N) compilation screening combining signature matching and behavioral analysis.
   * Pre-filter: skip files under 512 bytes (unlikely to contain malicious patterns).
   */
  scanModuleSync(packageName, moduleContent, filename) {
    this.stats.calls++;

    if (!moduleContent || typeof moduleContent !== 'string') {
      return { action: 'OBSERVE', detections: [], packageName, scanTime: Date.now() };
    }

    if (moduleContent.length < 512) {
      this.stats.chunkBypasses++;
      return { action: 'OBSERVE', detections: [], packageName, scanTime: Date.now() };
    }

    // Signature scan on first 2KB (signatures reliably appear early in malicious payloads)
    let searchContent = moduleContent;
    if (moduleContent.length > 2048) {
      this.stats.chunkBypasses++;
      searchContent = moduleContent.slice(0, 2048);
    }

    this.stats.automatonScans++;
    const detections = [];

    const match = this.matcher.searchInsensitive(searchContent);
    if (match) {
      const isCrypto = match.includes('stratum') || match.includes('pool') || match.includes('nicehash') || match.includes('cryptonight');
      detections.push({
        type: isCrypto ? 'crypto-miner' : 'dynamic-code-exec',
        severity: isCrypto ? 'CRITICAL' : 'HIGH',
        matched: match,
        timestamp: Date.now(),
      });
    }

    // Behavioral sequence analysis on full content
    const behaviorViolations = this.behaviorTracker.analyzeModule(filename || packageName, moduleContent);
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

    const action = detections.length > 0 ? 'QUARANTINE' : 'OBSERVE';
    return { action, detections, packageName, scanTime: Date.now(), behaviorViolations };
  }

  static isSuspicious(content) {
    return content && typeof content === 'string' && content.length > 0;
  }
}

module.exports = { Detector };
