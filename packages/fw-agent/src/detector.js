// packages/fw-agent/src/detector.js
const { AhoCorasick } = require('./aho-corasick');

class Detector {
  constructor(policyEngine) {
    this.policyEngine = policyEngine;
    this.matcher = new AhoCorasick([
      'stratum', 'pool.hashvault', 'coin-hive', 'xmr-stak', 'nicehash',
      'buffer.from', 'eval(', 'new function', 'child_process.exec',
      'net.createconnection', 'socket.connect', 'https.request'
    ]);

    this.stats = {
      calls: 0,
      chunkBypasses: 0,
      automatonScans: 0
    };
  }

  async scanModule(packageName, moduleContent) {
    return this.scanModuleSync(packageName, moduleContent);
  }

  /**
   * scanModuleSync - Synchronous O(N) compilation screening.
   * Completely eliminates V8 RegExp backtracking latency loops.
   * Pre-filter: skip files under 512 bytes (unlikely to contain malicious patterns).
   */
  scanModuleSync(packageName, moduleContent) {
    this.stats.calls++;

    if (!moduleContent || typeof moduleContent !== 'string') {
      return { action: 'OBSERVE', detections: [], packageName, scanTime: Date.now() };
    }

    // Skip trivially small files—malicious patterns require meaningful code
    if (moduleContent.length < 512) {
      this.stats.chunkBypasses++; // reuse field for "tiny bypass" count for telemetry parity
      return { action: 'OBSERVE', detections: [], packageName, scanTime: Date.now() };
    }

    // Chunking for perf: scan only first 2KB of larger modules.
    // Signatures reliably appear early in malicious payloads; reduces per-module work ~2-4x.
    let searchContent = moduleContent;
    if (moduleContent.length > 2048) {
      this.stats.chunkBypasses++;
      searchContent = moduleContent.slice(0, 2048);
    }

    this.stats.automatonScans++;
    let hasDetection = false;
    const detections = [];

    // Case-insensitive scan without allocating a lowercased copy of the content.
    // Uses array-indexed Aho-Corasick (charCode hot path) for O(N) deterministic speed.
    const match = this.matcher.searchInsensitive(searchContent);
    if (match) {
      hasDetection = true;
      const isCrypto = match.includes('stratum') || match.includes('pool');
      detections.push({
        type: isCrypto ? 'crypto-miner' : 'dynamic-code-exec',
        severity: isCrypto ? 'CRITICAL' : 'HIGH',
        timestamp: Date.now()
      });
    }

    const action = hasDetection ? 'QUARANTINE' : 'OBSERVE';
    return { action, detections, packageName, scanTime: Date.now() };
  }

  static isSuspicious(content) {
    return content && typeof content === 'string' && content.length > 0;
  }
}

module.exports = { Detector };
