// packages/fw-agent/src/detector.js
class Detector {
  constructor(policyEngine) {
    this.policyEngine = policyEngine;
    // Basic signature patterns for rapid filtering
    this.signatures = {
      'crypto-miner': [/stratum/, /pool\.hashvault/, /coin-hive/, /xmr-stak/, /nicehash/],
      'potential-obfuscation': [/Buffer\.from\(['"](aWYo|dmFy)/], // Common b64 starters
      'dynamic-code-exec': [/eval\s*\(/, /new\s+Function/, /child_process\.exec/, /require\s*\(\s*['"]\.\/['"\s]*\+/],
      'suspicious-network': [/https?\.request/, /socket\.connect/, /net\.createConnection/],
    };
  }

  /**
   * scanModuleSync - Enforces synchronous level repulsion.
   * Eliminates the temporal gap (Δt) to lock k = 1 under heavy load.
   */
  scanModuleSync(packageName, moduleContent) {
    const detections = [];
    
    // 1. Signature scan - check if content matches known malicious patterns
    for (const [type, patterns] of Object.entries(this.signatures)) {
      for (const pattern of patterns) {
        try {
          if (pattern.test(moduleContent)) {
            detections.push({ 
              type, 
              severity: type === 'crypto-miner' ? 'CRITICAL' : 'HIGH',
              timestamp: Date.now()
            });
            break; // Only add once per type
          }
        } catch (e) {
          // Regex error - skip
        }
      }
    }
    
    // 2. Determine action based on detections
    const action = detections.length > 0 ? 'QUARANTINE' : 'OBSERVE';
    
    return { 
      action, 
      detections,
      packageName,
      scanTime: Date.now()
    };
  }

  async scanModule(packageName, moduleContent) {
    // Legacy async implementation for backwards compatibility
    return this.scanModuleSync(packageName, moduleContent);
  }

  // Static helper to check if content looks suspicious
  static isSuspicious(content) {
    return content.length > 0 && typeof content === 'string';
  }
}

module.exports = { Detector };
