// packages/fw-agent/src/policy-watcher.js
// Continuous policy integrity verification.
// Re-reads the policy file every 60 seconds and verifies its SHA-256 hash against a
// stored baseline. Mismatch triggers an emergency lockdown that blocks all module loads.

const fs = require('fs');
const crypto = require('crypto');

const WATCH_INTERVAL_MS = 60_000;

class PolicyWatcher {
  constructor(policyPath, onTamperDetected) {
    this.policyPath = policyPath;
    this.onTamperDetected = onTamperDetected;
    this.baselineHash = null;
    this.baselinePath = policyPath + '.baseline';
    this.timer = null;
    this.locked = false;
  }

  _hashFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch (e) {
      return null;
    }
  }

  /**
   * Compute and persist the baseline hash from the current policy file.
   * Should be called once after startup integrity is confirmed.
   */
  initBaseline() {
    this.baselineHash = this._hashFile(this.policyPath);
    if (this.baselineHash) {
      try {
        fs.writeFileSync(this.baselinePath, this.baselineHash + '\n', 'utf8');
      } catch (e) {
        // Non-fatal: baseline stored in memory only if file write fails
      }
    }
    return this.baselineHash;
  }

  /**
   * Load a previously stored baseline hash.
   * Returns true if a valid baseline was loaded, false otherwise.
   */
  loadBaseline() {
    try {
      const stored = fs.readFileSync(this.baselinePath, 'utf8').trim();
      if (/^[0-9a-f]{64}$/.test(stored)) {
        this.baselineHash = stored;
        return true;
      }
    } catch (e) {
      // Baseline file not yet written
    }
    return false;
  }

  verify() {
    if (!this.baselineHash) return true;
    const current = this._hashFile(this.policyPath);
    if (current === null) {
      console.error('[PolicyWatcher] Policy file missing during periodic check');
      return false;
    }
    return current === this.baselineHash;
  }

  /**
   * Start the periodic integrity check.
   * Loads or initializes the baseline on first call.
   */
  start() {
    if (!fs.existsSync(this.policyPath)) return;

    if (!this.baselineHash) {
      if (!this.loadBaseline()) {
        this.initBaseline();
      }
    }

    this.timer = setInterval(() => {
      if (this.locked) return;
      if (!this.verify()) {
        this.locked = true;
        console.error('\n[CRITICAL] Policy integrity violation detected. EMERGENCY LOCKDOWN ACTIVE.');
        if (typeof this.onTamperDetected === 'function') {
          this.onTamperDetected();
        }
      }
    }, WATCH_INTERVAL_MS);

    // Do not block process exit
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  get isLocked() {
    return this.locked;
  }
}

module.exports = { PolicyWatcher };
