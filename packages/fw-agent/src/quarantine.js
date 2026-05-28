// packages/fw-agent/src/quarantine.js
const { hashMemoryObject, createForensicObject } = require('./policy');

/**
 * QuarantineStub - A Proxy that intercepts all method calls on quarantined modules
 * Every intercept is hashed and logged for forensic analysis
 */
class QuarantineStub {
  constructor(packageName, telemetry) {
    this.packageName = packageName;
    this.telemetry = telemetry;
    this.interceptCount = 0;
  }

  /**
   * Record a quarantine event with tamper-evident hashing
   */
  record(operation, details = {}) {
    this.interceptCount++;

    // Create the forensic object
    const forensicObject = createForensicObject(
      'QUARANTINE_BREACH',
      this.packageName,
      operation,
      {
        ...details,
        interceptCount: this.interceptCount
      }
    );

    // Calculate the forensic hash (SHA-256 of canonical JSON)
    const eventHash = hashMemoryObject(forensicObject);

    // Only emit telemetry if it exists (may be disabled during benchmarks)
    if (this.telemetry && this.telemetry.emit) {
      // Emit telemetry with the hash for immutable audit trail
      this.telemetry.emit('quarantine_event', {
        ...forensicObject,
        hash: eventHash  // Tamper-evident anchor
      });
    }

    // Also log to console for real-time observability (only first breach)
    if (this.interceptCount === 1) {
      console.warn(
        `[Quarantine Intercept] Package: ${this.packageName} | Operation: ${operation} | Hash: ${eventHash.substring(0, 16)}...`
      );
    }
  }

  /**
   * Create a Proxy that intercepts all property accesses and method calls
   */
  createProxy() {
    return new Proxy({}, {
      get: (target, prop) => {
        // Record the interception
        this.record(`property_access`, { property: String(prop) });

        // Return a function that logs further calls
        return (...args) => {
          this.record(`method_call`, {
            property: String(prop),
            args: args.length
          });
          return null; // Graceful degradation
        };
      },

      set: (target, prop, value) => {
        this.record(`property_write`, { property: String(prop) });
        return true; // Pretend success
      },

      has: (target, prop) => {
        this.record(`property_check`, { property: String(prop) });
        return false; // Pretend property doesn't exist
      },

      deleteProperty: (target, prop) => {
        this.record(`property_delete`, { property: String(prop) });
        return true; // Pretend deletion succeeded
      },

      ownKeys: (target) => {
        this.record(`enumerate_keys`, {});
        return [];
      },

      getOwnPropertyDescriptor: (target, prop) => {
        this.record(`descriptor_query`, { property: String(prop) });
        return undefined;
      }
    });
  }
}

module.exports = { QuarantineStub };
