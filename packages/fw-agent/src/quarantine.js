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
    this.rateLimitCount = 0;
    this.initTime = BigInt(process.hrtime.bigint());
  }

  /**
   * Record a quarantine event with tamper-evident hashing
   */
  record(operation, details = {}) {
    this.interceptCount++;
    
    // Detect rapid-fire intercepts (>100 calls in <1ms) as a potential exhaustion attack.
    // Do NOT kill the host process — rate-limit logs and return to preserve availability.
    const currentDelta = Number(process.hrtime.bigint() - this.initTime) / 1e6;
    if (this.interceptCount > 100 && currentDelta < 1.0) {
      this.rateLimitCount++;
      if (this.rateLimitCount % 10 === 1) {
        console.warn(
          `[Quarantine] Rapid-fire intercepts on "${this.packageName}" ` +
          `(${this.interceptCount} calls in ${currentDelta.toFixed(3)}ms). ` +
          `Rate-limiting (suppressed ${this.rateLimitCount - 1} events).`
        );
      }
      return; // Inert return — preserve host availability
    }

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
        // F-17: Prevent the proxy from being treated as a thenable/iterable.
        // If `then`, Symbol.toPrimitive, or Symbol.iterator resolve to a function,
        // Promise.resolve() / await / for..of will hang or throw unexpectedly.
        if (prop === 'then' || prop === Symbol.toPrimitive || prop === Symbol.iterator) {
          return undefined;
        }

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

      // F-63: defineProperty was previously untrapped, so it forwarded to the real (empty)
      // target via the default Reflect.defineProperty behavior. That actually defined the
      // property on target — typically non-configurable, since Object.defineProperty defaults
      // `configurable` to false when omitted. The ownKeys/getOwnPropertyDescriptor traps below
      // still reported the module as having no keys at all, which violates the Proxy invariant
      // that ownKeys' result must include every non-configurable own key the target actually
      // has — the engine then throws a raw TypeError on the next Object.keys() /
      // Reflect.ownKeys() / Object.getOwnPropertyDescriptors() call, entirely outside the
      // firewall's control. Pretend success, matching every other trap in this file, and never
      // forward to the target so its own-property set stays empty and the invariant holds.
      defineProperty: (target, prop, descriptor) => {
        this.record(`property_define`, { property: String(prop) });
        return true; // Pretend the definition succeeded; never touch the real target
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
