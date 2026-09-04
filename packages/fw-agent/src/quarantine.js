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
   * Create a Proxy that intercepts all property accesses and method calls.
   *
   * F-5.1: the target used to be a plain object (`{}`). A Proxy is only callable/
   * constructible if its *target* is callable/constructible — apply/construct traps are
   * never consulted otherwise, so `proxy()` or `new proxy()` on a function/class-shaped
   * quarantined dependency threw a native, uncatchable-by-us TypeError ("proxy is not a
   * function" / "not a constructor") instead of being safely neutered. The target is now a
   * real function, which is both callable and constructible, so the apply/construct traps
   * below actually run.
   *
   * That target inescapably owns one non-configurable own property: `prototype`
   * (writable, non-enumerable, non-configurable — spec-mandated for every ordinary
   * function). Every trap below that reports the presence/shape of own keys
   * (ownKeys/getOwnPropertyDescriptor/has/deleteProperty/defineProperty) must therefore
   * defer to the target's *real* descriptor whenever the key is non-configurable (or, once
   * the proxy is made non-extensible, for any real own key at all) — pretending it doesn't
   * exist violates the Proxy invariants and throws a raw TypeError straight out of the
   * engine, the exact class of crash this fix exists to close (same failure mode as F-63).
   * Configurable, forgeable keys (everything else) keep the prior "pretend empty" behavior.
   */
  createProxy() {
    const target = function QuarantinedModule() {};

    const isRealOwnKey = (prop) => {
      const real = Reflect.getOwnPropertyDescriptor(target, prop);
      return !!real && (!real.configurable || !Reflect.isExtensible(target));
    };

    return new Proxy(target, {
      apply: (targetFn, thisArg, args) => {
        this.record(`function_call`, { args: args.length });
        return null; // Graceful degradation — never execute the real quarantined code
      },

      construct: (targetFn, args, newTarget) => {
        this.record(`construct_call`, { args: args.length });
        // The constructed instance is itself just another inert, quarantined proxy.
        return this.createProxy();
      },

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
        // Cannot report a non-configurable (or, once frozen, any real) own key as absent.
        return isRealOwnKey(prop);
      },

      deleteProperty: (target, prop) => {
        this.record(`property_delete`, { property: String(prop) });
        const real = Reflect.getOwnPropertyDescriptor(target, prop);
        if (real && !real.configurable) {
          return false; // Cannot delete a non-configurable own property (e.g. `prototype`)
        }
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
      // firewall's control. Pretend success for forgeable keys; for a key that is genuinely
      // non-configurable on the target (`prototype`), forward to the real target so the
      // invariant checks the engine performs against Desc are satisfied honestly.
      defineProperty: (target, prop, descriptor) => {
        this.record(`property_define`, { property: String(prop) });
        const real = Reflect.getOwnPropertyDescriptor(target, prop);
        if (real && !real.configurable) {
          return Reflect.defineProperty(target, prop, descriptor);
        }
        return true; // Pretend the definition succeeded; never touch the real target
      },

      ownKeys: (target) => {
        this.record(`enumerate_keys`, {});
        return Reflect.ownKeys(target).filter(isRealOwnKey);
      },

      getOwnPropertyDescriptor: (target, prop) => {
        this.record(`descriptor_query`, { property: String(prop) });
        return isRealOwnKey(prop) ? Reflect.getOwnPropertyDescriptor(target, prop) : undefined;
      }
    });
  }
}

module.exports = { QuarantineStub };
