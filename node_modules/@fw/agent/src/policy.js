// packages/fw-agent/src/policy.js
const crypto = require('crypto');

/**
 * Canonical Helios object structure for tamper-evident hashing
 */
function createCanonicalObject(data, objectType = 'security_policy') {
  return {
    category: objectType,
    created_at: data.created_at || new Date().toISOString(),
    key: data.key || 'active_policy',
    relationships: data.relationships || [],
    source: data.source || 'fw-control-plane',
    value: data.value || data.rules || {}
  };
}

/**
 * Hash a memory object using SHA-256 (Helios-compatible format)
 */
function hashMemoryObject(obj) {
  // Canonical JSON serialization (sorted keys, no whitespace)
  const canonical = JSON.stringify(obj, Object.keys(obj).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

/**
 * Verify policy integrity against Helios hash
 */
async function verifyPolicyIntegrity(policyObject) {
  if (!policyObject || !policyObject.rules) {
    console.warn('[Policy Verification] Missing or empty policy object');
    return false;
  }

  // Construct the canonical object as it was signed
  const canonicalObject = createCanonicalObject(policyObject, 'security_policy');
  
  // Calculate the hash locally
  const calculatedHash = hashMemoryObject(canonicalObject);
  
  // Verify against the provided hash
  if (policyObject.helios_hash) {
    if (calculatedHash !== policyObject.helios_hash) {
      console.error('[CRITICAL] Policy tampering detected! Hash mismatch.');
      console.error(`Expected: ${policyObject.helios_hash}`);
      console.error(`Calculated: ${calculatedHash}`);
      return false;
    }
    console.log('[Policy Verification] ✅ Policy integrity verified');
    return true;
  }
  
  // If no hash provided, log warning but allow (graceful degradation)
  console.warn('[Policy Verification] ⚠️ No integrity hash provided (unsigned policy)');
  return true;
}

/**
 * Create a forensic object for a security event
 */
function createForensicObject(eventType, packageName, operation, details) {
  return {
    category: 'quarantine_event',
    created_at: new Date().toISOString(),
    key: `ev_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    relationships: [packageName],
    source: 'fw-agent-proxy',
    value: {
      eventType,
      operation,
      details,
      timestamp: Date.now()
    }
  };
}

module.exports = {
  createCanonicalObject,
  hashMemoryObject,
  verifyPolicyIntegrity,
  createForensicObject
};
