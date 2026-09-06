'use strict';

// Authoritative event vocabulary shared by the agent producer and control-plane validator.
// Keep audit-only events here too: accepting the superset lets the control plane remain
// compatible with events that may be forwarded by future agent versions.
const TELEMETRY_EVENT_TYPES = Object.freeze([
  'OBSERVE',
  'WARN',
  'QUARANTINE_ACTIVE',
  'QUARANTINE_BREACH',
  'BLOCK',
  'DETECTION_TRIGGERED',
  'QUARANTINE_BLOCK_REQUIRE',
  'POLICY_TAMPER_LOCKDOWN',
  'SUSPICIOUS_SCRIPT',
  'AGENT_START',
  'AGENT_SHUTDOWN',
  'FW_MODE_DEV',
  'FW_MODE_ENFORCE',
  'CACHE_SUBSTITUTION_DETECTED',
  'CACHE_SUBSTITUTION_AUDITED',
  'CACHE_SUBSTITUTION_BLOCKED',
  'ESM_HOOK_UNAVAILABLE',
  'CHILD_REINJECTION_FAILURE',
  'PACKAGE_IDENTITY_MISMATCH',
  'TELEMETRY_DEGRADED',
  'TELEMETRY_DELIVERY_FAILURE',
]);

const TELEMETRY_EVENT_TYPE_SET = new Set(TELEMETRY_EVENT_TYPES);

function isTelemetryEventType(eventType) {
  return TELEMETRY_EVENT_TYPE_SET.has(eventType);
}

module.exports = { TELEMETRY_EVENT_TYPES, isTelemetryEventType };
