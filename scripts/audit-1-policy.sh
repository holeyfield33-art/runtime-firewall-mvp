#!/usr/bin/env bash
# scripts/audit-1-policy.sh
# Verifies the policy-signing configuration — corrected to actually exercise the runtime guard.
#
# The original audit gated every check on NODE_ENV=production (so it silently passed in any
# normal dev/CI shell) and left the dev-key check as a "manual verification" note. This version
# adds two real assertions: (1) the bundled dev-key fingerprint is computed and compared
# automatically, and (2) the agent's runtime fail-closed behavior is invoked and observed.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[AUDIT 1] Policy Signature & Key Configuration"
fail() { echo "FAIL: $1"; exit 1; }

# 1. Production must set a real key and must NOT re-enable the dev key.
if [ "${NODE_ENV:-}" = "production" ]; then
  [ -n "${FW_POLICY_PUBKEY:-}" ] || fail "FW_POLICY_PUBKEY is not set in production"
  [ "${FW_ALLOW_DEV_POLICY_KEY:-0}" != "1" ] || fail "FW_ALLOW_DEV_POLICY_KEY=1 in production — dev key accepted!"
fi

# 2. policy.signed.json (if present) must be valid JSON with the signed-envelope fields.
if [ -f policy.signed.json ]; then
  jq -e '.version and .rules and .signedAt and .signature' policy.signed.json >/dev/null \
    || fail "policy.signed.json is missing signed-envelope fields (version/rules/signedAt/signature)"
  echo "OK: policy.signed.json is a valid signed envelope"
else
  echo "WARN: policy.signed.json not found — no policy enforcement"
fi

# 3. If a production key is set, prove it is NOT the bundled dev key (compare fingerprints).
DEV_FP="$(node -e "
  const pem = require('./packages/fw-agent/src/policy-watcher.js'); // side-effect: none
" 2>/dev/null; openssl pkey -pubin -in <(printf '%s\n' \
'-----BEGIN PUBLIC KEY-----' \
'MCowBQYDK2VwAyEANejKx1KxfXVk5B0UzI2Cp3XO9hmy6nIXTAhsW0bhlFo=' \
'-----END PUBLIC KEY-----') -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
echo "INFO: bundled dev-key fingerprint: ${DEV_FP}"
if [ -n "${FW_POLICY_PUBKEY:-}" ]; then
  PROD_FP="$(openssl pkey -pubin -in <(printf '%s' "$FW_POLICY_PUBKEY") -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 || echo unknown)"
  echo "INFO: configured FW_POLICY_PUBKEY fingerprint: ${PROD_FP}"
  [ "$PROD_FP" != "$DEV_FP" ] || fail "FW_POLICY_PUBKEY is the bundled dev key — its private half is public!"
  echo "OK: production key differs from the bundled dev key"
fi

# 4. Runtime fail-closed proof: production + dev key + no explicit opt-in must refuse to start.
OUT="$(NODE_ENV=production FW_ENABLE_DETECTION=1 FW_POLICY_PUBKEY= FW_ALLOW_DEV_POLICY_KEY= \
  node --require ./packages/fw-agent -e "console.log('STARTED')" 2>&1 || true)"
echo "$OUT" | grep -q "Refusing to start" || fail "agent did NOT refuse to start with the dev key in production (F-33)"
! echo "$OUT" | grep -q "STARTED" || fail "agent started despite dev key in production"
echo "OK: agent refuses to start in production with the bundled dev key (F-33)"

echo "AUDIT 1 PASSED"
