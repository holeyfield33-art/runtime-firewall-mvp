#!/usr/bin/env bash
# scripts/audit-3-runtime.sh
# End-to-end runtime detection checks. Corrected on three counts vs. the original:
#   - the demo check grepped for "[COMPILATION LOCKDOWN]", a string demo.sh deliberately
#     filters OUT of its own output; we count the "[BLOCKED]" lines the demo actually prints.
#   - test:live now genuinely reports "Blocked: 2" (the obfuscated fixture is a real
#     base64-decode+eval payload caught by F-31, not a runtime ReferenceError).
#   - the strict-preload check sets FW_ENABLE_DETECTION=1 (without it the agent no-ops).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[AUDIT 3] Runtime Behavior & Detection Verification"
fail() { echo "FAIL: $1"; exit 1; }

# 1. Demo blocks both threats. demo.sh prints "[BLOCKED] ..." wrapper lines.
LOG="$(mktemp)"
bash demo/demo.sh >"$LOG" 2>&1 || true
BLOCKS="$(grep -c "\[BLOCKED\]" "$LOG" || true)"
[ "${BLOCKS:-0}" -ge 2 ] || fail "demo did not block 2 threats (found ${BLOCKS:-0})"
echo "OK: demo blocked ${BLOCKS} threats"

# 2. Integration test: exactly one hard block.
npm run --silent test:integration 2>&1 | grep -q "Blocked: 1" || fail "integration test did not report Blocked: 1"
echo "OK: integration test passed (Blocked: 1)"

# 3. Live test: two hard blocks (miner + base64->eval obfuscation).
npm run --silent test:live 2>&1 | grep -q "Blocked: 2" || fail "live test did not report Blocked: 2"
echo "OK: live test passed (Blocked: 2)"

# 4. Zero-overhead mode: no hook installed when detection is disabled.
FW_ENABLE_DETECTION=0 node -e "require('./packages/fw-agent'); console.log('OK')" 2>&1 | grep -q "OK" \
  || fail "zero-overhead mode failed"
echo "OK: zero-overhead mode works"

# 5. Strict preload: a non---require load is rejected. (Needs detection enabled; use a dir
#    with no policy file so the preload guard is what fires, and allow the dev key for dev.)
TMPDIR_PRELOAD="$(mktemp -d)"
REPO_ROOT="$(pwd)"
OUT="$(cd "$TMPDIR_PRELOAD" && FW_STRICT_PRELOAD=1 FW_ENABLE_DETECTION=1 FW_ALLOW_DEV_POLICY_KEY=1 \
  node -e "require('$REPO_ROOT/packages/fw-agent')" 2>&1 || true)"
echo "$OUT" | grep -q "CRITICAL" || fail "strict preload did not reject a non---require load (F-32)"
echo "OK: strict preload rejects non---require loads (F-32)"

echo "AUDIT 3 PASSED"
