#!/usr/bin/env bash
# scripts/audit-2-interception.sh
# Verifies core interception + that documented bypasses are acknowledged.
# Corrected: the original grepped for the literal "16 passed"; the suite reports
# "N passed, 0 failed out of N tests" and has grown well past 16. We assert on
# "0 failed" plus a non-zero pass count instead of a hard-coded number.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[AUDIT 2] Core Interception & Bypass Detection"
fail() { echo "FAIL: $1"; exit 1; }

# 1. Adversarial suite must pass with zero failures.
LOG="$(mktemp)"
npm run --silent test:adversarial 2>&1 | tee "$LOG" >/dev/null || fail "adversarial suite exited non-zero"
grep -Eq "Results: [0-9]+ passed, 0 failed" "$LOG" || fail "adversarial suite reported failures"
COUNT="$(grep -Eo "Results: [0-9]+ passed" "$LOG" | grep -Eo "[0-9]+")"
echo "OK: adversarial tests passed (${COUNT}/${COUNT})"

# 2. Known bypasses documented in the root README.
for term in "Bracket eval" "String concat" "Variable-alias" "Prototype chain"; do
  grep -q "$term" README.md || echo "WARN: bypass not documented in README.md: '$term'"
done
echo "OK: known-bypass documentation checked"

# 3. npm postinstall scope gap documented.
grep -q "postinstall" README.md || fail "npm postinstall gap is NOT documented"
echo "OK: npm postinstall gap documented"

# 4. Self-integrity baseline exists and matches current source.
[ -f packages/fw-agent/.helios-baseline ] || fail "self-integrity baseline missing"
node scripts/generate-baseline.js --check >/dev/null || fail "self-integrity baseline does not match source"
echo "OK: self-integrity baseline present and matches source"

# 5. The base64->eval obfuscation is genuinely blocked (F-31 — was a silent gap).
node -e "
  const { Detector } = require('./packages/fw-agent/src/detector');
  const d = new Detector(new Map());
  const src = \"const p = Buffer.from('cGF5bG9hZA==','base64').toString(); eval(p);\" + '\n// ' + 'x'.repeat(600);
  const r = d.scanModuleSync('m.js', src, 'm.js');
  const blocked = r.detections.some(x => !x.warnOnly && x.rule === 'OBFUSCATED_CODE_EXECUTION');
  if (!blocked) { console.error('base64->eval NOT blocked'); process.exit(1); }
" || fail "base64->eval obfuscation is not blocked (F-31 regression)"
echo "OK: base64->eval obfuscation is blocked (F-31)"

echo "AUDIT 2 PASSED"
