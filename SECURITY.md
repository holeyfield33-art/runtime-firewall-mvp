# Security Policy

## Supported Versions

| Version | Supported           |
|---------|---------------------|
| 0.2.x   | Yes                 |
| 0.1.x   | Security fixes only |
| < 0.1   | No                  |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security bugs.**

Report vulnerabilities privately through GitHub Security Advisories:

1. Go to the repository page on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability**.
4. Fill in the form with a description, reproduction steps, and impact assessment.

We will acknowledge your report within 5 business days and aim to resolve and publish a fix within 90 days of confirmation. We will credit reporters who wish to be named in the advisory.

## Scope

### In scope

- **Detection bypass**: a technique that causes the firewall to allow a module it should block or quarantine, without requiring AST-level or full dynamic analysis (which are already documented as out-of-scope at the architectural level).
- **Firewall integrity**: an attack that defeats or silently disables the self-integrity check, the policy watcher's tamper detection, or the audit log without triggering a lockdown.

### Out of scope

- **Telemetry fail-open under `FW_TELEMETRY=1` with no control plane**: when `FW_TELEMETRY=1` is set and no control plane is running, the telemetry worker swallows connection errors and delivers nothing. This is intentional and documented behavior -- do not file a security report for it.
- **Known bypass techniques documented in README**: bracket-notation eval (`this["ev"+"al"]`), string concatenation (`global["ev"+"al"]`), array-join reassembly, and prototype-chain access all require AST-level or dynamic analysis. These are architectural limitations, not implementation bugs.
- **Issues in packages outside `aletheia-firewall`**: `fw-control` (the control plane server) is out of scope for this policy; its security posture is separate.
- **Performance or denial-of-service against the scanner itself**: the firewall is a synchronous in-process hook; its availability is tied to the host process.
- **False positives**: incorrect blocking of benign modules is a usability issue, not a security vulnerability.

## July 2026 Audit — Resolution Status

The following findings from the July 2026 internal audit have been addressed as of v0.2.0:

| Finding | Severity | Status | Fix version |
| ------- | -------- | ------ | ----------- |
| F-01: CI pipeline broken (wrong working-directory) | CRITICAL | ✅ Fixed | 0.1.1 |
| F-02: TOFU policy baseline attackable | HIGH | ✅ Fixed | 0.2.0 — Ed25519 signing |
| F-03: 2 KB truncation bypass | HIGH | ✅ Fixed | 0.2.0 — full-content scan |
| F-04: False positives on common patterns | HIGH | ✅ Fixed | 0.1.1 — WARN tier |
| F-05: `process.exit(9)` in quarantine | MEDIUM | ✅ Fixed | 0.1.1 — rate-limited return |
| F-06: No policy hot-reload | MEDIUM | ✅ Fixed | 0.2.0 — `onValidChange` callback |
| F-07: <100-byte skip in behavioral analyzer | MEDIUM | ✅ Fixed | 0.2.0 |
| F-08: Inline require("https").get missed | MEDIUM | ✅ Fixed | 0.2.0 |
| F-09: Control plane binds 0.0.0.0 | MEDIUM | ✅ Fixed | 0.2.0 — 127.0.0.1 default |
| F-13: No warning for unauthenticated dashboard | LOW | ✅ Fixed | 0.2.0 |
| F-14: No tests for watcher/quarantine/auditlog | INFO | ✅ Fixed | 0.1.1 — new test suite |

Deferred to Phase 3+ (out of scope for 0.2.0):

| Finding | Severity | Notes |
| ------- | -------- | ----- |
| F-10: AST-level obfuscation detection | MEDIUM | Requires V8 Inspector / AST pre-processing |
| F-11: Postinstall shim for pre-firewall hooks | MEDIUM | Architectural; hooks run before the firewall loads |
| F-12: Runtime taint tracking | LOW | Requires dynamic analysis infrastructure |

### Policy signing key management

The dev key pair shipped in `scripts/` is for **development and CI only**. Before deploying to production:

1. Run `node scripts/generate-policy-key.js` and save the private key securely (never commit it).
2. Replace `DEV_PUBLIC_KEY_PEM` in `packages/fw-agent/src/policy-watcher.js` with your new public key.
3. Regenerate `.helios-baseline`: `node -e "const c=require('crypto'),f=require('fs'),files=['index.js','src/detector.js','src/behavior-tracker.js','src/policy-watcher.js','src/quarantine.js','src/audit-log.js','src/policy.js'],h=c.createHash('sha256');files.forEach(x=>h.update(f.readFileSync(x)));f.writeFileSync('.helios-baseline',h.digest('hex')+'\n');"` (from `packages/fw-agent/`).
4. Sign your policy rules: `node scripts/sign-policy.js your-private-key.pem rules.json`.
