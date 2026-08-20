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

There is **no shared dev private key committed to this repository.** `DEV_PUBLIC_KEY_PEM` in
`packages/fw-agent/src/policy-watcher.js` is a public key with no matching private key held by
anyone — it exists only so `policy.signed.json` fixtures the project ships (empty-rules demo
files) can carry a valid signature, and so `FW_ALLOW_DEV_POLICY_KEY=1` has something concrete to
gate. Before deploying to production:

1. Run `node scripts/generate-policy-key.js` and keep the private key on your own machine —
   never commit it, never share it, and never write it to a path inside this repository.
2. Either set `FW_POLICY_PUBKEY` to your new public key at runtime (recommended — no source
   change needed), or replace `DEV_PUBLIC_KEY_PEM` in `packages/fw-agent/src/policy-watcher.js`
   for your own fork.
3. If you edited `policy-watcher.js`, regenerate `.helios-baseline`: `npm run baseline` (from
   the repo root). Do not hand-roll the hashing snippet — `scripts/generate-baseline.js` is the
   single source of truth for the hashed file list and hashing method; see `CONTRIBUTING.md`.
4. Sign your policy rules: `node scripts/sign-policy.js your-private-key.pem rules.json`.

#### Key revocation record (F-62, 2026-08-20)

`scripts/dev-private-key.pem` — a shared development/CI private key — was committed to this
public repository from the project's early history through the v0.5.0 release. Its matching
public key was hardcoded as `DEV_PUBLIC_KEY_PEM`. Anyone with read access to the repository
(or its git history) could use it to forge a validly-signed `policy.signed.json`; the only
guard was the `FW_ALLOW_DEV_POLICY_KEY=1` opt-in (required by `PolicyWatcher.start()`) and the
`NODE_ENV=production` check in `assertProductionKeyConfig()`, both of which depend on correct
deployment configuration rather than on the key itself being untrusted.

As part of this hardening pass:

- `scripts/dev-private-key.pem` was **deleted from `HEAD`**. `DEV_PUBLIC_KEY_PEM` was rotated to
  a freshly generated public key whose private counterpart has never been committed anywhere,
  in this repository or elsewhere, and never will be.
- The old private key **remains recoverable from this repository's git history** — history was
  deliberately not rewritten in this change (a separate, explicit decision, not an oversight).
  Treat every signature produced by the old key as **permanently untrusted**: a
  freshly-rotated agent rejects it regardless of `FW_ALLOW_DEV_POLICY_KEY`, because it no longer
  matches the bundled `DEV_PUBLIC_KEY_PEM` or any key an operator would configure via
  `FW_POLICY_PUBKEY`.
- Production deployments were already required to set `FW_POLICY_PUBKEY` explicitly
  (`assertProductionKeyConfig()` refuses to start under `NODE_ENV=production` against the
  bundled dev key without it); this rotation does not change that contract, it only closes the
  exposure window for anyone who was relying on the bundled key outside of local dev/CI.
