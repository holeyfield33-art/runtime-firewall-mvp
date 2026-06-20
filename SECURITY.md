# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

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
