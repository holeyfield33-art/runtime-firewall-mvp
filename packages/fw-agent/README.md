# Aletheia Firewall

Zero-dependency runtime firewall that blocks malicious npm modules at require-time through behavioral detection, Aho-Corasick signature scanning, and policy enforcement.

## Install

```bash
npm install aletheia-firewall
```

## Usage

```bash
FW_ENABLE_DETECTION=1 node --require aletheia-firewall app.js
```

For Bun:

```bash
FW_ENABLE_DETECTION=1 BUN_PRELOAD=aletheia-firewall bun app.js
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FW_ENABLE_DETECTION` | `0` | Set to `1` to activate the firewall (required) |
| `FW_ENABLE_BEHAVIORAL` | `1` | Set to `0` to disable the behavioral pass while keeping signature scanning active. Useful as an escape hatch if behavioral detection produces false positives. Note: several detections (credential exfiltration, dynamic-code/exec chains, base64→eval obfuscation) rely on the behavioral pass — disabling it falls back to signature-only coverage. |
| `FW_TELEMETRY` | `0` | Set to `1` to start a telemetry worker that POSTs events to `FW_CONTROL_PORT`; with no control plane running it fails open and delivers nothing. |
| `FW_CONTROL_PORT` | `3000` | Port for the control plane telemetry ingestion endpoint (`fw-control`). Used by the telemetry worker when `FW_TELEMETRY=1`. |
| `FW_STRICT_PRELOAD` | `0` | Set to `1` to exit if not loaded via `--require` |
| `FW_FREEZE_PROTOTYPES` | `0` | Set to `1` to freeze built-in prototypes (prototype-pollution hardening; opt-in because it breaks some polyfills and test frameworks) |
| `FW_POLICY_PUBKEY` | *(dev key)* | PEM-encoded Ed25519 SPKI public key for verifying `policy.signed.json`. **Must be set in production** — the bundled dev private key is public. |
| `FW_ALLOW_DEV_POLICY_KEY` | `0` | Set to `1` to allow the dev key when `FW_POLICY_PUBKEY` is unset (local/dev/CI). Agent refuses to start with a policy file present and no production key unless this flag is set. |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Audit log directory |
| `HELIOS_BLOCK_SCRIPTS` | `1` | Set to `0` to warn instead of block suspicious npm scripts |
| `BUN_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Bun; the agent exits with code 1 if absent |
| `DENO_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Deno; the agent exits with code 1 if absent |

> Telemetry is **off by default**. `FW_TELEMETRY=1` starts a telemetry worker that POSTs events to the control plane at `FW_CONTROL_PORT`. The control plane (`fw-control`) ships in this repo and can be started with `npm run start:control`.

## Policy File

`policy.signed.json` must be a **signed envelope** (`{ version, rules, signedAt, signature }`) —
an unsigned `{ "rules": … }` object fails verification on startup and triggers emergency lockdown.
Author a plain rules file and sign it:

```bash
echo '{ "malware.js": "BLOCK", "untrusted-pkg.js": "QUARANTINE", "noisy-lib.js": "OBSERVE" }' > rules.json
node scripts/sign-policy.js scripts/dev-private-key.pem rules.json policy.signed.json
```

For the bundled dev key you must run with `FW_ALLOW_DEV_POLICY_KEY=1`; in production sign with your
own key (`scripts/generate-policy-key.js`) and set `FW_POLICY_PUBKEY`.

- **BLOCK**: Module never runs.
- **QUARANTINE**: Exports replaced with a logging Proxy; child requires blocked.
- **OBSERVE** (default): Full behavioral + signature scan; blocks on detection.

> **Signing:** `policy.signed.json` carries a real **Ed25519 signature** over its canonical
> payload `{ version, rules (keys sorted), signedAt }`, re-verified every 60 seconds. An invalid
> or missing signature triggers emergency lockdown. The verifying public key is compiled into
> `src/policy-watcher.js` and overridable via `FW_POLICY_PUBKEY`; author a rules file and sign it
> with `scripts/sign-policy.js`. (Since v0.2.0 this replaced the earlier SHA-256 trust-on-first-use
> baseline — earlier docs describing SHA-256-only monitoring are obsolete.)

## Performance

The firewall's cost is a **one-time per-module compile scan** — the `Module._compile` hook runs once per file on first load, then a compilation cache short-circuits it. There is **zero overhead when `FW_ENABLE_DETECTION` is unset** (`index.js` returns immediately and installs no hook).

Measured on a 900-module cold load (methodology: `packages/fw-control/test/bench.js` in the monorepo), AMD EPYC, Node v22 (CI: 18, 20, 22), Linux x64:

| Metric | Measured | Gate budget | Enforced? |
|--------|----------|-------------|-----------|
| Median module-compile overhead | ~17–21% (varies by host) | 25% | **Yes** |
| P95 overhead | ~25–37% across hosts | 30% (reference) | No — informational |

Environment: measured on two AMD EPYC Codespaces — 9V74 (80-core) and 7763 (64-core), Node v22. The median is host-dependent (7763 ~17%, 9V74 ~20–21%); after the v0.1.0 sub-512B scan-skip fix the measured range is ~17–21%.

The gate **enforces median only** (budget 25%). P95 (~25–37%) is informational and **not stable across hardware** — it reflects shared-CPU scheduler contention on multi-tenant Codespaces, not firewall algorithmic cost — so it is reported but never gated.

To reproduce, run the 900-module gate from the GitHub repo: `npm run gate`.

## Known Bypasses

This firewall provides defense-in-depth but cannot catch all threats. Documented bypasses require dynamic or AST-level analysis:

| Technique | Status |
|-----------|--------|
| Direct `eval("code")` + exec | **BLOCKED** (behavioral `DYNAMIC_CODE_EXEC_CHAIN`) |
| `Buffer.from(b64,'base64').toString() -> eval` | **BLOCKED** (behavioral `OBFUSCATED_CODE_EXECUTION`; bare `buffer.from`/`eval(` are WARN-only, the decode+eval combination blocks) |
| `atob`/hex-decode -> `new Function` | **BLOCKED** (behavioral `OBFUSCATED_CODE_EXECUTION`) |
| Crypto-miner stratum URL | **BLOCKED** |
| `.env`/credential read + network call | **BLOCKED** |
| `eval` + `child_process.exec` | **BLOCKED** |
| `curl \| bash` in host project's npm scripts | **BLOCKED** (root scripts only; not dependency install hooks) |
| Bracket eval: `this["ev"+"al"]` | **BYPASSES** — needs AST analysis |
| String concat: `global["ev"+"al"]` | **BYPASSES** — needs taint tracking |
| Variable-alias eval: `const fn = eval; fn("code")` | **BYPASSES** — needs runtime Proxy / taint tracking |
| Array join: `["ch","ild"].join("")` | **BYPASSES (per-module)** — may be caught by cross-module state |
| Prototype chain: `eval.constructor` | **BYPASSES** — needs runtime instrumentation |

See the monorepo's `docs/THREAT-COVERAGE.md` for the full, test-backed protection/bypass matrix.

## Behavioral Detection Notes

- **`process.env` + network egress is intentionally NOT blocked** (WARN only): it is the everyday
  pattern legitimate analytics/telemetry SDKs use. Only a genuine credential *path* (`.env`, `.ssh`,
  `id_rsa`, …) or `.npmrc` token/host/hardcoded-exfil signal escalates to a CRITICAL block.
- **Dynamic `require(variable)`** surfaces as an `OBSERVE`/telemetry signal, not a block —
  non-literal `require` is pervasive in legitimate code (lazy loading, plugin systems).

## Tests

Tests live in the monorepo root — they are not included in the published package. To run them:

```bash
git clone https://github.com/holeyfield33-art/runtime-firewall-mvp
cd runtime-firewall-mvp
npm install
npm run test:unit         # Aho-Corasick + Detector
npm run test:adversarial  # adversarial bypass cases
npm run test:coverage     # engine-core coverage gate (95%)
npm test                  # all
```

## License

MIT
