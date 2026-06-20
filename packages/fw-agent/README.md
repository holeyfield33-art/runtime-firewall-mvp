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
| `FW_ENABLE_BEHAVIORAL` | `1` | Set to `0` to disable the behavioral pass while keeping signature scanning active. Useful as an escape hatch if behavioral detection produces false positives. With behavioral on: 14/14 adversarial test cases pass; with behavioral off: 12/14 (tests 6 and 7 assert a behavioral event type; both modules are still blocked by signature scanning). |
| `FW_TELEMETRY` | `0` | Set to `1` to start a telemetry worker that POSTs events to `FW_CONTROL_PORT`; with no control plane running it fails open and delivers nothing. |
| `FW_CONTROL_PORT` | `3000` | Port the telemetry worker POSTs to when `FW_TELEMETRY=1` (default 3000); no control plane ships in v0.1.0. |
| `FW_STRICT_PRELOAD` | `0` | Set to `1` to exit if not loaded via `--require` |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Audit log directory |
| `HELIOS_BLOCK_SCRIPTS` | `1` | Set to `0` to warn instead of block suspicious npm scripts |
| `BUN_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Bun; the agent exits with code 1 if absent |
| `DENO_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Deno; the agent exits with code 1 if absent |

> Telemetry is **off by default**. `FW_TELEMETRY=1` starts a telemetry worker that POSTs events to `FW_CONTROL_PORT`; with no control plane running it fails open and delivers nothing. No control plane ships in v0.1.0.

## Policy File

Create `policy.signed.json` in your working directory:

```json
{
  "rules": {
    "malware.js": "BLOCK",
    "untrusted-pkg.js": "QUARANTINE",
    "noisy-lib.js": "OBSERVE"
  }
}
```

- **BLOCK**: Module never runs.
- **QUARANTINE**: Exports replaced with a logging Proxy; child requires blocked.
- **OBSERVE** (default): Full behavioral + signature scan; blocks on detection.

> **Naming note:** The `.signed` convention in `policy.signed.json` means the file is SHA-256 integrity-monitored at runtime (re-verified every 60 seconds). This is **not** asymmetric or cryptographic signing — no keys or certificates are involved.

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
| Direct `eval("code")` | **BLOCKED** |
| `Buffer.from(b64).toString() -> eval` | **BLOCKED** |
| Crypto-miner stratum URL | **BLOCKED** |
| `process.env` + network call | **BLOCKED** |
| `eval` + `child_process.exec` | **BLOCKED** |
| `curl \| bash` in host project's npm scripts | **BLOCKED** (root scripts only; not dependency install hooks) |
| Bracket eval: `this["ev"+"al"]` | **BYPASSES** — needs AST analysis |
| String concat: `global["ev"+"al"]` | **BYPASSES** — needs taint tracking |
| Array join: `["ch","ild"].join("")` | **BYPASSES** — needs dynamic analysis |
| Prototype chain: `eval.constructor` | **BYPASSES** — needs runtime instrumentation |

## Behavioral Detection Limitations

Two pre-existing gaps are documented and tracked as roadmap items:

- **Sub-100B behavioral bypass:** the behavioral scanner skips modules shorter than 100 bytes. A payload consisting entirely of a dangerous action under 100 bytes evades the behavioral pass (signature scanning still applies to all non-empty modules).
- **Inline require NETWORK_EGRESS gap:** `require("https").get(...)` (inline, no separate variable assignment) does not match the behavioral `NETWORK_EGRESS` regex, which expects `https.get(`. Signature scanning covers the `https.request` and `http.request` patterns.

Both are MEDIUM findings. Fixes require engine changes (out of scope for docs-only releases).

## Tests

Tests live in the monorepo root — they are not included in the published package. To run them:

```bash
git clone https://github.com/holeyfield33-art/runtime-firewall-mvp
cd runtime-firewall-mvp
npm install
npm run test:unit         # Aho-Corasick + Detector
npm run test:adversarial  # 14 adversarial cases
npm test                  # all
```

## License

MIT
