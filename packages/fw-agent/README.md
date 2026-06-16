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
| `FW_TELEMETRY` | `0` | Reserved. No control plane ships in v0.1.0; forwards nothing. |
| `FW_CONTROL_PORT` | `3000` | Reserved. Port for a future hosted control plane; unused in v0.1.0. |
| `FW_STRICT_PRELOAD` | `0` | Set to `1` to exit if not loaded via `--require` |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Audit log directory |
| `HELIOS_BLOCK_SCRIPTS` | `1` | Set to `0` to warn instead of block suspicious npm scripts |

> Telemetry is **off by default** and inert in v0.1.0 -- `FW_TELEMETRY`/`FW_CONTROL_PORT` are reserved for a future hosted control plane and forward nothing until one is configured.

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

## Performance

Hook cost is sub-millisecond per module load and below measurement noise floor. At scale, GC and process-scheduler variance dominate over hook overhead. Empirical production metrics will show the true end-to-end impact.

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

## License

MIT
