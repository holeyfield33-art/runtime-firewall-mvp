# Aletheia Firewall

Zero-dependency runtime firewall that blocks malicious npm modules at require-time through behavioral detection, Aho-Corasick signature scanning, and tamper-evident policy enforcement.

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
| `FW_TELEMETRY` | `0` | Set to `1` to forward events to the control plane |
| `FW_CONTROL_PORT` | `3000` | Control plane port |
| `FW_STRICT_PRELOAD` | `0` | Set to `1` to exit if not loaded via `--require` |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Audit log directory |
| `HELIOS_DASHBOARD_TOKEN` | *(none)* | Bearer token for the `/logs` dashboard endpoint |
| `HELIOS_BLOCK_SCRIPTS` | `1` | Set to `0` to warn instead of block suspicious npm scripts |

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
| `curl \| bash` postinstall | **BLOCKED** |
| Bracket eval: `this["ev"+"al"]` | **BYPASSES** — needs AST analysis |
| String concat: `global["ev"+"al"]` | **BYPASSES** — needs taint tracking |
| Array join: `["ch","ild"].join("")` | **BYPASSES** — needs dynamic analysis |
| Prototype chain: `eval.constructor` | **BYPASSES** — needs runtime instrumentation |

## License

MIT
