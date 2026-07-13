# Helios firewall — demo

A self-contained demonstration of the Helios runtime firewall blocking malicious
Node modules at `require()` time while letting legitimate code through.

## Run it

```bash
bash demo/demo.sh
```

Expected output:

- **evil-miner** → `BLOCKED` (crypto-miner signature)
- **evil-stealer** → `BLOCKED` (credential exfiltration: sensitive-file read + network egress)
- **nice-analytics** → `ALLOWED` (benign network metrics — observed, not blocked)

The script exits non-zero if any module behaves unexpectedly (malware that
loads, or a clean module that is wrongly blocked), so it doubles as a smoke test.

## What's here

| File | Purpose |
| --- | --- |
| `demo.sh` | Entry point. Sets `FW_ENABLE_DETECTION=1`, runs both workloads. |
| `run-malware.js` | Loads the two malicious modules; expects both blocked. |
| `run-clean.js` | Loads the benign module; expects it allowed. |
| `modules/evil-miner.js` | Crypto-miner payload (matched by signature detector). |
| `modules/evil-stealer.js` | Credential stealer (matched by behavioral analyzer). |
| `modules/nice-analytics.js` | Legitimate analytics module (allowed). |

## How the firewall decides

The agent hooks `Module.prototype._compile` and screens every module before its
body executes:

- **Signature detection** — high-confidence malware strings (mining-pool
  identifiers, VM-escape calls) trigger a hard block. This catches
  `evil-miner.js`.
- **Behavioral analysis** — a sensitive-file read combined with network egress
  in the same module is flagged as `CREDENTIAL_EXFILTRATION` (CRITICAL) and
  blocked. This catches `evil-stealer.js`.
- **WARN-only observations** — an ordinary outbound network call (as in
  `nice-analytics.js`) is logged for visibility but never blocks on its own.
