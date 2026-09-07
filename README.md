# Aletheia Runtime Enforcement
**Secure your Node.js supply chain with behavioral detection.**

[![CI](https://img.shields.io/github/actions/workflow/status/holeyfield33-art/runtime-firewall-mvp/ci.yml?branch=main&label=CI)](https://github.com/holeyfield33-art/runtime-firewall-mvp/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/holeyfield33-art/runtime-firewall-mvp/dynamic/github-code-scanning/codeql?branch=main&label=CodeQL)](https://github.com/holeyfield33-art/runtime-firewall-mvp/security/code-scanning)

Aletheia is a professional runtime enforcement layer for Node.js. It intercepts module compilation to detect and block malicious packages through a combination of **Behavioral State Machine Analysis**, **Aho-Corasick Signature Scanning**, and **Ed25519 Signed Policy Enforcement**.

Unlike static scanners, Aletheia watches what a dependency *actually does* once it's in your runtime, stopping credential exfiltration and crypto-miners in real-time.

**Core Capabilities:**
- ✅ **CommonJS Interception**: Hooks `Module.prototype._compile`.
- ✅ **ESM Support**: Synchronous ESM Customization Hooks (Node ≥22.15.0/≥23.5.0).
- ✅ **Behavioral Detection**: Blocks complex sequences (e.g., `.env` read $\rightarrow$ network call).
- ✅ **Signed Policy**: Emergency lockdown if the `policy.signed.json` is tampered with.
- ✅ **Self-Integrity**: SHA-256 baseline check of the firewall's own source on startup.

---

## 🚀 Quick Start

**Prerequisites:** Node.js ≥ 18

```bash
git clone https://github.com/holeyfield33-art/runtime-firewall-mvp
cd runtime-firewall-mvp
npm install

# Run your app with the enforcement layer preloaded
FW_ENABLE_DETECTION=1 node --require=./packages/fw-agent app.js
```

### Control Plane (Telemetry & Dashboard)
Forward security events to a central dashboard for real-time monitoring:

```bash
# Terminal 1: Start Control Plane (Port 3000)
node packages/fw-control/src/server.js

# Terminal 2: Run App with Telemetry
FW_ENABLE_DETECTION=1 FW_TELEMETRY=1 node --require=./packages/fw-agent app.js
```

---

## 🛡️ Security Architecture

### 1. Behavioral Detection (State Machine)
Aletheia tracks dangerous action sequences. If a module exhibits a critical pattern, it is blocked immediately.

| Rule | Trigger | Severity | Action |
|------|---------|----------|--------|
| `CREDENTIAL_EXFILTRATION` | Sensitive path read + Network call | CRITICAL | Block |
| `DYNAMIC_CODE_EXEC_CHAIN` | `eval` / `new Function` + `child_process.exec` | CRITICAL | Block |
| `OBFUSCATED_CODE_EXECUTION` | Decode blob + Evaluate as code | HIGH | Block |

### 2. Signature Scanner
High-performance O(N) pattern matching covering crypto-miners, supply-chain worms, and unauthorized network egress.

### 3. Signed Policy Enforcement
Policies are distributed as signed envelopes (`policy.signed.json`). Aletheia uses **Ed25519 signatures** to ensure the policy hasn't been modified by an attacker.

---

## 📊 Performance & Trust

Aletheia is designed for production. It maintains a strict overhead budget to ensure security doesn't compromise availability.

- **Median Overhead**: ~25% compilation overhead (budgeted).
- **Deterministic**: No "black box" AI; decisions are based on explicit signatures and behavioral rules.
- **Zero-Trust**: Fails closed in `FW_MODE=enforce` if the agent is not preloaded correctly.

## 🧪 Testing & Red-Teaming
We believe in evidence. Run our adversarial suite to see the firewall in action:
```bash
npm run redteam
```
**Current Efficacy**: 76% of malicious payloads in our adversarial corpus are blocked. All bypasses are documented in `docs/THREAT-COVERAGE.md`.

---

## 🛠️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FW_ENABLE_DETECTION` | `0` | Set to `1` to activate the enforcement layer. |
| `FW_MODE` | `dev` | `enforce` fails closed if not preloaded via `--require`. |
| `FW_POLICY_PUBKEY` | *(dev key)* | Ed25519 public key for policy verification. |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Directory for the persistent audit log. |
