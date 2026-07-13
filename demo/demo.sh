#!/usr/bin/env bash
# One-command demo for the Aletheia Runtime Firewall.
# Usage:  bash demo/demo.sh    (run from the repo root)
set -e
AGENT="../packages/fw-agent/index.js"
cd "$(dirname "$0")"
line() { printf '\n============================================================\n'; }

line; echo " 1) FIREWALL OFF  -  malware loads and runs freely"; line
node run-malware.js

line; echo " 2) FIREWALL ON   -  App A (malware) is blocked at require()"; line
FW_ENABLE_DETECTION=1 node --require "$AGENT" run-malware.js 2>&1 \
  | grep -vE "AGENT_START|\[Helios\]|Audit log|Exit 0|COMPILATION LOCKDOWN"

line; echo " 3) FIREWALL ON   -  App B (normal app) runs fine, no false alarm"; line
FW_ENABLE_DETECTION=1 node --require "$AGENT" run-clean.js 2>&1 \
  | grep -vE "AGENT_START|\[Helios\]|Audit log|Exit 0|COMPILATION LOCKDOWN"
echo
