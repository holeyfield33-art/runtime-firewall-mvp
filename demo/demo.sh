#!/usr/bin/env bash
#
# demo/demo.sh — end-to-end demonstration of the Helios runtime firewall.
#
# Runs a malicious workload (a crypto-miner and a credential stealer) and a
# clean workload (a benign analytics module) through the agent. Expected result:
#
#   * evil-miner    -> BLOCKED
#   * evil-stealer  -> BLOCKED
#   * nice-analytics-> ALLOWED
#
# Exits non-zero if any expectation is not met.

set -euo pipefail

# Run from the repo root so the agent finds policy.signed.json in the cwd.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

export FW_ENABLE_DETECTION=1
export FW_ALLOW_DEV_POLICY_KEY=1

echo "######################################################################"
echo "#  Helios runtime firewall — live demo"
echo "######################################################################"

node demo/run-malware.js
echo
node demo/run-clean.js

echo
echo "######################################################################"
echo "#  Demo complete: malware BLOCKED, legitimate module ALLOWED."
echo "######################################################################"
