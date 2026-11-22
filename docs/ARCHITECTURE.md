# Architecture

Aletheia Firewall is an opt-in, in-process Node.js runtime firewall. It activates only when explicitly preloaded (`node --require=aletheia-firewall`) and `FW_ENABLE_DETECTION=1` is set.

## Trust boundaries

- **Customer owns policy authority.** The Ed25519 private key and `policy.signed.json` are controlled by the operator. `FW_POLICY_PUBKEY` is the trust anchor.
- **Same-process ceiling.** The agent runs in the same process as the application. A fully compromised process can mutate primitives the agent relies on. This is a documented limitation, not a containment boundary.
- **Covered load paths.** CommonJS `require()` via `Module._compile` is covered. ESM static/dynamic `import` is covered only on Node ≥22.15.0 / ≥23.5.0. Lifecycle scripts, native addons, and `data:` URLs are outside the covered surface.
- **No network required for enforcement.** An installed copy enforces local policy without contacting the publisher.

## Activation and posture

- Absent policy file at startup → detection-only mode. Built-in signature and behavioral detection remain active; customer-signed rules and policy monitoring are inactive. A policy file added later is not picked up until restart.
- Valid signed policy → rules applied; `POLICY_LOADED` recorded.
- Invalid signature → emergency lockdown. Subsequent covered module loads throw.
- `POLICY_RELOADED` records applied rule-set changes only (rules hash differs). Same-rules re-signing emits no event. `previousPolicyHash` / `previousSignedAt` identify the previous applied rule set’s envelope. Older authentic policies with different rules remain accepted (replay is a documented limitation).

## Policy format

`policy.signed.json` is an Ed25519-signed envelope:

```json
{ "version": 1, "rules": { ... }, "signedAt": "YYYY-MM-DDTHH:mm:ss.sssZ", "signature": "base64url" }
```

`signedAt` must be a UTC ISO-8601 timestamp with milliseconds (the exact form produced by `new Date().toISOString()`). Type, syntax, and calendar validity are checked in signing, verification, and the runtime watcher. The original timestamp string is preserved for accepted envelopes.

## Recovery

Key loss and key compromise both require generating a new keypair, re-signing the intended rules, updating `FW_POLICY_PUBKEY`, and restarting protected processes. Compromise additionally requires treating all prior signatures under the exposed key as untrusted. See the package README for the full procedure.

This document describes the current implementation as of the merged posture, reload-contract, and signedAt-validation changes. It is not a design proposal.
