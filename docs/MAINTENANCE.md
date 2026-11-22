# Maintenance and recovery

This runbook covers the operational recovery paths that are supported by the current agent.

## Policy failure

An invalid or missing signature on a present `policy.signed.json` produces emergency lockdown. Covered module loads throw until the process is restarted with a valid signed policy. There is no automatic fail-open or unsigned fallback.

A missing policy file at startup is detection-only (see ARCHITECTURE.md). Adding a file later does not activate monitoring until restart.

## Key loss

1. Generate a new keypair on a trusted machine (`npx aletheia-policy-keygen`).
2. Re-sign the current intended rules with the new private key.
3. Deploy the new `policy.signed.json` and set `FW_POLICY_PUBKEY` to the new public key.
4. Restart every protected process.

A process still trusting the old key will reject the new signature and enter lockdown.

## Key compromise

Treat every policy previously signed under the exposed key as untrusted.

1. Generate a new keypair on a trusted machine. Do not reuse the old files.
2. Re-sign the current intended rules and review them before deploying.
3. Replace `FW_POLICY_PUBKEY` everywhere it is set and restart every protected process.
4. Remove old policy files and backups signed by the compromised key from deployment paths.
5. Review audit logs for unexpected `POLICY_LOADED` / `POLICY_RELOADED` events.
6. Destroy remaining copies of the old private key.

There is no revocation list. Rotation + restart is the recovery mechanism.

## Performance gate

The repository maintains a 25% median compilation-overhead budget enforced by `npm run gate`. Run the gate on hardware with 4+ logical cores for a meaningful result. Historical v0.4.0 measurements and methodology live in `results/`. The gate is currently manual (not wired into CI).

## Publishing

Trusted Publishing (OIDC) is the intended path. No long-lived npm token is required in the repository. See `.github/workflows/publish.yml` and the package README for the current setup.
