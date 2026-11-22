# Aletheia Firewall

Zero-dependency, opt-in runtime enforcement layer for supported Node.js module-loading paths. It
scans modules as they are compiled/loaded (`require()` of `.js`/`.cjs`, and `import` of `file://`
ESM on supported Node versions) using Aho-Corasick signature matching, behavioral-sequence
correlation, and — opt-in — a narrow AST obfuscation tier, then enforces a signed policy. It is
defense-in-depth, **not** a comprehensive malware blocker: it covers specific module-loading paths
(see the coverage table below) and a documented set of techniques, with known gaps listed honestly.

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

> **ESM coverage requires Node ≥22.15.0 / ≥23.5.0.** Below that floor, CommonJS `require()`
> coverage is unaffected, but `import`/`import()` runs unprotected — see the version-floor note
> below. If your deployment depends on ESM coverage, set **`FW_REQUIRE_ESM_COVERAGE=1`** so the
> agent refuses to start where ESM interception is unavailable. `FW_MODE=enforce` on its own does
> **not** guarantee ESM protection.

## Quick start: signed policy (no source checkout needed)

The key-generation and signing tools ship in this package as CLI commands:

```bash
npx aletheia-policy-keygen      # writes aletheia-policy-private.pem (0600) + aletheia-policy-public.pem
                                # the private key is never printed; existing key files are never overwritten
echo '{ "some-package": "BLOCK" }' > rules.json
npx aletheia-policy-sign aletheia-policy-private.pem rules.json policy.signed.json

# Production configuration: trust YOUR public key via FW_POLICY_PUBKEY.
export FW_POLICY_PUBKEY="$(cat aletheia-policy-public.pem)"
FW_ENABLE_DETECTION=1 node --require aletheia-firewall app.js   # run from the directory holding policy.signed.json
```

Keep the private key off production hosts and out of source control — the runtime only needs the
public key. `policy.signed.json` is read from **`process.cwd()`** at startup (see
[Policy File](#policy-file)).

## Coverage & Limitations

Aletheia hooks `Module.prototype._compile` (Node's CommonJS compilation step) and, on a
supported Node version, `module.registerHooks()` (Node's synchronous ESM Customization Hooks
API) for the ES module loader. This means:

| Load path | Covered |
|---|---|
| `require()` of `.js` / `.cjs` | ✅ |
| `import` / `import()` of a `file://` module URL (ESM, `.mjs`, or `.js` under `"type": "module"`) | ✅ on Node ≥22.15.0 / ≥23.5.0 — ❌ below that floor (see note) |
| `import()` of a `data:`, `http:`, `https:`, or `blob:` module URL | ❌ always — see note |
| `.json` requires | ❌ handled by Node core, bypasses `_compile` |
| Native addons (`.node`) | ❌ not JS, not scanned |
| Dependency npm lifecycle scripts (preinstall/postinstall) | ❌ run before the firewall loads |

**ESM version floor:** `module.registerHooks()` — the non-deprecated, synchronous ESM hook API —
requires Node ≥22.15.0 or ≥23.5.0. The package's declared `engines` floor (`>=18.0.0`) covers
its CommonJS functionality; below the ESM-specific floor, `import`/`import()` runs
**unprotected**, with a loud warning — never silently claimed as covered. Under
`FW_MODE=enforce` that warning is escalated to a `[CRITICAL]` message and an
`ESM_HOOK_UNAVAILABLE` audit event, **but the process still starts and ESM still runs
unprotected** (`FW_MODE=enforce` governs the preload requirement, not the Node version). To fail
closed when ESM coverage is unavailable, set `FW_REQUIRE_ESM_COVERAGE=1`: the agent then exits
with code 1 at startup on an unsupported Node version, and starts normally on a supported one.

**ESM module-URL scheme:** even on a supported Node version, ESM coverage only applies to
`file://` module URLs. The load hook returns before the detector runs for any other scheme, so
`import()` of a `data:`, `http:`, `https:`, or `blob:` URL is **unprotected on every Node
version**, floor or no floor — this is a separate gap from the version floor above, not covered
by it. See [`docs/THREAT-COVERAGE.md`](https://github.com/Enkidagoat/runtime-firewall-mvp/blob/main/docs/THREAT-COVERAGE.md)'s execution-path table for the full breakdown.

Aletheia is a **runtime enforcement layer**: it watches what a dependency does once it's
already in your CommonJS require graph, after `npm install` has finished. It is not an
install-time scanner and does not intercept package installation.

Detection runs in tiers: **signature + behavioral by default**, plus an **opt-in AST obfuscation
tier** (`FW_ENABLE_AST=1`, off by default pending a broader benign-package soak). By default,
payloads can still evade static matching through string-splitting, encoding, or indirection; the
AST tier folds and structurally resolves many of those. Our adversarial corpus documents both
honestly:

| Configuration | Malicious caught | Known bypasses | False positives* |
|---|---|---|---|
| **Default** (`FW_ENABLE_AST` unset) | **105/143 (73.4%)** | 38 | 0 / 36 controls |
| **`FW_ENABLE_AST=1`** (opt-in) | **127/143 (88.8%)** | 16 | 0 / 36 controls |

\* "0 false positives" means zero across the **36 curated benign controls** — it is **not** a
measured general false-positive rate on arbitrary packages, which is one reason the AST tier ships
opt-in. Run them yourself from the repository root: `npm run redteam` (default) and
`npm run redteam:ast` (AST tier).

**Bounded, prioritized AST scanning.** The AST tier parses a bounded number of candidate spans per
file and scans them **highest-risk-first** (never in file order), so a payload can't be starved by a
flood of harmless decoy spans placed ahead of it. If a genuinely high-risk span is left unanalyzed
because the budget was exhausted, the scan is reported *incomplete* and `FW_AST_INCOMPLETE_POLICY`
decides what happens (see the environment-variable table).

Every bypass class is listed in [`red-team/README.md`](https://github.com/Enkidagoat/runtime-firewall-mvp/blob/main/red-team/README.md) and the monorepo's
[`docs/THREAT-COVERAGE.md`](https://github.com/Enkidagoat/runtime-firewall-mvp/blob/main/docs/THREAT-COVERAGE.md).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FW_ENABLE_DETECTION` | `0` | Set to `1` to activate the firewall (required) |
| `FW_ENABLE_BEHAVIORAL` | `1` | Set to `0` to disable the behavioral pass while keeping signature scanning active. Useful as an escape hatch if behavioral detection produces false positives. Note: several detections (credential exfiltration, dynamic-code/exec chains, base64→eval obfuscation) rely on the behavioral pass — disabling it falls back to signature-only coverage. |
| `FW_ENABLE_AST` | `0` | Set to `1` to enable the opt-in AST obfuscation tier (`src/ast-scan.js`). Folds/resolves bracket-, alias-, unicode-escape-, concat-, decode-, and constructor-based obfuscation of `eval`/`Function`/`require`. Raises malicious coverage from 73.4% to 88.8% on the corpus (see the table above). Off by default pending a broader benign-package soak; it is internally fail-open (any error falls back to signature+behavioral). |
| `FW_AST_INCOMPLETE_POLICY` | `quarantine` | Only relevant when `FW_ENABLE_AST=1`. Governs what happens when a module is so densely packed with high-risk obfuscation shapes that the AST tier could not fully analyze it (an *incomplete* scan — the span-exhaustion attack shape). Defaults to **fail-closed** (`quarantine`/`block`): an un-analyzable suspicious module is treated as block-tier, so the bypass is closed by default rather than only for operators who opt in. Set `observe` to opt down to WARN-only telemetry (module still runs) if you prefer availability. Only fires on pathological saturation (>256 rare high-risk spans in one module); ordinary large bundles never reach it. |
| `FW_ENABLE_CROSSFILE` | `0` | Set to `1` to enable cross-file behavioral correlation within a package (capabilities split across files). Off by default: it false-positives on large legitimate packages that legitimately split credential reads, metadata fetches, and code-gen/spawn across files. Intended for curated dependency sets and the registry batch scanner. |
| `FW_CACHE_POLICY` | `block` under `FW_MODE=enforce`, else `audit` | How `require.cache`/`Module._load` pre-seeding (a forged cache entry that bypasses `_compile` entirely) is handled: `block` refuses the substitution, `audit` allows it but logs, `allow` disables the check. |
| `FW_TELEMETRY` | `0` | Set to `1` to start a telemetry worker that POSTs events to `FW_CONTROL_PORT`; with no control plane running it fails open and delivers nothing. |
| `FW_CONTROL_PORT` | `3000` | Port for the control plane telemetry ingestion endpoint (`fw-control`). Used by the telemetry worker when `FW_TELEMETRY=1`. |
| `FW_TELEMETRY_TOKEN` | *(none)* | Bearer token sent with every `/v1/telemetry` request when `FW_TELEMETRY=1`. Must match the control plane's own `FW_TELEMETRY_TOKEN`; required if the control plane is reachable beyond the local host. |
| `FW_MODE` | `dev` | `enforce` fails closed (`process.exit(1)`) when not preloaded via `--require`; `dev` (default) warns loudly and continues. `enforce` does **not** make an unsupported Node version fatal for ESM (it logs `[CRITICAL]` and continues) — use `FW_REQUIRE_ESM_COVERAGE=1` for that. See the [root README](https://github.com/Enkidagoat/runtime-firewall-mvp/blob/main/README.md)'s "Enforcement mode vs Development mode" section. |
| `FW_REQUIRE_ESM_COVERAGE` | `0` | Set to `1` to refuse to start (`process.exit(1)`) when ESM interception is unavailable (Node below ≥22.15.0 / ≥23.5.0, or hook registration failed). Independent of `FW_MODE`. Recommended for any deployment that loads ESM dependencies. |
| `FW_STRICT_PRELOAD` | `0` | Set to `1` to exit if not loaded via `--require` (backward-compatible alias for `FW_MODE=enforce`) |
| `FW_FREEZE_PROTOTYPES` | `0` | Set to `1` to freeze built-in prototypes (prototype-pollution hardening; opt-in because it breaks some polyfills and test frameworks) |
| `FW_POLICY_PUBKEY` | *(bundled dev public key)* | PEM-encoded Ed25519 SPKI public key for verifying `policy.signed.json`. **This is the production configuration — set it to your own public key** (e.g. `export FW_POLICY_PUBKEY="$(cat aletheia-policy-public.pem)"`). The bundled default is a shared, published dev *public* key; no one holds its private key (an earlier, committed dev private key was revoked under F-62 — see SECURITY.md in the repository), but it is not your trust anchor and must not be relied on in production. |
| `FW_ALLOW_DEV_POLICY_KEY` | `0` | Set to `1` to allow the bundled dev public key when `FW_POLICY_PUBKEY` is unset (local/dev/CI only). The agent refuses to start with a policy file present and no `FW_POLICY_PUBKEY` unless this flag is set. |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Audit log directory |
| `HELIOS_BLOCK_SCRIPTS` | `1` | Set to `0` to warn instead of block suspicious npm scripts |
| `BUN_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Bun; the agent exits with code 1 if absent |
| `DENO_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Deno; the agent exits with code 1 if absent |

> Telemetry is **off by default**. `FW_TELEMETRY=1` starts a telemetry worker that POSTs events to the control plane at `FW_CONTROL_PORT`. The control plane (`fw-control`) ships in this repo and can be started with `npm run start:control`.

## Policy File

**Location:** the agent reads `policy.signed.json` from **`process.cwd()` at startup** — the
directory the Node process is started from, not the directory of your app or of `node_modules`.
The path is not configurable in this release. Start your process from the directory that holds the
policy file.

**No policy file = detection-only.** If detection is enabled and no file exists at that path, the
agent prints one `[Helios] DETECTION-ONLY` warning and writes one `POLICY_ABSENT_DETECTION_ONLY`
audit event: built-in signature/behavioral detection stays active, but your signed
BLOCK/QUARANTINE/OBSERVE rules and policy integrity monitoring are **inactive** for that process
(a file added later is not picked up until restart). This is reported the same way under
`FW_MODE=enforce`; it is not an error.

`policy.signed.json` must be a **signed envelope** (`{ version, rules, signedAt, signature }`) —
an unsigned `{ "rules": … }` object, a tampered file, or a signature from a key other than
`FW_POLICY_PUBKEY` fails verification and triggers **emergency lockdown** (all module loads
blocked). It never silently downgrades to detection-only. Author a plain rules file and sign it
with the CLIs shipped in this package:

```bash
npx aletheia-policy-keygen [--private-key <file>] [--public-key <file>] [--force]
echo '{ "malware.js": "BLOCK", "untrusted-pkg.js": "QUARANTINE", "noisy-lib.js": "OBSERVE" }' > rules.json
npx aletheia-policy-sign aletheia-policy-private.pem rules.json policy.signed.json
export FW_POLICY_PUBKEY="$(cat aletheia-policy-public.pem)"
```

`aletheia-policy-keygen` writes the private key with mode 0600, never prints it, and refuses to
overwrite an existing key file unless `--force` is given. `aletheia-policy-sign` self-verifies
the signature before writing and prints the public-key fingerprint it verifies under. Do not edit
files under `node_modules` to change the trusted key — `FW_POLICY_PUBKEY` is the supported
configuration.

- **BLOCK**: Module never runs; `require()`/`import` throws.
- **QUARANTINE**: Module never runs. On Node **below** 22.15.0 / 23.5.0 (and, on any Node, for a
  `.js` file whose nearest `package.json` has no `"type"` field) the exports are replaced with a
  logging Proxy and child requires are blocked. On Node **≥22.15.0 / ≥23.5.0**, a CommonJS load
  whose format Node knows up front — a `.cjs` file, or a `.js` file under `"type": "commonjs"`
  (which `npm init -y` writes by default on npm ≥11) — and every ESM load goes through the ESM load
  hook, which cannot substitute exports, so **QUARANTINE acts as a hard BLOCK** there:
  `require()` throws `[Firewall] Compilation denied …`. Plan for both behaviors.
- **OBSERVE** (default): Full behavioral + signature scan; blocks on detection.

**Reloads and replay.** The file is re-verified every 60 seconds. A changed, validly signed policy
is hot-reloaded and recorded as a `POLICY_RELOADED` audit event with the new file's SHA-256,
its `signedAt`, the previous hash/`signedAt`, and `signedAtNotNewerThanPrevious`; the policy
active at startup is recorded as `POLICY_LOADED`. **Any envelope authentically signed by the
trusted key is accepted — including an older one.** Someone who can write `policy.signed.json`
can replay a previously signed (e.g. less restrictive) policy, live or at restart. The audit
events make that visible after the fact; they do **not** prevent it. Protect write access to the
policy file and the directory it lives in.

### Key loss and key compromise

The trusted key is whatever `FW_POLICY_PUBKEY` contains; there is no revocation list.

- **Private key lost** (no compromise): run `npx aletheia-policy-keygen` (use `--force` only if you
  intend to replace the old files), re-sign your rules with the new private key, deploy the new
  `policy.signed.json` **and** the new `FW_POLICY_PUBKEY` together, then restart. A process still
  trusting the old key will reject the new signature and enter emergency lockdown — it fails
  closed, not open — so roll out both values at once.
- **Private key compromised** (or suspected): treat every policy signed under that key as
  untrusted, including ones you signed yourself, because an attacker can mint or replay them.
  1. Generate a new key pair on a trusted machine; do not reuse the old key files.
  2. Re-sign the current intended rules with the new key and review them before deploying.
  3. Replace `FW_POLICY_PUBKEY` everywhere it is set (environment, secrets store, container
     images, CI) and restart every protected process — a running process keeps trusting the key
     it started with.
  4. Remove old policy files and backups signed by the compromised key from deployment paths; after
     rotation they fail verification (lockdown) rather than load.
  5. Review audit logs for `POLICY_LOADED` / `POLICY_RELOADED` events whose `policyHash` you did not
     deploy, and for `POLICY_TAMPER_LOCKDOWN`.
  6. Destroy the old private key copies.

> **Signing:** `policy.signed.json` carries a real **Ed25519 signature** over its canonical
> payload `{ version, rules (keys sorted), signedAt }`, re-verified every 60 seconds. An invalid
> signature on a present file triggers emergency lockdown; an absent file means detection-only
> (above). The verifying key is `FW_POLICY_PUBKEY` (a bundled dev public key is the fallback for
> local/dev/CI only); sign with `npx aletheia-policy-sign`. (Since v0.2.0 this replaced the earlier
> SHA-256 trust-on-first-use baseline — earlier docs describing SHA-256-only monitoring are obsolete.)

## Release integrity

- **v0.6.2** on npm is **registry-signed** (verify with `npm audit signatures`) and was
  independently **byte-reproduced** from tag `v0.6.2` (commit `cf59c98`, tarball sha256
  `86497590eefdcfc3c7b6dcb1f7f8ae809863d6dd4dba66e62a2f57be3f06598b`), but it has **no npm
  provenance (SLSA) attestation**: it was published manually after the Trusted Publishing step
  failed. A registry signature proves the registry is serving the bytes it received from an
  authenticated publisher account; it does **not** prove which source commit or CI workflow built
  them — that is what a provenance attestation adds.
- **v0.5.0 and v0.6.0** carry npm provenance attestations
  (`npm view aletheia-firewall@0.6.0 dist.attestations`).
- Later releases are intended to be published only through the repository's Trusted Publishing
  workflow with provenance; check `dist.attestations` for the version you install rather than
  assuming it.

## Performance

The firewall's cost is a **one-time per-module compile scan** — the `Module._compile` hook runs once per file on first load, then a compilation cache short-circuits repeat compilations. There is **zero overhead when `FW_ENABLE_DETECTION` is unset** (`index.js` returns immediately and installs no hook).

The repo maintains a 25% median compilation-overhead gate budget, but this is a regression threshold, not a published release guarantee. The v0.4.0 frozen evidence (the most recent controlled performance freeze — see the note below) shows the runtime `Module._compile` interception path is the dominant steady-state cost; `Detector.scanModuleSync` is a secondary contributor in the verified 900-module workload.

| Metric | Budget | Enforced? |
|--------|--------|-----------|
| Median module-compile overhead | 25% | Manual only — the gate is not wired into CI (AUDIT.md finding #4) |
| P95 overhead | 30% (informational only) | No |

The gate is a **regression guard**, not a performance target. If the median exceeds 25%, the change needs review.

For the v0.4.0 frozen baseline and diagnostic evidence, see [`PERFORMANCE.md`](https://github.com/Enkidagoat/runtime-firewall-mvp/blob/main/PERFORMANCE.md) and `results/benchmarks/steady-state-compile-attr-*.json` in the repository. This is the most recent controlled performance freeze in the repo; no v0.5.0-specific freeze has been published yet, so treat these numbers as last-measured-at-v0.4.0, not as a v0.5.0 guarantee.

To reproduce, run the 900-module gate from the GitHub repo: `npm run gate`.

## Known Bypasses

This firewall provides defense-in-depth but cannot catch all threats. "Status" below is split by
tier: default (signature + behavioral) and `FW_ENABLE_AST=1` (the opt-in AST tier).

| Technique | Status |
|-----------|--------|
| Direct `eval("code")` + exec | **BLOCKED** (behavioral `DYNAMIC_CODE_EXEC_CHAIN`) |
| `Buffer.from(b64,'base64').toString() -> eval` | **BLOCKED** (behavioral `OBFUSCATED_CODE_EXECUTION`; bare `buffer.from`/`eval(` are WARN-only, the decode+eval combination blocks) |
| `atob`/hex-decode -> `new Function` | **BLOCKED** (behavioral `OBFUSCATED_CODE_EXECUTION`) |
| Crypto-miner stratum URL | **BLOCKED** |
| `.env`/credential read + network call | **BLOCKED** |
| `eval` + `child_process.exec` | **BLOCKED** |
| `curl \| bash` in host project's npm scripts | **BLOCKED** (root scripts only; not dependency install hooks) |
| Bracket eval: `this["ev"+"al"]` | Default: **BYPASSES** · `FW_ENABLE_AST=1`: **BLOCKED** (bracket key folded, resolved eval access) |
| String concat: `global["ev"+"al"]` | Default: **BYPASSES** · `FW_ENABLE_AST=1`: **BLOCKED** (concat folded) |
| Variable-alias eval: `const fn = eval; fn("code")` | Default: **BYPASSES** · `FW_ENABLE_AST=1`: **BLOCKED** (alias tracking) |
| Array join: `["ch","ild"].join("")` | Default: **BYPASSES** · `FW_ENABLE_AST=1`: **BLOCKED** (join folded, re-matched) |
| Unicode-escape eval: `eval(...)` | Default: **BYPASSES** · `FW_ENABLE_AST=1`: **BLOCKED** (tokenizer decodes escapes) |
| Prototype chain: `Object.getPrototypeOf(fn).constructor`, `constructor.constructor` | Default: **BYPASSES** · `FW_ENABLE_AST=1`: **BLOCKED** (constructor-chase resolved) |
| AST span-exhaustion: real payload hidden behind >40 decoy spans | `FW_ENABLE_AST=1`: **BLOCKED** (highest-risk-first span scheduling; incomplete scans governed by `FW_AST_INCOMPLETE_POLICY`) |
| WASM payloads, env-sourced config, network+process-exec taint chains, low-and-slow C2 | **BYPASSES even with `FW_ENABLE_AST=1`** — architectural limits of static/AST analysis; need runtime/dataflow instrumentation |

See the monorepo's [`docs/THREAT-COVERAGE.md`](https://github.com/Enkidagoat/runtime-firewall-mvp/blob/main/docs/THREAT-COVERAGE.md) for the full, test-backed protection/bypass matrix.

## Behavioral Detection Notes

- **`process.env` + network egress is intentionally NOT blocked** (WARN only): it is the everyday
  pattern legitimate analytics/telemetry SDKs use. Only a genuine credential *path* (`.env`, `.ssh`,
  `id_rsa`, …) or `.npmrc` token/host/hardcoded-exfil signal escalates to a CRITICAL block.
- **Dynamic `require(variable)`** surfaces as an `OBSERVE`/telemetry signal, not a block —
  non-literal `require` is pervasive in legitimate code (lazy loading, plugin systems).

## Tests

Tests live in the monorepo root — they are not included in the published package. To run them:

```bash
git clone https://github.com/Enkidagoat/runtime-firewall-mvp
cd runtime-firewall-mvp
npm install
npm run test:unit         # Aho-Corasick + Detector
npm run test:adversarial  # adversarial bypass cases
npm run test:coverage     # engine-core coverage gate (95%)
npm test                  # all
```

## License

Apache License 2.0 — see `LICENSE` (included in this package).
