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
> below.

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
**unprotected**, with a loud, logged warning (`FW_MODE=enforce` treats it as a hard failure) —
never silently claimed as covered.

**ESM module-URL scheme:** even on a supported Node version, ESM coverage only applies to
`file://` module URLs. The load hook returns before the detector runs for any other scheme, so
`import()` of a `data:`, `http:`, `https:`, or `blob:` URL is **unprotected on every Node
version**, floor or no floor — this is a separate gap from the version floor above, not covered
by it. See `docs/THREAT-COVERAGE.md`'s execution-path table for the full breakdown.

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

Every bypass class is listed in [`red-team/README.md`](../../red-team/README.md) and the monorepo's
`docs/THREAT-COVERAGE.md`.

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
| `FW_MODE` | `dev` | `enforce` fails closed (`process.exit(1)`) when not preloaded via `--require`; `dev` (default) warns loudly and continues. See the root README's "Enforcement mode vs Development mode" section. |
| `FW_STRICT_PRELOAD` | `0` | Set to `1` to exit if not loaded via `--require` (backward-compatible alias for `FW_MODE=enforce`) |
| `FW_FREEZE_PROTOTYPES` | `0` | Set to `1` to freeze built-in prototypes (prototype-pollution hardening; opt-in because it breaks some polyfills and test frameworks) |
| `FW_POLICY_PUBKEY` | *(dev key)* | PEM-encoded Ed25519 SPKI public key for verifying `policy.signed.json`. **Must be set in production** — the bundled dev private key is public. |
| `FW_ALLOW_DEV_POLICY_KEY` | `0` | Set to `1` to allow the dev key when `FW_POLICY_PUBKEY` is unset (local/dev/CI). Agent refuses to start with a policy file present and no production key unless this flag is set. |
| `HELIOS_LOG_DIR` | `/var/log/helios` | Audit log directory |
| `HELIOS_BLOCK_SCRIPTS` | `1` | Set to `0` to warn instead of block suspicious npm scripts |
| `BUN_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Bun; the agent exits with code 1 if absent |
| `DENO_PRELOAD` | *(none)* | Must include `aletheia-firewall` when running under Deno; the agent exits with code 1 if absent |

> Telemetry is **off by default**. `FW_TELEMETRY=1` starts a telemetry worker that POSTs events to the control plane at `FW_CONTROL_PORT`. The control plane (`fw-control`) ships in this repo and can be started with `npm run start:control`.

## Policy File

`policy.signed.json` must be a **signed envelope** (`{ version, rules, signedAt, signature }`) —
an unsigned `{ "rules": … }` object fails verification on startup and triggers emergency lockdown.
Author a plain rules file and sign it:

```bash
node scripts/generate-policy-key.js   # prints a fresh keypair; keep the private key local-only, never commit it
echo '{ "malware.js": "BLOCK", "untrusted-pkg.js": "QUARANTINE", "noisy-lib.js": "OBSERVE" }' > rules.json
node scripts/sign-policy.js /path/to/your-private-key.pem rules.json policy.signed.json
```

There is no bundled/committed dev private key (see `SECURITY.md`). If your key matches the
bundled `DEV_PUBLIC_KEY_PEM` default you must also run with `FW_ALLOW_DEV_POLICY_KEY=1`; in
production, set `FW_POLICY_PUBKEY` to your own public key instead.

- **BLOCK**: Module never runs.
- **QUARANTINE**: Exports replaced with a logging Proxy; child requires blocked.
- **OBSERVE** (default): Full behavioral + signature scan; blocks on detection.

> **Signing:** `policy.signed.json` carries a real **Ed25519 signature** over its canonical
> payload `{ version, rules (keys sorted), signedAt }`, re-verified every 60 seconds. An invalid
> or missing signature triggers emergency lockdown. The verifying public key is compiled into
> `src/policy-watcher.js` and overridable via `FW_POLICY_PUBKEY`; author a rules file and sign it
> with `scripts/sign-policy.js`. (Since v0.2.0 this replaced the earlier SHA-256 trust-on-first-use
> baseline — earlier docs describing SHA-256-only monitoring are obsolete.)

## Performance

The firewall's cost is a **one-time per-module compile scan** — the `Module._compile` hook runs once per file on first load, then a compilation cache short-circuits repeat compilations. There is **zero overhead when `FW_ENABLE_DETECTION` is unset** (`index.js` returns immediately and installs no hook).

The repo maintains a 25% median compilation-overhead gate budget, but this is a regression threshold, not a published release guarantee. The v0.4.0 frozen evidence (the most recent controlled performance freeze — see the note below) shows the runtime `Module._compile` interception path is the dominant steady-state cost; `Detector.scanModuleSync` is a secondary contributor in the verified 900-module workload.

| Metric | Budget | Enforced? |
|--------|--------|-----------|
| Median module-compile overhead | 25% | **Yes** |
| P95 overhead | 30% (informational only) | No |

The gate is a **regression guard**, not a performance target. If the median exceeds 25%, the change needs review.

For the v0.4.0 frozen baseline and diagnostic evidence, see `PERFORMANCE.md` and `results/benchmarks/steady-state-compile-attr-*.json`. This is the most recent controlled performance freeze in the repo; no v0.5.0-specific freeze has been published yet, so treat these numbers as last-measured-at-v0.4.0, not as a v0.5.0 guarantee.

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

See the monorepo's `docs/THREAT-COVERAGE.md` for the full, test-backed protection/bypass matrix.

## Behavioral Detection Notes

- **`process.env` + network egress is intentionally NOT blocked** (WARN only): it is the everyday
  pattern legitimate analytics/telemetry SDKs use. Only a genuine credential *path* (`.env`, `.ssh`,
  `id_rsa`, …) or `.npmrc` token/host/hardcoded-exfil signal escalates to a CRITICAL block.
- **Dynamic `require(variable)`** surfaces as an `OBSERVE`/telemetry signal, not a block —
  non-literal `require` is pervasive in legitimate code (lazy loading, plugin systems).

## Tests

Tests live in the monorepo root — they are not included in the published package. To run them:

```bash
git clone https://github.com/holeyfield33-art/runtime-firewall-mvp
cd runtime-firewall-mvp
npm install
npm run test:unit         # Aho-Corasick + Detector
npm run test:adversarial  # adversarial bypass cases
npm run test:coverage     # engine-core coverage gate (95%)
npm test                  # all
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
