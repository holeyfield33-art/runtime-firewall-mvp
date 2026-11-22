# Software Bill of Materials (SBOM)

An SBOM is a formal, machine-readable inventory of the components that make up a software package. For Aletheia Firewall it answers: what third-party code is present when a customer installs `aletheia-firewall` or runs the control plane, what licenses apply, and which versions are locked.

## Current state (as of main `20ccd9b`)

### Published agent (`aletheia-firewall`)
- **Runtime dependencies: zero.**  
  The package ships only its own source (`index.js`, `src/`, `bin/`, `.helios-baseline`, README, LICENSE).  
  It uses only Node.js built-in modules (`fs`, `crypto`, `path`, `module`, `worker_threads`, etc.).
- **No transitive runtime supply chain** for the agent itself.  
  A customer who installs only `aletheia-firewall` receives no additional npm packages that execute in their process.

### Control plane (`@fw/control`, private)
- Direct dependency: `fastify@^5.12.5` (and its transitive tree, currently ~100+ packages in the lockfile).
- Used only when the optional telemetry/ingestion server is started. Not part of the published agent.

### Development / test only (not published)
- Root `devDependencies`: `c8` (coverage), `proxyquire` (test mocking).
- These never appear in the published `aletheia-firewall` tarball.

### Lockfile
- `package-lock.json` (lockfileVersion 3) pins the exact versions of every development and control-plane dependency for reproducible builds and audits.
- The agent’s zero-dependency status is intentional and is part of its supply-chain security claim.

## What an SBOM covers for this project

| Component | Included in published agent SBOM? | Notes |
|-----------|-----------------------------------|-------|
| Agent source + baseline | Yes | First-party |
| Node.js runtime | No (platform) | Declared via `engines` |
| Fastify + transitive | No | Control plane only |
| c8, proxyquire | No | Dev/test only |
| GitHub Actions runners, npm CLI | No | CI infrastructure |

## Generating an SBOM

From the repository root (requires Node ≥18):

```bash
# CycloneDX JSON (recommended, widely supported)
npx @cyclonedx/cyclonedx-npm --output-file sbom-agent.json --package-lock-only packages/fw-agent

# Or SPDX
npx @cyclonedx/cyclonedx-npm --output-format spdx-json --output-file sbom-agent.spdx.json --package-lock-only packages/fw-agent
```

For the control plane (if you need a separate SBOM):

```bash
npx @cyclonedx/cyclonedx-npm --output-file sbom-control.json --package-lock-only packages/fw-control
```

The resulting file lists every package, version, license, and hash that would be installed for that package. Because the agent has zero dependencies, its SBOM contains only the root component.

## Implementation steps (recommended)

1. Add a CI job that generates the agent SBOM on every release tag and attaches it to the GitHub Release.
2. Publish the SBOM alongside the npm package (or as a release asset) so customers can verify the zero-dependency claim.
3. Document the exact command and expected empty dependency list in `docs/MAINTENANCE.md` and the package README.
4. Periodically re-generate and diff the control-plane SBOM if the private control plane is ever distributed.
5. Keep the agent’s `package.json` free of `dependencies` and `devDependencies` so the published SBOM remains trivial and auditable.

## Verification

```bash
# Confirm agent still has zero runtime deps
node -e "const p=require('./packages/fw-agent/package.json'); console.log(p.dependencies||'none')"

# Confirm published files do not include node_modules
npm pack --dry-run --json -w packages/fw-agent | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d)[0].files.map(f=>f.path).filter(p=>p.includes("node_modules"))))'
```

An empty list confirms the published agent contains no third-party code.
