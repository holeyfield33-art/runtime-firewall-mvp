// red-team/corpus/benign-controls.js
// Benign controls — legitimate module patterns that MUST pass (OBSERVE).
// A block here is a FALSE POSITIVE and fails the suite. These exercise the exact
// idioms real packages use that overlap with malicious signals.

module.exports = [
  {
    id: 'benign-math',
    category: 'benign-controls',
    technique: 'plain-utility',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Plain arithmetic utility module',
    code: `
      function add(a, b) { return a + b; }
      function sub(a, b) { return a - b; }
      module.exports = { add, sub };
    `,
  },
  {
    id: 'benign-http-client',
    category: 'benign-controls',
    technique: 'axios-like-client',
    severity: 'NONE',
    expected: 'PASS',
    description: 'HTTP client reading config from process.env and making requests (WARN at most)',
    code: `
      const https = require('https');
      const base = process.env.API_BASE_URL || 'https://api.example.com';
      module.exports.get = (path) => https.request(base + path);
    `,
  },
  {
    id: 'benign-jwt-decode',
    category: 'benign-controls',
    technique: 'base64-decode-no-eval',
    severity: 'NONE',
    expected: 'PASS',
    description: 'JWT/token library decoding base64 — decode without eval must not block (F-31 guard)',
    code: `
      function decode(token) {
        const raw = Buffer.from(token.split('.')[1], 'base64').toString('utf8');
        return JSON.parse(raw);
      }
      module.exports = { decode };
    `,
  },
  {
    id: 'benign-build-eval',
    category: 'benign-controls',
    technique: 'constant-eval',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Build tool evaluating a constant expression (bare eval is WARN-only, F-20)',
    code: `module.exports = { value: eval('40 + 2') };`,
  },
  {
    id: 'benign-npmrc-registry',
    category: 'benign-controls',
    technique: 'npm-tooling-registry-resolve',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Legit npm tooling reads .npmrc to resolve the registry, then fetches from a config-built URL (F-30 guard)',
    code: `
      const fs = require('fs');
      const os = require('os');
      const content = fs.readFileSync(require('path').join(os.homedir(), '.npmrc'), 'utf8');
      const match = content.match(/^\\s*registry\\s*=\\s*(.+)/m);
      const registry = match ? match[1].trim() : 'https://registry.npmjs.org';
      module.exports.fetchMeta = (name) => fetch(registry + '/' + name);
    `,
  },
  {
    id: 'benign-word-list-stratum',
    category: 'benign-controls',
    technique: 'dictionary-word-list',
    severity: 'NONE',
    expected: 'PASS',
    description: 'Dictionary/word-list package containing "stratum"/"stratus" (F-29 guard)',
    code: `
      module.exports = ["stratification", "stratum", "stratus", "substratum", "coincidence"];
    `,
  },
  {
    id: 'benign-spawn-process-lib',
    category: 'benign-controls',
    technique: 'process-runner-lib',
    severity: 'NONE',
    expected: 'PASS',
    description: 'execa/cross-spawn-style process runner (child_process.spawn is WARN-only, F-26)',
    code: `
      const { spawn } = require('child_process');
      module.exports.run = (cmd, args) => spawn(cmd, args, { stdio: 'inherit' });
    `,
  },
  {
    id: 'benign-dotenv',
    category: 'benign-controls',
    technique: 'dotenv-loader',
    severity: 'NONE',
    expected: 'PASS',
    description: 'dotenv-style loader that reads process.env (no credential path, no exfil)',
    code: `
      module.exports.config = () => {
        for (const k of Object.keys(process.env)) { /* populate */ }
        return process.env;
      };
    `,
  },
  {
    id: 'benign-lodash-newfunction',
    category: 'benign-controls',
    technique: 'template-compile',
    severity: 'NONE',
    expected: 'PASS',
    description: 'lodash.template-style compiler using new Function (WARN-only, no process exec / decode)',
    code: `
      module.exports.compile = (src) => new Function('data', 'return ' + JSON.stringify(src));
    `,
  },
];
