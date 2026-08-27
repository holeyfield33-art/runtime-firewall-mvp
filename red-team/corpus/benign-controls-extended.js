// red-team/corpus/benign-controls-extended.js
// Extended benign controls — legitimate idioms that overlap with the new attack
// variants above and MUST NOT be blocked. A block here is a FALSE POSITIVE.

module.exports = [
  {
    id: 'benign-node-fetch-client',
    category: 'benign-controls', technique: 'http-client-lib', severity: 'NONE',
    expected: 'PASS',
    description: 'HTTP client wrapper (http.request) reading a base URL from env',
    code: `const http = require('http'); const base = process.env.BASE || 'http://localhost'; module.exports.get = (p) => http.request(base + p);`,
  },
  {
    id: 'benign-config-json-read',
    category: 'benign-controls', technique: 'config-file-read-fetch', severity: 'NONE',
    expected: 'PASS',
    description: 'Reads a non-sensitive config.json then calls an API — config.json is not a credential path',
    code: `
      const fs = require('fs');
      const cfg = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
      module.exports.load = () => fetch(cfg.endpoint);
    `,
  },
  {
    id: 'benign-ws-client',
    category: 'benign-controls', technique: 'websocket-client', severity: 'NONE',
    expected: 'PASS',
    description: 'Legit realtime client opening a WebSocket to its own service',
    code: `const ws = new WebSocket('wss://realtime.example.com/socket'); ws.onmessage = (m) => handle(m.data); module.exports = ws;`,
  },
  {
    id: 'benign-dgram-dns',
    category: 'benign-controls', technique: 'udp-client', severity: 'NONE',
    expected: 'PASS',
    description: 'UDP metrics/statsd client via dgram — no credential read',
    code: `const u = require('dgram').createSocket('udp4'); module.exports.metric = (m) => u.send(m, 8125, 'metrics.local');`,
  },
  {
    id: 'benign-tls-client',
    category: 'benign-controls', technique: 'tls-client', severity: 'NONE',
    expected: 'PASS',
    description: 'Database/driver TLS client via tls.connect — no secret file read',
    code: `module.exports.connect = () => require('tls').connect(5432, 'db.example.com');`,
  },
  {
    id: 'benign-vm-sandbox-config',
    category: 'benign-controls', technique: 'vm-config-eval', severity: 'NONE',
    expected: 'PASS',
    description: 'vm.runInNewContext evaluating a config expression — WARN-only (no process exec, no decode)',
    code: `module.exports.evalExpr = (e) => require('vm').runInNewContext(e, { Math });`,
  },
  {
    id: 'benign-settimeout-fn',
    category: 'benign-controls', technique: 'settimeout-function', severity: 'NONE',
    expected: 'PASS',
    description: 'setTimeout with a function argument (not a code string) — must not trip the string-arg DYNAMIC_CODE regex',
    code: `module.exports.later = (fn) => setTimeout(() => fn(), 250);`,
  },
  {
    id: 'benign-fromcharcode-decoder',
    category: 'benign-controls', technique: 'unicode-decoder', severity: 'NONE',
    expected: 'PASS',
    description: 'String.fromCharCode in a legitimate unicode decoder — no eval anywhere',
    code: `module.exports.decode = (codes) => codes.map((c) => String.fromCharCode(c)).join('');`,
  },
  {
    id: 'benign-decodeuri-parser',
    category: 'benign-controls', technique: 'url-param-parser', severity: 'NONE',
    expected: 'PASS',
    description: 'decodeURIComponent in a query-string parser — no eval',
    code: `module.exports.parse = (qs) => Object.fromEntries(qs.split('&').map((p) => p.split('=').map(decodeURIComponent)));`,
  },
  {
    id: 'benign-base64-image',
    category: 'benign-controls', technique: 'base64-asset-decode', severity: 'NONE',
    expected: 'PASS',
    description: 'Decodes a base64 image/data blob (Buffer.from base64) and never eval\'s it (F-31 guard)',
    code: `module.exports.toBuffer = (dataUri) => Buffer.from(dataUri.split(',')[1], 'base64');`,
  },
  {
    id: 'benign-spawn-git',
    category: 'benign-controls', technique: 'git-wrapper', severity: 'NONE',
    expected: 'PASS',
    description: 'Simple-git-style wrapper spawning git — child_process.spawn is WARN-only',
    code: `const { spawn } = require('child_process'); module.exports.status = () => spawn('git', ['status', '--porcelain']);`,
  },
  {
    id: 'benign-template-newfunction',
    category: 'benign-controls', technique: 'template-compiler', severity: 'NONE',
    expected: 'PASS',
    description: 'Template compiler using new Function on a compiled template body — WARN-only, no decode/exec chain',
    code: `module.exports.compile = (body) => new Function('data', 'with(data){return \`' + body + '\`}');`,
  },
  {
    id: 'benign-pkg-registry-fetch',
    category: 'benign-controls', technique: 'registry-metadata-fetch', severity: 'NONE',
    expected: 'PASS',
    description: 'Reads local package.json then fetches registry metadata from a config-built URL',
    code: `
      const pkg = require('./package.json');
      const reg = process.env.NPM_REGISTRY || 'https://registry.npmjs.org';
      module.exports.meta = () => fetch(reg + '/' + pkg.name);
    `,
  },
  {
    id: 'benign-axios-proxy-env',
    category: 'benign-controls', technique: 'proxy-config-env', severity: 'NONE',
    expected: 'PASS',
    description: 'HTTP library honouring HTTPS_PROXY from env and making a request (WARN at most)',
    code: `const https = require('https'); const proxy = process.env.HTTPS_PROXY; module.exports.get = (u) => https.get(u, { proxy });`,
  },
  {
    id: 'benign-execfile-ffprobe',
    category: 'benign-controls', technique: 'media-tool-wrapper', severity: 'NONE',
    expected: 'PASS',
    description: 'Media library invoking ffprobe via execFile — WARN-only, no dynamic-code chain',
    code: `const { execFile } = require('child_process'); module.exports.probe = (f, cb) => execFile('ffprobe', ['-show_format', f], cb);`,
  },
  {
    id: 'benign-bundled-npmrc-host-far-egress',
    category: 'benign-controls', technique: 'bundled-npmrc-mention-near-unrelated-host-key', severity: 'NONE',
    expected: 'PASS',
    description: 'F-43/F-68 regression: mirrors the real vite@8.2.1 dist/node/chunks/node.js false ' +
      'positive. A genuine .npmrc string reference sits a few dozen characters from an unrelated ' +
      'dev-server `host:` config key -- coincidental, unrelated code, exactly like the real bundle ' +
      '-- while the actual network call is tens of thousands of characters away in the same file. ' +
      'Neither signal pair is proximate to the other, so CREDENTIAL_EXFILTRATION must not fire.',
    code: `
      const path = require('path');
      const fs = require('fs');
      function loadRegistryConfig(dir) {
        const configPath = path.join(dir, '.npmrc');
        return fs.existsSync(configPath) ? fs.readFileSync(configPath, 'utf8') : null;
      }
      const devServerDefaults = { host: 'localhost', port: 5173, strictPort: false };
      ` +
      '\n      // unrelated bundled code filling the space between the config schema above and\n' +
      '      // the real network call below, mirroring how far apart these land in a real chunk\n' +
      '      const _bundledFiller = ' + JSON.stringify('x'.repeat(20000)) + ';\n' +
      `
      const https = require('https');
      function fetchManifest(url) {
        return https.request(url, (res) => res.resume());
      }
      module.exports = { loadRegistryConfig, devServerDefaults, fetchManifest };
    `,
  },

  // ── Phase 3 AST-detection false-positive guards ─────────────────────────────
  // Folding literals and resolving obfuscated-looking call targets is a NEW false-positive
  // surface (see packages/fw-agent/src/ast-scan.js) distinct from the raw-text signal engine
  // above — these exercise the same primitives the AST pass specifically inspects, used the
  // way real packages actually use them, and must stay clean under FW_ENABLE_AST=1.
  {
    id: 'benign-ast-constructor-typecheck',
    category: 'benign-controls', technique: 'constructor-property-typecheck', severity: 'NONE',
    expected: 'PASS',
    description: 'Ordinary `.constructor` type-check idiom (common in validation/serialization libraries) — must not be mistaken for the constructor-chase sandbox-escape shape, which requires the OBJECT to itself be a function expression or Object.getPrototypeOf(fn), not an arbitrary value.',
    code: `
      function isPlainObject(x) {
        return x != null && typeof x === 'object' && x.constructor === Object;
      }
      function sameType(a, b) {
        return a.constructor === b.constructor;
      }
      module.exports = { isPlainObject, sameType };
    `,
  },
  {
    id: 'benign-ast-fromcharcode-i18n',
    category: 'benign-controls', technique: 'fromcharcode-non-code-string', severity: 'NONE',
    expected: 'PASS',
    description: 'String.fromCharCode building an ordinary display string (a common pattern in i18n/emoji/unicode-table helpers) — folds to plain text, not a signature match, and the CODE_DECODE-class structural signal it also contributes never chains into a block because there is no dynamicCode/eval anywhere nearby.',
    code: `
      function heart() { return String.fromCharCode(0x2764); }
      function greeting(name) {
        const hello = String.fromCharCode(72, 101, 108, 108, 111);
        return hello + ', ' + name + '!';
      }
      module.exports = { heart, greeting };
    `,
  },
  {
    id: 'benign-ast-buffer-base64-data',
    category: 'benign-controls', technique: 'buffer-base64-ordinary-data', severity: 'NONE',
    expected: 'PASS',
    description: 'Buffer.from(..., "base64") decoding ordinary config/asset data (not a command, not a path, not a known-bad signature) — the fold must produce a harmless string that matches nothing.',
    code: `
      function decodeAsset(b64) {
        return Buffer.from(b64, 'base64').toString('utf8');
      }
      const defaultIcon = Buffer.from('aWNvbi1wbGFjZWhvbGRlcg==', 'base64').toString();
      module.exports = { decodeAsset, defaultIcon };
    `,
  },
  {
    id: 'benign-ast-array-join-message',
    category: 'benign-controls', technique: 'array-join-non-sensitive', severity: 'NONE',
    expected: 'PASS',
    description: 'Array.join used to build an ordinary log/error message — a folded literal that matches no BLOCK_SIGNATURES/SENSITIVE_PATH pattern must never manufacture a finding just because folding happened.',
    code: `
      function formatError(parts) {
        return ['Error', 'occurred', 'while', 'processing', 'request'].join(' ');
      }
      const csvHeader = ['id', 'name', 'created_at'].join(',');
      module.exports = { formatError, csvHeader };
    `,
  },
  {
    id: 'benign-ast-computed-property-config',
    category: 'benign-controls', technique: 'computed-member-config-key', severity: 'NONE',
    expected: 'PASS',
    description: 'Dynamic bracket-notation property access with a computed-but-benign key (a common config/i18n/feature-flag lookup pattern) — folding the key must never resolve to eval/Function, so no standalone finding fires.',
    code: `
      const messages = { en_greeting: 'hello', fr_greeting: 'bonjour' };
      function greet(lang) {
        const key = lang + '_greeting';
        return messages[key] || messages['en' + '_greeting'];
      }
      module.exports = { greet };
    `,
  },
  {
    id: 'benign-ast-indirect-eval-alone',
    category: 'benign-controls', technique: 'indirect-eval-no-chain', severity: 'WARN',
    expected: 'PASS',
    description: 'The (0, eval) indirect-eval idiom used alone (some legitimate polyfills/sandboxing shims use it for global-scope eval) with no decode/process-exec chain — resolveIdentity() must classify this as "direct" (already visible to the existing engine) and NOT escalate it to a standalone block the way a genuinely obfuscated alias would.',
    code: `
      function globalEval(code) {
        return (0, eval)(code);
      }
      module.exports = { globalEval };
    `,
  },
];
