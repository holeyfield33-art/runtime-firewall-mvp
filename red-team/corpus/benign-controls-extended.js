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
];
