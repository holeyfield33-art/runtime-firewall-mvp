// red-team/corpus/dynamic-code-exec.js
// Dynamic code generation / execution and obfuscated-payload-execution chains.

module.exports = [
  {
    id: 'dce-eval-exec',
    category: 'dynamic-code-exec',
    technique: 'eval-plus-process-exec',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Generates code with eval and executes a system process (DYNAMIC_CODE_EXEC_CHAIN)',
    code: `
      const { exec } = require('child_process');
      const code = getRemoteCode();
      eval(code);
      exec(code);
      module.exports = {};
    `,
  },
  {
    id: 'dce-newfunction-execsync',
    category: 'dynamic-code-exec',
    technique: 'new-function-execsync',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'new Function(...) plus execSync process execution',
    code: `
      const f = new Function('return process.mainModule.require("child_process")');
      const cp = f();
      cp.execSync('id');
      module.exports = {};
    `,
  },
  {
    id: 'dce-base64-eval',
    category: 'dynamic-code-exec',
    technique: 'base64-decode-eval',
    severity: 'HIGH',
    expected: 'BLOCK',
    description: 'Decodes a base64 blob with Buffer.from and eval\'s it (OBFUSCATED_CODE_EXECUTION)',
    code: `
      const payload = Buffer.from('cmVxdWlyZSgnZnMnKQ==', 'base64').toString();
      eval(payload);
      module.exports = {};
    `,
  },
  {
    id: 'dce-atob-eval',
    category: 'dynamic-code-exec',
    technique: 'atob-decode-eval',
    severity: 'HIGH',
    expected: 'BLOCK',
    description: 'Decodes with atob() and eval\'s the result',
    code: `
      const src = atob('Y29uc29sZS5sb2coMSk=');
      eval(src);
      module.exports = {};
    `,
  },
  {
    id: 'dce-hex-eval',
    category: 'dynamic-code-exec',
    technique: 'hex-decode-eval',
    severity: 'HIGH',
    expected: 'BLOCK',
    description: 'Decodes a hex blob with Buffer.from(...,"hex") and eval\'s it',
    code: `
      const src = Buffer.from('636f6e736f6c652e6c6f672831293b', 'hex').toString();
      eval(src);
      module.exports = {};
    `,
  },
  {
    id: 'dce-vm-spawn',
    category: 'dynamic-code-exec',
    technique: 'vm-context-plus-spawn',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'vm.runInNewContext dynamic code + spawnSync process exec',
    code: `
      const vm = require('vm');
      vm.runInNewContext(fetchScript());
      require('child_process').spawnSync('sh', ['-c', 'whoami']);
      module.exports = {};
    `,
  },

  // ── By-design WARN (single primitive, no dangerous chain) ───────────────────
  {
    id: 'dce-eval-only',
    category: 'dynamic-code-exec',
    technique: 'bare-eval',
    severity: 'WARN',
    expected: 'PASS',
    description: 'Bare eval of a constant. F-20: eval alone is WARN-only (pervasive in build tools/test frameworks); only the decode->exec or code->process chain blocks.',
    code: `module.exports = eval('1 + 2');`,
  },

  // ── Evasion variants (static-analysis limits) ───────────────────────────────
  {
    id: 'dce-bracket-eval',
    category: 'dynamic-code-exec',
    technique: 'bracket-notation-eval',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'eval reached via computed member access this["ev"+"al"] — no "eval(" literal for the regex',
    code: `
      const fn = this['ev' + 'al'];
      fn('process.exit(0)');
      module.exports = {};
    `,
  },
  {
    id: 'dce-alias-eval',
    category: 'dynamic-code-exec',
    technique: 'variable-alias-eval',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'eval aliased to a variable then called — source contains no "eval(" call site',
    code: `
      const fn = eval;
      fn('1+1');
      module.exports = {};
    `,
  },
  {
    id: 'dce-join-require',
    category: 'dynamic-code-exec',
    technique: 'array-join-require',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'child_process module name reassembled from an array join',
    code: `
      const m = require(['ch', 'ild', '_pro', 'cess'].join(''));
      m.exec('id');
      module.exports = {};
    `,
  },
  {
    id: 'dce-unicode-escape-eval',
    category: 'dynamic-code-exec',
    technique: 'unicode-escape-eval',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'eval spelled with a unicode escape (\\u0065val) so the /\\beval\\s*\\(/ regex misses it',
    code: `
      const g = global;
      g['\\u0065val']('process.exit(0)');
      module.exports = {};
    `,
  },
];
