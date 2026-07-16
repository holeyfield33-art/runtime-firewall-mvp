// red-team/corpus/dynamic-code-exec-extended.js
// Extended dynamic-code / obfuscated-execution variants.

module.exports = [
  // ── Covered chains (expected BLOCK) ─────────────────────────────────────────
  {
    id: 'dce-eval-spawnsync',
    category: 'dynamic-code-exec', technique: 'eval-spawnsync', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'eval generated code + spawnSync process exec',
    code: `const c = getRemote(); eval(c); require('child_process').spawnSync('sh', ['-c', c]);`,
  },
  {
    id: 'dce-function-execfile',
    category: 'dynamic-code-exec', technique: 'function-execfile', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'new Function + execFile',
    code: `const f = new Function('return 1'); f(); require('child_process').execFile('/bin/sh', ['-c', 'id']);`,
  },
  {
    id: 'dce-base64-function',
    category: 'dynamic-code-exec', technique: 'base64-decode-function', severity: 'HIGH',
    expected: 'BLOCK',
    description: 'base64 decode fed into new Function (OBFUSCATED_CODE_EXECUTION)',
    code: `const src = Buffer.from('cmV0dXJuIDQy', 'base64').toString(); const f = new Function(src); module.exports = f();`,
  },
  {
    id: 'dce-atob-function',
    category: 'dynamic-code-exec', technique: 'atob-decode-function', severity: 'HIGH',
    expected: 'BLOCK',
    description: 'atob decode fed into Function("...")',
    code: `const src = atob('cmV0dXJuIDE='); const f = Function('a', src); module.exports = f;`,
  },
  {
    id: 'dce-settimeout-string-exec',
    category: 'dynamic-code-exec', technique: 'settimeout-string-exec', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'setTimeout("code-string") (dynamic code) + child_process exec',
    code: `setTimeout("require('child_process').exec('id')", 100); const cp = require('child_process'); cp.exec('whoami');`,
  },
  {
    id: 'dce-setinterval-string-exec',
    category: 'dynamic-code-exec', technique: 'setinterval-string-exec', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'setInterval("code-string") + execSync',
    code: `setInterval("doWork()", 1000); require('child_process').execSync('uname -a');`,
  },
  {
    id: 'dce-vm-script-exec',
    category: 'dynamic-code-exec', technique: 'vm-script-exec', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'vm.Script compile/run + spawn',
    code: `const vm = require('vm'); new vm.Script(src).runInThisContext(); require('child_process').spawn('sh', ['-c', 'id']);`,
  },
  {
    id: 'dce-vm-runinthis-spawn',
    category: 'dynamic-code-exec', technique: 'vm-runinthiscontext-spawn', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'vm.runInThisContext + spawnSync',
    code: `const vm = require('vm'); vm.runInThisContext(payload); require('child_process').spawnSync('id');`,
  },
  {
    id: 'dce-eval-shellstring',
    category: 'dynamic-code-exec', technique: 'eval-shelljs', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'eval + shelljs ShellString exec',
    code: `eval(remoteCode); const shell = require('shelljs'); shell.ShellString('id').exec ? shell.exec('id') : 0;`,
  },
  {
    id: 'dce-hex-function',
    category: 'dynamic-code-exec', technique: 'hex-decode-function', severity: 'HIGH',
    expected: 'BLOCK',
    description: 'hex decode fed into new Function',
    code: `const src = Buffer.from('72657475726e2031', 'hex').toString(); module.exports = new Function(src)();`,
  },

  // ── Evasion of the string signals / chains (known bypass) ────────────────────
  {
    id: 'dce-eval-decodeuri',
    category: 'dynamic-code-exec', technique: 'decodeuri-eval', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'eval(decodeURIComponent(...)) — decodeURIComponent is not a CODE_DECODE signal, and bare eval is WARN-only, so nothing chains',
    code: `eval(decodeURIComponent('%72%65%71%75%69%72%65%28%31%29')); module.exports = {};`,
  },
  {
    id: 'dce-fromcharcode-eval',
    category: 'dynamic-code-exec', technique: 'fromcharcode-eval', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Payload built with String.fromCharCode then eval\'d — no decode primitive is recognised',
    code: `const s = String.fromCharCode(97,108,101,114,116,40,49,41); eval(s); module.exports = {};`,
  },
  {
    id: 'dce-reverse-eval',
    category: 'dynamic-code-exec', technique: 'reversed-string-eval', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Reversed source string un-reversed at runtime then eval\'d',
    code: `const s = ')1(trela'.split('').reverse().join(''); eval(s); module.exports = {};`,
  },
  {
    id: 'dce-constructor-constructor',
    category: 'dynamic-code-exec', technique: 'constructor-sandbox-escape', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Function reached via constructor.constructor(...) — no eval/new Function literal for the regex, even though a process exec follows',
    code: `
      const F = (function(){}).constructor;
      F('return process.mainModule.require("child_process")')().exec('id');
      module.exports = {};
    `,
  },
  {
    id: 'dce-process-binding',
    category: 'dynamic-code-exec', technique: 'process-binding-eval', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'process.binding("spawn_sync") to launch a process alongside eval — process.binding is not in PROCESS_EXEC, so the DYNAMIC_CODE_EXEC_CHAIN never completes',
    code: `
      const b = process.binding('spawn_sync');
      eval('void 0');
      b.spawn({ file: '/bin/sh', args: ['sh', '-c', 'id'] });
      module.exports = {};
    `,
  },
  {
    id: 'dce-generatorfunction',
    category: 'dynamic-code-exec', technique: 'generatorfunction-constructor', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Code compiled via the GeneratorFunction constructor — not matched by the DYNAMIC_CODE regexes',
    code: `
      const GF = Object.getPrototypeOf(function*(){}).constructor;
      const g = GF('yield require("child_process").execSync("id")');
      g().next();
      module.exports = {};
    `,
  },
  {
    id: 'dce-indirect-eval-decodeuri',
    category: 'dynamic-code-exec', technique: 'indirect-eval-decodeuri', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Indirect (0, eval) call on a decodeURIComponent payload — indirect eval still matches /\\beval\\s*\\(/ but there is no chained decode/exec signal, so it stays WARN-only',
    code: `(0, eval)(decodeURIComponent('%61%6c%65%72%74%28%31%29')); module.exports = {};`,
  },
  {
    id: 'dce-inline-require-vm',
    category: 'dynamic-code-exec', technique: 'inline-require-dynamiccode-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Inline require("vm").runInThisContext(...) + spawnSync. The DYNAMIC_CODE regexes match a bound `vm.runInThisContext(` but not the inline `require("vm").runInThisContext(` form, so DYNAMIC_CODE_EXEC_CHAIN never completes. (Compare dce-vm-runinthis-spawn, which uses the bound form and IS blocked.)',
    code: `require('vm').runInThisContext(payload); require('child_process').spawnSync('id'); module.exports = {};`,
  },
  {
    id: 'dce-wasm-code',
    category: 'dynamic-code-exec', technique: 'wasm-instantiate', severity: 'HIGH',
    expected: 'BLOCK', knownBypass: true,
    description: 'Arbitrary logic delivered as a WebAssembly module — no JS dynamic-code signal at all',
    code: `WebAssembly.instantiate(bytes).then((m) => m.instance.exports.run()); module.exports = {};`,
  },
];
