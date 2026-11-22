#!/usr/bin/env node
// scripts/smoke-tarball.js
// ─────────────────────────────────────────────────────────────────────────────
// Post-pack smoke test: exercises the ACTUAL published tarball as an installed
// dependency, not the repo source. The publish workflow builds the .tgz with
// `npm pack`, installs it into a clean throwaway project, and runs this script
// against that install — so a source/package divergence (a missing `files`
// entry, a broken export, a stale baseline) fails the release BEFORE `npm
// publish`, instead of shipping a broken artifact.
//
// Usage:  node scripts/smoke-tarball.js <installed-project-dir>
//
// <installed-project-dir> is a directory that already has `aletheia-firewall`
// installed in its node_modules (the workflow does `npm install <tgz>` there).
//
// Checks (each in its own real child process, real exit codes):
//   1. clean load        — --require the agent, run trivially -> exit 0
//   2. self-integrity    — the clean load also proves the shipped .helios-baseline
//                          matches the shipped src (a tampered/stale baseline makes
//                          the agent refuse to run, failing check 1)
//   3. blocking (CJS)    — require() a malicious .cjs -> COMPILATION LOCKDOWN, non-zero
//   4. AST tier (CJS)    — FW_ENABLE_AST=1 catches a bracket-eval obfuscation -> non-zero
//   5. enforcement mode  — FW_MODE=enforce without a real --require preload -> non-zero
//   6. ESM interception  — import() a malicious file:// .mjs -> blocked on supported Node,
//                          or a clean skip with a logged reason below the ESM version floor
//   7. detection-only    — no policy file -> one warning + one POLICY_ABSENT_DETECTION_ONLY event
//   8. keygen (bin)      — installed aletheia-policy-keygen: files written, private key never printed,
//                          no silent overwrite
//   9. sign + enforce    — installed aletheia-policy-sign + FW_POLICY_PUBKEY -> BLOCK enforced
//  10. ESM requirement   — FW_REQUIRE_ESM_COVERAGE=1 starts on supported Node, exits 1 below floor
// ─────────────────────────────────────────────────────────────────────────────
'use strict';
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const projectDir = process.argv[2];
if (!projectDir) {
  console.error('usage: node scripts/smoke-tarball.js <installed-project-dir>');
  process.exit(2);
}

// Resolve the agent's entrypoint from the INSTALLED package (node_modules), not the repo.
const agentPath = require.resolve('aletheia-firewall', { paths: [projectDir] });
console.log('[smoke] testing installed package at:', agentPath);

const baseEnv = Object.assign({}, process.env, {
  FW_ENABLE_DETECTION: '1',
  FW_ALLOW_DEV_POLICY_KEY: '1',
});

function run(args, envExtra, extraOpts) {
  return spawnSync(process.execPath, args, Object.assign({
    cwd: projectDir,
    encoding: 'utf8',
    timeout: 30000,
    env: Object.assign({}, baseEnv, envExtra),
  }, extraOpts));
}

function write(name, body) {
  const file = path.join(projectDir, name);
  fs.writeFileSync(file, body);
  return file;
}

let passed = 0;
function check(name, fn) {
  try {
    fn();
    console.log('  ✓ ' + name);
    passed++;
  } catch (e) {
    console.error('  ✗ ' + name + '\n    ' + ((e && e.stack) || e));
    process.exit(1);
  }
}

// 1: clean load — the agent preloads and a trivial program runs to completion.
check('clean load with the agent preloaded', () => {
  const res = run([`--require=${agentPath}`, '-e', "console.log('CLEAN-OK')"], { FW_MODE: 'dev' });
  assert.strictEqual(res.status, 0, 'expected exit 0, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/CLEAN-OK/.test(res.stdout), 'expected CLEAN-OK on stdout:\n' + res.stdout);
});

// 2: self-integrity — the shipped .helios-baseline must be present in the tarball AND match the
// shipped src, so the agent does not refuse to run with a tamper banner. A distinct check from the
// clean load above: it asserts the baseline artifact ships and that the integrity gate is satisfied.
check('self-integrity baseline ships and verifies', () => {
  const installedDir = path.dirname(agentPath);
  assert.ok(fs.existsSync(path.join(installedDir, '.helios-baseline')),
    '.helios-baseline must be present in the installed package (it is what the self-integrity gate reads)');
  const res = run([`--require=${agentPath}`, '-e', "console.log('INTEGRITY-OK')"], { FW_MODE: 'dev' });
  assert.strictEqual(res.status, 0, 'agent must start (self-integrity gate satisfied), got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(!/self-integrity check FAILED/.test(res.stderr), 'self-integrity must not fail on the shipped tarball:\n' + res.stderr);
  assert.ok(/INTEGRITY-OK/.test(res.stdout), 'expected the program to run past the integrity gate:\n' + res.stdout);
});

// 3: blocking a malicious CommonJS module through the real _compile hook.
check('blocks a malicious CJS module (eval + child_process.exec)', () => {
  const evil = write('evil-cjs.js', "const cp = require('child_process');\nconst code = getRemoteCode();\neval(code);\ncp.exec(code);\nmodule.exports = {};\n");
  const res = run([`--require=${agentPath}`, '-e', `require(${JSON.stringify(evil)}); console.log('LOADED');`], { FW_MODE: 'dev' });
  assert.notStrictEqual(res.status, 0, 'malicious module must be blocked (non-zero exit)\nstdout:\n' + res.stdout + '\nstderr:\n' + res.stderr);
  assert.ok(!/LOADED/.test(res.stdout), 'malicious module must not load');
  assert.ok(/COMPILATION LOCKDOWN/.test(res.stderr), 'expected COMPILATION LOCKDOWN banner:\n' + res.stderr);
});

// 4: AST tier catches a bracket-eval obfuscation that the default tiers miss.
check('AST tier (FW_ENABLE_AST=1) blocks a bracket-eval obfuscation', () => {
  const evil = write('evil-ast.js', "const run = this['ev' + 'al'];\nrun('require(\"child_process\").execSync(\"id\")');\nmodule.exports = {};\n");
  const res = run([`--require=${agentPath}`, '-e', `require(${JSON.stringify(evil)}); console.log('LOADED');`], { FW_MODE: 'dev', FW_ENABLE_AST: '1' });
  assert.notStrictEqual(res.status, 0, 'AST tier must block the bracket-eval\nstdout:\n' + res.stdout + '\nstderr:\n' + res.stderr);
  assert.ok(/COMPILATION LOCKDOWN/.test(res.stderr), 'expected COMPILATION LOCKDOWN banner:\n' + res.stderr);
});

// 5: enforcement mode fails closed when the agent is not genuinely preloaded.
check('FW_MODE=enforce without a real --require preload exits non-zero', () => {
  // `node -e "require(agent)"` is the preload-spoof attempt: the agent is required at runtime, not
  // via --require, so enforce mode must refuse.
  const res = run(['-e', `require(${JSON.stringify(agentPath)})`], { FW_MODE: 'enforce' });
  assert.notStrictEqual(res.status, 0, 'enforce mode without preload must exit non-zero, got ' + res.status + '\nstderr:\n' + res.stderr);
  assert.ok(/CRITICAL/.test(res.stderr), 'expected a CRITICAL message on stderr:\n' + res.stderr);
});

// 6: ESM interception — import() a malicious file:// .mjs.
check('blocks (or cleanly skips below floor) a malicious ESM module', () => {
  // CRITICAL: the fixture must run to COMPLETION and print ESM-LOADED when UNPROTECTED — otherwise a
  // nonzero exit proves nothing about the firewall (an earlier fixture threw on an undefined
  // reference, so the "blocked" assertion passed even with the ESM hook entirely absent). This body
  // is benign to execute (assigns a string, exports, logs) but carries a crypto-miner BLOCK
  // signature the firewall must catch at load time.
  const evilMjs = write('evil.mjs', "export const pool = 'stratum+tcp://xmr.pool.evil:3333';\nconsole.log('ESM-LOADED');\n");
  const loader = write('esm-loader.mjs', `await import(${JSON.stringify('file://' + evilMjs)});\n`);
  const [maj, min] = process.versions.node.split('.').map(Number);
  const esmSupported = (maj > 23) || (maj === 23 && min >= 5) || (maj === 22 && min >= 15);

  // Control: WITHOUT the firewall the fixture must load cleanly (exit 0, ESM-LOADED). This proves
  // the fixture itself is valid, so any block below is attributable to the firewall, not the module.
  const unprotected = run([loader], { FW_MODE: 'dev' });
  assert.strictEqual(unprotected.status, 0, 'ESM fixture must load cleanly WITHOUT the firewall (control), got ' + unprotected.status + '\nstderr:\n' + unprotected.stderr);
  assert.ok(/ESM-LOADED/.test(unprotected.stdout), 'ESM fixture must reach completion unprotected (control):\n' + unprotected.stdout);

  const res = run([`--require=${agentPath}`, loader], { FW_MODE: 'dev' });
  if (esmSupported) {
    // Firewall-SPECIFIC assertions: nonzero exit AND the COMPILATION LOCKDOWN banner AND the module
    // did not reach ESM-LOADED. A missing/broken ESM hook would let the control-valid fixture load
    // (exit 0, ESM-LOADED) and fail these — which is the whole point.
    assert.notStrictEqual(res.status, 0, 'on a supported Node version the malicious ESM module must be BLOCKED by the firewall\nstderr:\n' + res.stderr);
    assert.ok(/COMPILATION LOCKDOWN/.test(res.stderr), 'ESM block must come from the firewall (COMPILATION LOCKDOWN banner), not an unrelated error:\n' + res.stderr);
    assert.ok(!/ESM-LOADED/.test(res.stdout), 'malicious ESM module must not reach completion on a supported Node version:\n' + res.stdout);
  } else {
    // Below the ESM hook floor: import() runs unprotected (ESM-LOADED prints, exit 0), and the agent
    // must have warned loudly that ESM is uncovered rather than silently claiming coverage.
    assert.strictEqual(res.status, 0, 'below the ESM floor the module loads unprotected (exit 0), got ' + res.status + '\nstderr:\n' + res.stderr);
    assert.ok(/ESM-LOADED/.test(res.stdout), 'below the ESM floor the module must actually load (proves the fixture is exercised):\n' + res.stdout);
    assert.ok(/ESM static\/dynamic import interception not active|run unprotected/i.test(res.stderr), 'below the ESM floor the agent must emit its specific ESM-uncovered warning:\n' + res.stderr);
    console.log('    (Node ' + process.versions.node + ' is below the ESM hook floor — coverage is CJS-only here, by design)');
  }
});

// ── SRS-FW-004: installed-package onboarding (no source repo) ───────────────────────────────
// 7-10 exercise ONLY what an npm consumer has: the installed package, its bin/ CLIs, and env vars.
const binDir = path.join(projectDir, 'node_modules', '.bin');
function runBin(name, args, cwd) {
  const link = path.join(binDir, name);
  assert.ok(fs.existsSync(link), `installed package must expose the "${name}" bin at ${link}`);
  return spawnSync(process.execPath, [fs.realpathSync(link), ...args], { cwd, encoding: 'utf8', timeout: 30000 });
}
const onboardDir = path.join(projectDir, 'onboarding');
fs.mkdirSync(onboardDir, { recursive: true });

// 7: detection-only posture is reported once (no policy file in cwd).
check('no policy file: one DETECTION-ONLY warning + one POLICY_ABSENT_DETECTION_ONLY audit event', () => {
  const logDir = path.join(onboardDir, 'audit-absent');
  const res = run([`--require=${agentPath}`, '-e', "console.log('RAN')"], { FW_MODE: 'dev', HELIOS_LOG_DIR: logDir }, { cwd: onboardDir });
  assert.strictEqual(res.status, 0, res.stderr);
  assert.strictEqual(res.stderr.split('\n').filter((l) => l.includes('DETECTION-ONLY')).length, 1, 'expected exactly one warning:\n' + res.stderr);
  const events = fs.readFileSync(path.join(logDir, 'audit.log'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.strictEqual(events.filter((e) => e.eventType === 'POLICY_ABSENT_DETECTION_ONLY').length, 1);
});

// 8: package-owned key generation never prints the private key and refuses to overwrite.
check('installed aletheia-policy-keygen writes key files, never prints the private key, refuses overwrite', () => {
  const g = runBin('aletheia-policy-keygen', [], onboardDir);
  assert.strictEqual(g.status, 0, g.stderr);
  assert.ok(!/PRIVATE KEY/.test(g.stdout + g.stderr), 'private key must not be printed');
  assert.ok(fs.existsSync(path.join(onboardDir, 'aletheia-policy-private.pem')));
  assert.ok(fs.existsSync(path.join(onboardDir, 'aletheia-policy-public.pem')));
  const again = runBin('aletheia-policy-keygen', [], onboardDir);
  assert.strictEqual(again.status, 1, 'second run must refuse to overwrite, got ' + again.status);
});

// 9: package-owned signing + enforcement with the consumer's own key via FW_POLICY_PUBKEY.
check('installed aletheia-policy-sign + FW_POLICY_PUBKEY: BLOCK rule enforced from the installed package', () => {
  fs.writeFileSync(path.join(onboardDir, 'blocked-mod.js'), "module.exports = 'BLOCKED-MOD-RAN';\n");
  fs.writeFileSync(path.join(onboardDir, 'rules.json'), JSON.stringify({ 'blocked-mod.js': 'BLOCK' }));
  const s = runBin('aletheia-policy-sign', ['aletheia-policy-private.pem', 'rules.json', 'policy.signed.json'], onboardDir);
  assert.strictEqual(s.status, 0, s.stderr);
  const env = { FW_MODE: 'dev', FW_POLICY_PUBKEY: fs.readFileSync(path.join(onboardDir, 'aletheia-policy-public.pem'), 'utf8'), FW_ALLOW_DEV_POLICY_KEY: '0', HELIOS_LOG_DIR: path.join(onboardDir, 'audit-policy') };
  const res = run([`--require=${agentPath}`, '-e', "try { console.log(require('./blocked-mod.js')); } catch (e) { console.log('DENIED: ' + e.message); }"], env, { cwd: onboardDir });
  assert.strictEqual(res.status, 0, res.stderr);
  assert.ok(/DENIED: \[Firewall\] Compilation denied/.test(res.stdout), 'BLOCK rule must be enforced:\n' + res.stdout + res.stderr);
  assert.ok(!res.stderr.includes('DETECTION-ONLY'), 'must not report detection-only when a valid policy is loaded:\n' + res.stderr);
});

// 10: FW_REQUIRE_ESM_COVERAGE=1 is the fail-closed control for ESM coverage.
check('FW_REQUIRE_ESM_COVERAGE=1: starts on a supported Node, refuses to start below the ESM floor', () => {
  const [maj, min] = process.versions.node.split('.').map(Number);
  const esmSupported = (maj > 23) || (maj === 23 && min >= 5) || (maj === 22 && min >= 15);
  const res = run([`--require=${agentPath}`, '-e', "console.log('RAN')"], { FW_MODE: 'dev', FW_REQUIRE_ESM_COVERAGE: '1' });
  if (esmSupported) assert.strictEqual(res.status, 0, res.stderr);
  else { assert.strictEqual(res.status, 1, 'expected exit 1 below the ESM floor, got ' + res.status); assert.ok(/FW_REQUIRE_ESM_COVERAGE=1 is set/.test(res.stderr), res.stderr); }
});

console.log(`\n[smoke] all tarball smoke checks passed (${passed}).`);
