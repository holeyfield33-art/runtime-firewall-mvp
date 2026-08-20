// packages/fw-agent/test/cache-poisoning-test.js
// F-58 regression: Module._load() -- the actual require() entry point -- checks
// Module._cache[resolvedPath] BEFORE Module.prototype._compile ever runs. Without a Module._load
// wrap, allowed code can insert a forged module (or even a bare `{ exports }` object -- Node's
// cache-hit path never requires a real Module instance) directly into
// require.cache[resolvedPath]; require() returns the forged exports, the target's real code
// never executes, and the _compile hook -- and therefore all detection -- never sees the file.
//
// Required test matrix (P0 hardening directive, PR5):
//   1. Attack case: forged module inserted into require.cache directly, under all three
//      FW_CACHE_POLICY values, with the audit log verified to record the specific
//      CACHE_SUBSTITUTION event (not a generic block).
//   2. Normal caching, unaffected: require('./x') twice -- one real verification, one legitimate
//      cache hit -- under the strictest policy (block), with no false positive.
//   3. Legitimate synthetic cache: a bare synthetic entry with no real module body, under audit
//      (allowed + audited) vs block (refused).
//   4. Real tooling: proxyquire -- an actual, widely-used npm package whose stubbing mechanism
//      temporarily REPLACES Module._cache wholesale (see node_modules/proxyquire/lib/
//      proxyquire.js) -- under all three policy values, confirming no regression.
//
// jest's own module-registry behavior was also validated manually (real `jest --runInBand` run
// under FW_CACHE_POLICY=block/audit/allow, all three: 1 passed, 1 total, no false positives) but
// is not wired into this file: jest pulls in ~300 transitive packages, too heavy to justify as a
// permanent devDependency for one compatibility check on a project that otherwise runs its own
// tests with zero test-framework dependencies. See the PR5 commit message for that evidence.
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const AGENT_PATH = path.join(__dirname, '..', 'index.js');

let passed = 0;
function check(name, fn) {
  try {
    fn();
    console.log('  ✓ ' + name);
    passed++;
  } catch (e) {
    console.error('  ✗ ' + name + '\n    ' + (e && e.stack || e));
    process.exit(1);
  }
}

function mkTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function readAuditEvents(logDir) {
  const logPath = path.join(logDir, 'audit.log');
  if (!fs.existsSync(logPath)) return [];
  return fs.readFileSync(logPath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

function runChild(cwd, script, envExtra) {
  const logDir = mkTmpDir('fw-cache-auditlog-');
  const res = spawnSync(process.execPath, ['--require', AGENT_PATH, '-e', script], {
    cwd,
    encoding: 'utf8',
    timeout: 15000,
    env: Object.assign({}, process.env, { FW_ENABLE_DETECTION: '1', FW_MODE: 'dev', HELIOS_LOG_DIR: logDir }, envExtra),
  });
  res.auditEvents = readAuditEvents(logDir);
  fs.rmSync(logDir, { recursive: true, force: true });
  return res;
}

function parseResult(stdout) {
  const m = /RESULT:(.*)/.exec(stdout || '');
  if (!m) throw new Error('child produced no RESULT: line. stdout=\n' + stdout);
  return JSON.parse(m[1]);
}

// ── 1. Attack case: forged Module inserted directly into require.cache ─────────────────────────
(function attackCase() {
  const tmp = mkTmpDir('fw-cache-attack-');
  const target = path.join(tmp, 'forged-target.js');
  fs.writeFileSync(target, 'module.exports = { legitimate: true };\n');

  const attackScript = `
    const Module = require('module');
    const fw = require(${JSON.stringify(AGENT_PATH)});
    // Node's own "-e" inline-script wrapping counts as one _compile pass by itself (confirmed:
    // present identically on the pre-PR5 baseline, unrelated to this fix) -- capture it here so
    // the assertion below is about the DELTA caused by the forged target, not an absolute count.
    const baselineCompilations = fw.compileMetrics.filesCompiled;
    const target = ${JSON.stringify(target)};
    const forged = new Module(target, null);
    forged.filename = target;
    forged.loaded = true;
    forged.exports = { stolen: true };
    require.cache[target] = forged;
    let result, threw = null;
    try { result = require(target); } catch (e) { threw = e.message; }
    console.log('RESULT:' + JSON.stringify({ result, threw, compilationsDelta: fw.compileMetrics.filesCompiled - baselineCompilations }));
  `;

  check('attack + FW_CACHE_POLICY=block: refuses the forged entry, Compilations does not increment, audit log records CACHE_SUBSTITUTION_DETECTED/BLOCK', () => {
    const res = runChild(tmp, attackScript, { FW_CACHE_POLICY: 'block' });
    const result = parseResult(res.stdout);
    assert.strictEqual(result.result, undefined, 'require() must not return the forged exports');
    assert.ok(result.threw && /unverified require\.cache entry/.test(result.threw), 'expected a cache-substitution refusal, got: ' + result.threw);
    assert.strictEqual(result.compilationsDelta, 0, 'the forged file must never have been _compiled/scanned');
    const evt = res.auditEvents.find(e => e.eventType === 'CACHE_SUBSTITUTION_DETECTED');
    assert.ok(evt, 'audit log must record a CACHE_SUBSTITUTION_DETECTED event: ' + JSON.stringify(res.auditEvents));
    assert.strictEqual(evt.action, 'BLOCK', 'the specific event must record the BLOCK action, not a generic one');
    assert.strictEqual(evt.policy, 'block');
  });

  check('attack + FW_CACHE_POLICY=audit: allows the forged entry through but audits it (log + console)', () => {
    const res = runChild(tmp, attackScript, { FW_CACHE_POLICY: 'audit' });
    const result = parseResult(res.stdout);
    assert.deepStrictEqual(result.result, { stolen: true }, 'audit policy still allows the forged export through');
    assert.strictEqual(result.threw, null);
    assert.strictEqual(result.compilationsDelta, 0, 'still never scanned -- audit does not retroactively scan');
    assert.ok(/AUDIT:/.test(res.stderr), 'expected a visible AUDIT warning on stderr:\n' + res.stderr);
    const evt = res.auditEvents.find(e => e.eventType === 'CACHE_SUBSTITUTION_DETECTED');
    assert.ok(evt, 'audit log must record the event even when allowed: ' + JSON.stringify(res.auditEvents));
    assert.strictEqual(evt.action, 'AUDIT_ALLOW');
  });

  check('attack + FW_CACHE_POLICY=allow: silently allows the forged entry (no console warning), still logged to disk', () => {
    const res = runChild(tmp, attackScript, { FW_CACHE_POLICY: 'allow' });
    const result = parseResult(res.stdout);
    assert.deepStrictEqual(result.result, { stolen: true });
    assert.strictEqual(result.compilationsDelta, 0);
    assert.ok(!/AUDIT:/.test(res.stderr), 'allow policy must not print the audit warning:\n' + res.stderr);
    const evt = res.auditEvents.find(e => e.eventType === 'CACHE_SUBSTITUTION_DETECTED');
    assert.ok(evt, 'even the silent "allow" path must still write to the persistent audit log: ' + JSON.stringify(res.auditEvents));
    assert.strictEqual(evt.action, 'ALLOW');
  });

  check('attack + default policy (FW_MODE=dev, FW_CACHE_POLICY unset) behaves like audit', () => {
    const res = runChild(tmp, attackScript, {});
    const result = parseResult(res.stdout);
    assert.deepStrictEqual(result.result, { stolen: true });
    assert.ok(/AUDIT:/.test(res.stderr), 'dev-mode default must be audit (visible), not silent allow:\n' + res.stderr);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

// ── 2. Normal caching, unaffected: real double-require under the strictest policy ──────────────
(function normalCaching() {
  const tmp = mkTmpDir('fw-cache-normal-');
  const target = path.join(tmp, 'normal.js');
  fs.writeFileSync(target, 'module.exports = { real: true, n: Math.random() };\n');
  const jsonTarget = path.join(tmp, 'config.json');
  fs.writeFileSync(jsonTarget, '{"a":1}');

  const script = `
    const fw = require(${JSON.stringify(AGENT_PATH)});
    // See the attack-case comment above: Node's own "-e" wrapping counts as one _compile pass
    // on its own, unrelated to this fix -- measure the delta instead of an absolute count.
    const baselineCompilations = fw.compileMetrics.filesCompiled;
    const target = ${JSON.stringify(target)};
    const jsonTarget = ${JSON.stringify(jsonTarget)};
    const r1 = require(target);
    const r2 = require(target);
    const j1 = require(jsonTarget);
    const j2 = require(jsonTarget);
    console.log('RESULT:' + JSON.stringify({
      sameRef: r1 === r2,
      jsonSameRef: j1 === j2,
      compilationsDelta: fw.compileMetrics.filesCompiled - baselineCompilations,
    }));
  `;

  check('two require() calls for the same .js file, under FW_CACHE_POLICY=block: second call is a real cache hit, no false positive, exactly one real compilation', () => {
    const res = runChild(tmp, script, { FW_CACHE_POLICY: 'block' });
    const result = parseResult(res.stdout);
    assert.strictEqual(result.sameRef, true, 'second require() must return the exact same cached export object');
    assert.strictEqual(result.jsonSameRef, true, 'JSON double-require must also be an untouched cache hit (JSON never routes through _compile)');
    assert.strictEqual(result.compilationsDelta, 1, 'only ONE real compilation should have happened for the .js file');
    assert.ok(!/CACHE_SUBSTITUTION|unverified require\.cache entry/.test(res.stderr), 'no cache-substitution event for a genuine, firewall-verified cache hit:\n' + res.stderr);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

// ── 3. Legitimate synthetic cache: a bare entry with no real module body ───────────────────────
(function syntheticCache() {
  const tmp = mkTmpDir('fw-cache-synthetic-');
  const target = path.join(tmp, 'synthetic-target.js');
  // The file exists on disk (module resolution needs SOMETHING to resolve to) but its real
  // content is never what gets returned -- the synthetic cache entry pre-empts it entirely.
  fs.writeFileSync(target, 'module.exports = { real: true };\n');

  const syntheticScript = `
    const target = ${JSON.stringify(target)};
    // No real Module instance at all -- just a bare object with the two properties Node's
    // Module._load cache-hit path actually reads (loaded, exports). This is the exact
    // "require.cache[target] = { exports: maliciousObject }, no real module body" case.
    require.cache[target] = { loaded: true, exports: { synthetic: true } };
    let result, threw = null;
    try { result = require(target); } catch (e) { threw = e.message; }
    console.log('RESULT:' + JSON.stringify({ result, threw }));
  `;

  check('synthetic (bare, non-Module) cache entry + FW_CACHE_POLICY=audit: allowed and audited', () => {
    const res = runChild(tmp, syntheticScript, { FW_CACHE_POLICY: 'audit' });
    const result = parseResult(res.stdout);
    assert.deepStrictEqual(result.result, { synthetic: true });
    const evt = res.auditEvents.find(e => e.eventType === 'CACHE_SUBSTITUTION_DETECTED');
    assert.ok(evt && evt.action === 'AUDIT_ALLOW', 'expected an audited allow for the synthetic entry: ' + JSON.stringify(res.auditEvents));
  });

  check('synthetic (bare, non-Module) cache entry + FW_CACHE_POLICY=block: refused', () => {
    const res = runChild(tmp, syntheticScript, { FW_CACHE_POLICY: 'block' });
    const result = parseResult(res.stdout);
    assert.strictEqual(result.result, undefined);
    assert.ok(result.threw && /unverified require\.cache entry/.test(result.threw), 'expected refusal, got: ' + result.threw);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
})();

// ── 4. Real tooling: proxyquire (actual npm package, not simulated) ────────────────────────────
(function realTooling() {
  let proxyquireDir;
  try {
    proxyquireDir = path.dirname(require.resolve('proxyquire/package.json', { paths: [path.join(__dirname, '..', '..', '..')] }));
  } catch (e) {
    console.log('  (skipped) proxyquire not installed -- real-tooling check requires `npm install` at the repo root');
    return;
  }

  const tmp = mkTmpDir('fw-cache-proxyquire-');
  fs.writeFileSync(path.join(tmp, 'dep.js'), "module.exports = { greet: () => 'real' };\n");
  fs.writeFileSync(path.join(tmp, 'sut.js'), "const dep = require('./dep');\nmodule.exports = { hello: () => dep.greet() };\n");

  const script = `
    const proxyquire = require(${JSON.stringify(path.join(proxyquireDir))});
    const stubbed = proxyquire('./sut', { './dep': { greet: () => 'stubbed' } });
    const real = require('./sut');
    console.log('RESULT:' + JSON.stringify({ stubbed: stubbed.hello(), real: real.hello() }));
  `;

  for (const policy of ['block', 'audit', 'allow']) {
    check(`real tooling (proxyquire) + FW_CACHE_POLICY=${policy}: proxyquire's own Module._cache manipulation is unaffected (no false positive)`, () => {
      const res = runChild(tmp, script, { FW_CACHE_POLICY: policy });
      const result = parseResult(res.stdout);
      assert.strictEqual(result.stubbed, 'stubbed', 'proxyquire stub must still apply, got: ' + JSON.stringify(result));
      assert.strictEqual(result.real, 'real', 'the real (non-stubbed) module must still load correctly, got: ' + JSON.stringify(result));
      assert.strictEqual(res.status, 0, 'proxyquire usage must not crash the process:\n' + res.stderr);
    });
  }

  fs.rmSync(tmp, { recursive: true, force: true });
})();

console.log(`\n${passed} cache-poisoning (F-58) checks passed.`);
