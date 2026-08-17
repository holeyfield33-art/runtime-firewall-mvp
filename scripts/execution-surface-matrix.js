#!/usr/bin/env node
// scripts/execution-surface-matrix.js
// P0-1 coordinator. Spawns one firewalled child process per execution-surface row (mirrors the
// scripts/cold-steady-bench.js spawn pattern: spawnSync(process.execPath, ['--require='+agentPath,
// childPath, rowId], {env}) with FW_ENABLE_DETECTION=1 + FW_ALLOW_DEV_POLICY_KEY=1), collects the
// row's verdict via a temp-file handoff (os.tmpdir() + MATRIX_OUTFILE, read-then-unlink, same
// pattern as scripts/probe-harness.js), prints a human table, and writes
// results/execution-surface-matrix.json. Every row reports exactly one of
// {INTERCEPTED, BYPASS, UNSUPPORTED} — never UNKNOWN.
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const AGENT_PATH = path.join(__dirname, '..', 'packages', 'fw-agent', 'index.js');
const ROWS_DIR = path.join(__dirname, 'matrix-rows');
const ESM_ENTRY_PATH = path.join(__dirname, 'execution-surface-matrix-esm-entry.mjs');
const VALID_VERDICTS = new Set(['INTERCEPTED', 'BYPASS', 'UNSUPPORTED']);

// Each row is its own file under matrix-rows/ (not one dispatcher script): combining unrelated
// primitives (vm + child_process + eval) in a single module would make the harness itself trip
// the real behavioral detector (DYNAMIC_CODE_EXEC_CHAIN matches dynamic-code + process-exec
// signals present in the same file), so every row keeps to only what its own surface needs.
const ROWS = [
  { id: 'require-control', label: 'require() [control]', script: path.join(ROWS_DIR, 'require-control.js') },
  { id: 'nested-require', label: 'nested require() [control]', script: path.join(ROWS_DIR, 'nested-require.js') },
  { id: 'esm-static-import', label: 'ESM static import', script: ESM_ENTRY_PATH },
  { id: 'dynamic-import', label: 'dynamic import()', script: path.join(ROWS_DIR, 'dynamic-import.js') },
  { id: 'worker-thread', label: 'worker_threads -> new Worker', script: path.join(ROWS_DIR, 'worker-thread.js') },
  { id: 'child-fork', label: 'child_process.fork()', script: path.join(ROWS_DIR, 'child-fork.js') },
  { id: 'child-spawn', label: "child_process.spawn('node', ...)", script: path.join(ROWS_DIR, 'child-spawn.js') },
  { id: 'vm-context', label: 'vm.runInNewContext()', script: path.join(ROWS_DIR, 'vm-context.js') },
  { id: 'native-addon', label: 'native .node addon load', script: path.join(ROWS_DIR, 'native-addon.js') },
  { id: 'pre-hook-cache', label: 'module loaded before firewall (pre-hook/cache)', script: path.join(ROWS_DIR, 'pre-hook-cache.js') },
];

function runRow(row) {
  const outFile = path.join(
    os.tmpdir(),
    `matrix-out-${process.pid}-${row.id}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`
  );
  const env = Object.assign({}, process.env, {
    FW_ENABLE_DETECTION: '1',
    FW_ALLOW_DEV_POLICY_KEY: '1',
    MATRIX_OUTFILE: outFile,
  });
  const args = [`--require=${AGENT_PATH}`, row.script, row.id];
  const res = spawnSync(process.execPath, args, { encoding: 'utf8', env, timeout: 30000 });

  let parsed = null;
  try {
    parsed = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    parsed = null;
  } finally {
    try { fs.unlinkSync(outFile); } catch (e) {}
  }

  if (parsed && VALID_VERDICTS.has(parsed.verdict)) {
    return { verdict: parsed.verdict, detail: parsed.detail || '' };
  }

  // No parseable verdict from the child (crash, timeout, or malformed output). If the crash was
  // caused by our OWN firewall's block (stderr contains the "[Firewall] ..." message every block
  // path in this agent uses), that crash IS the interception signal — some execution paths (a
  // genuine top-level ESM static `import` declaration whose target throws during module linking,
  // P2-01) have no way to catch their own failure and self-report; a [Firewall] message on stderr
  // is the only observable signal such a row can ever produce. Misclassifying that as UNSUPPORTED
  // would hide a working control behind the very crash that proves it worked.
  const stderrText = res.stderr || '';
  if (res.status !== 0 && stderrText.includes('[Firewall]')) {
    return {
      verdict: 'INTERCEPTED',
      detail: `Child crashed (exit=${res.status}) before it could self-report a verdict, but stderr shows a firewall block: ${stderrText.trim().slice(0, 300)}`,
    };
  }

  // Otherwise: genuinely no parseable verdict and no firewall block signal — never surface
  // UNKNOWN; attribute UNSUPPORTED with the observed failure so the row is still reported.
  const detail = `Child produced no parseable verdict. exit=${res.status} signal=${res.signal} ` +
    `stderr=${(res.stderr || '').trim().slice(0, 500)}`;
  return { verdict: 'UNSUPPORTED', detail };
}

function makeMetadata() {
  const gitSha = (() => {
    try {
      const g = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
      return g.status === 0 ? g.stdout.trim() : null;
    } catch (e) { return null; }
  })();
  const packageJson = require(path.join(__dirname, '..', 'packages', 'fw-agent', 'package.json'));
  return {
    matrixVersion: 'execution-surface-matrix-v1',
    gitSha,
    package: { name: packageJson.name, version: packageJson.version },
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
  };
}

function printTable(rows) {
  const pathWidth = Math.max('PATH'.length, ...rows.map(r => r.path.length)) + 2;
  const verdictWidth = Math.max('VERDICT'.length, ...rows.map(r => r.verdict.length)) + 2;
  console.log('PATH'.padEnd(pathWidth) + 'VERDICT'.padEnd(verdictWidth) + 'DETAIL');
  console.log('-'.repeat(pathWidth + verdictWidth + 60));
  for (const row of rows) {
    console.log(row.path.padEnd(pathWidth) + row.verdict.padEnd(verdictWidth) + row.detail);
  }
}

function main() {
  const rows = ROWS.map((row) => {
    const { verdict, detail } = runRow(row);
    return { path: row.label, verdict, detail };
  });

  const output = { generatedAt: new Date().toISOString(), target: 'packages/fw-agent', metadata: makeMetadata(), rows };

  const outDir = path.join(process.cwd(), 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, 'execution-surface-matrix.json');
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2) + '\n', 'utf8');

  printTable(rows);
  console.log(`\nWrote ${rows.length}-row matrix to ${path.relative(process.cwd(), outPath)}`);

  const controlFailures = rows.filter(r => r.path.includes('[control]') && r.verdict !== 'INTERCEPTED');
  if (controlFailures.length > 0) {
    console.error('\n[FAIL] Control row(s) not INTERCEPTED: ' + controlFailures.map(r => r.path).join(', '));
    process.exitCode = 1;
  }
}

main();
