#!/usr/bin/env node
// red-team/run.js
// ─────────────────────────────────────────────────────────────────────────────
// Helios Runtime Firewall — Red-Team Attack Suite
//
// Runs a corpus of adversarial JavaScript module payloads through the firewall's
// detector and LOGS WHAT GETS THROUGH AND WHAT DOESN'T. The block decision here is
// identical to the one index.js makes on every require(): a module is BLOCKED
// (QUARANTINE) iff the detector produces at least one non-warnOnly detection.
//
//   BLOCKED  — the firewall stopped the module (QUARANTINE)
//   PASSED   — the module was allowed to load (OBSERVE)
//
// Verdicts (expected vs. actual):
//   caught          malicious payload -> BLOCKED         (firewall did its job)
//   BYPASS          malicious payload -> PASSED           (got through)
//     .known        a documented static-analysis gap (needs runtime/AST analysis)
//     .REGRESSION   a bypass we did NOT expect — a real hole / broken defense
//   clean           benign control   -> PASSED           (no false positive)
//   FALSE-POSITIVE  benign control    -> BLOCKED          (over-blocking)
//
// The suite fails (exit 1) only on REGRESSIONs or FALSE-POSITIVEs. Known bypasses
// are logged as accepted gaps and never fail the build.
//
// Usage:
//   node red-team/run.js [--category <name>] [--output <file>] [--quiet] [--only-bypass]
//   npm run redteam
// ─────────────────────────────────────────────────────────────────────────────

const fs = require('fs');
const path = require('path');

const { Detector } = require('../packages/fw-agent/src/detector');
const { corpus } = require('./corpus');

// ── args ─────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { output: null, category: null, quiet: false, onlyBypass: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--output' || a === '-o') args.output = argv[++i];
    else if (a === '--category' || a === '-c') args.category = argv[++i];
    else if (a === '--quiet' || a === '-q') args.quiet = true;
    else if (a === '--only-bypass') args.onlyBypass = true;
    else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  }
  return args;
}

function printHelp() {
  console.log(`Helios Red-Team Attack Suite

  node red-team/run.js [options]

  -c, --category <name>   Run only one category (crypto-miner, reverse-shell,
                          credential-exfil, dynamic-code-exec, supply-chain,
                          benign-controls)
  -o, --output <file>     Write the JSON summary here
                          (default: results/redteam-summary.json)
  -q, --quiet             Suppress the per-attack table; print the summary only
      --only-bypass       Only print rows that got through (bypasses + false neg)
  -h, --help              Show this help`);
}

// ── colour helpers (auto-disabled when not a TTY) ────────────────────────────
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s) => c('31', s);
const green = (s) => c('32', s);
const yellow = (s) => c('33', s);
const dim = (s) => c('2', s);
const bold = (s) => c('1', s);

// ── evaluate one attack ──────────────────────────────────────────────────────
// A module is "blocked" exactly when the detector yields a non-warnOnly detection,
// mirroring index.js: `scanResult.detections.filter(d => !d.warnOnly)`.
function evaluate(detector, attack) {
  detector.behaviorTracker.reset();
  const filename = `${attack.id}.js`;
  const result = detector.scanModuleSync(filename, attack.code, filename);

  const blockDetections = result.detections.filter((d) => !d.warnOnly);
  const warnDetections = result.detections.filter((d) => d.warnOnly);
  const outcome = blockDetections.length > 0 ? 'BLOCKED' : 'PASSED';

  let verdict;
  if (attack.expected === 'BLOCK') {
    if (outcome === 'BLOCKED') verdict = 'caught';
    else verdict = attack.knownBypass ? 'known-bypass' : 'REGRESSION';
  } else {
    // expected PASS (benign control or by-design WARN)
    verdict = outcome === 'PASSED' ? 'clean' : 'FALSE-POSITIVE';
  }

  return {
    id: attack.id,
    category: attack.category,
    technique: attack.technique,
    severity: attack.severity,
    expected: attack.expected,
    knownBypass: Boolean(attack.knownBypass),
    description: attack.description,
    outcome,
    verdict,
    gotThrough: outcome === 'PASSED' && attack.expected === 'BLOCK',
    rules: blockDetections.map((d) => d.rule || d.type),
    warnMatches: warnDetections.map((d) => d.rule || d.matched || d.type),
    detections: result.detections,
  };
}

// ── run ──────────────────────────────────────────────────────────────────────
function run(args) {
  const detector = new Detector(new Map());
  const selected = args.category
    ? corpus.filter((a) => a.category === args.category)
    : corpus;

  if (selected.length === 0) {
    console.error(red(`No attacks found for category "${args.category}".`));
    const cats = [...new Set(corpus.map((a) => a.category))].sort();
    console.error(`Available: ${cats.join(', ')}`);
    process.exit(2);
  }

  const rows = selected.map((a) => evaluate(detector, a));

  // ── per-category rollup ────────────────────────────────────────────────────
  const categories = {};
  for (const r of rows) {
    const cat = (categories[r.category] ||= {
      total: 0, malicious: 0, benign: 0,
      blocked: 0, passed: 0,
      caught: 0, knownBypasses: 0, regressions: 0, falsePositives: 0,
    });
    cat.total++;
    if (r.expected === 'BLOCK') cat.malicious++; else cat.benign++;
    if (r.outcome === 'BLOCKED') cat.blocked++; else cat.passed++;
    if (r.verdict === 'caught') cat.caught++;
    else if (r.verdict === 'known-bypass') cat.knownBypasses++;
    else if (r.verdict === 'REGRESSION') cat.regressions++;
    else if (r.verdict === 'FALSE-POSITIVE') cat.falsePositives++;
  }

  const malicious = rows.filter((r) => r.expected === 'BLOCK');
  const benign = rows.filter((r) => r.expected === 'PASS');
  const gapReport = rows.filter((r) => r.gotThrough); // everything malicious that got through
  const regressions = rows.filter((r) => r.verdict === 'REGRESSION');
  const knownBypasses = rows.filter((r) => r.verdict === 'known-bypass');
  const falsePositives = rows.filter((r) => r.verdict === 'FALSE-POSITIVE');
  const caught = malicious.filter((r) => r.outcome === 'BLOCKED');

  const detectionRate = malicious.length
    ? (caught.length / malicious.length) * 100 : 0;

  const summary = {
    tool: 'helios-red-team-suite',
    target: 'runtime-firewall-mvp :: Detector.scanModuleSync (index.js block rule)',
    generatedAt: new Date().toISOString(),
    categoryFilter: args.category || null,
    totals: {
      attacks: rows.length,
      malicious: malicious.length,
      benign: benign.length,
      blocked: rows.filter((r) => r.outcome === 'BLOCKED').length,
      passed: rows.filter((r) => r.outcome === 'PASSED').length,
      caught: caught.length,
      bypasses: gapReport.length,
      knownBypasses: knownBypasses.length,
      regressions: regressions.length,
      falsePositives: falsePositives.length,
      detectionRatePct: Number(detectionRate.toFixed(1)),
    },
    categories,
    gap_report: gapReport.map((r) => ({
      id: r.id, category: r.category, technique: r.technique,
      severity: r.severity, knownBypass: r.knownBypass, description: r.description,
    })),
    false_positives: falsePositives.map((r) => ({
      id: r.id, category: r.category, technique: r.technique,
      rulesTriggered: r.rules, description: r.description,
    })),
    results: rows.map((r) => ({
      id: r.id, category: r.category, technique: r.technique, severity: r.severity,
      expected: r.expected, outcome: r.outcome, verdict: r.verdict,
      knownBypass: r.knownBypass, rules: r.rules, warnMatches: r.warnMatches,
    })),
  };

  if (!args.quiet) printReport(rows, summary, args);
  else printSummaryBlock(summary);

  // ── write JSON summary ─────────────────────────────────────────────────────
  const outPath = args.output
    ? path.resolve(process.cwd(), args.output)
    : path.join(__dirname, '..', 'results', 'redteam-summary.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(summary, null, 2) + '\n');
  console.log(dim(`\nJSON summary written to ${path.relative(process.cwd(), outPath)}`));

  // ── exit code: regressions or false positives fail the build ───────────────
  const failed = regressions.length + falsePositives.length;
  if (failed > 0) process.exit(1);
}

// ── reporting ────────────────────────────────────────────────────────────────
const VERDICT_STYLE = {
  'caught': (s) => green(s),
  'clean': (s) => green(s),
  'known-bypass': (s) => yellow(s),
  'REGRESSION': (s) => red(bold(s)),
  'FALSE-POSITIVE': (s) => red(bold(s)),
};
const VERDICT_ICON = {
  'caught': '✅', 'clean': '✅',
  'known-bypass': '⚠️ ', 'REGRESSION': '❌', 'FALSE-POSITIVE': '❌',
};

function printReport(rows, summary, args) {
  console.log('\n' + '═'.repeat(72));
  console.log(bold('  Helios Runtime Firewall — Red-Team Attack Suite'));
  console.log('  ' + dim(summary.target));
  console.log('═'.repeat(72));

  const byCat = {};
  for (const r of rows) (byCat[r.category] ||= []).push(r);

  for (const cat of Object.keys(byCat)) {
    console.log('\n' + bold(`▸ ${cat}`) + dim(`  (${byCat[cat].length})`));
    for (const r of byCat[cat]) {
      if (args.onlyBypass && !r.gotThrough && r.verdict !== 'FALSE-POSITIVE') continue;
      const style = VERDICT_STYLE[r.verdict] || ((s) => s);
      const icon = VERDICT_ICON[r.verdict] || '  ';
      const tag = style(r.verdict.padEnd(14));
      const flow = r.outcome === 'BLOCKED' ? green('BLOCKED') : yellow('PASSED ');
      const rules = r.rules.length ? dim(' [' + r.rules.join(', ') + ']')
        : (r.warnMatches.length ? dim(' [warn: ' + r.warnMatches.join(', ') + ']') : '');
      console.log(`  ${icon} ${tag} ${flow}  ${r.id}${rules}`);
      if (r.gotThrough || r.verdict === 'FALSE-POSITIVE') {
        console.log(dim(`        └─ ${r.description}`));
      }
    }
  }

  printSummaryBlock(summary);
}

function printSummaryBlock(summary) {
  const t = summary.totals;
  console.log('\n' + '─'.repeat(72));
  console.log(bold('  Summary'));
  console.log('─'.repeat(72));
  console.log(`  Attacks run .............. ${t.attacks}  (${t.malicious} malicious, ${t.benign} benign)`);
  console.log(`  Blocked (QUARANTINE) ..... ${t.blocked}`);
  console.log(`  Passed  (OBSERVE) ........ ${t.passed}`);
  console.log(`  ${green('Malicious caught')} ......... ${t.caught}/${t.malicious}   (detection rate ${t.detectionRatePct}%)`);
  console.log(`  ${yellow('Known bypasses')} ........... ${t.knownBypasses}   ${dim('(accepted static-analysis gaps)')}`);
  console.log(`  ${red('NEW bypasses (regressions)')}  ${t.regressions}`);
  console.log(`  ${red('False positives')} .......... ${t.falsePositives}`);

  console.log('\n  ' + bold('Per category') + dim('  (malicious caught / total malicious, false pos)'));
  for (const [cat, s] of Object.entries(summary.categories)) {
    const cov = s.malicious ? `${s.caught}/${s.malicious}` : '—  ';
    const fp = s.falsePositives ? red(` FP:${s.falsePositives}`) : '';
    const kb = s.knownBypasses ? yellow(` known-bypass:${s.knownBypasses}`) : '';
    console.log(`    ${cat.padEnd(20)} ${cov}${kb}${fp}`);
  }

  if (summary.gap_report.length) {
    console.log('\n  ' + bold('What got through (gap report)'));
    for (const g of summary.gap_report) {
      const tag = g.knownBypass ? yellow('[known]') : red('[NEW]  ');
      console.log(`    ${tag} ${g.id}  ${dim('(' + g.technique + ')')}`);
    }
  }

  if (summary.false_positives.length) {
    console.log('\n  ' + red(bold('False positives (over-blocking)')));
    for (const f of summary.false_positives) {
      console.log(`    ${red('✗')} ${f.id}  ${dim('rules: ' + f.rulesTriggered.join(', '))}`);
    }
  }

  const verdict = (summary.totals.regressions + summary.totals.falsePositives) === 0
    ? green(bold('PASS — no regressions, no false positives'))
    : red(bold(`FAIL — ${summary.totals.regressions} regression(s), ${summary.totals.falsePositives} false positive(s)`));
  console.log('\n  ' + verdict);
}

run(parseArgs(process.argv.slice(2)));
