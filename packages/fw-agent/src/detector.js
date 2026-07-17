// packages/fw-agent/src/detector.js
const { AhoCorasick } = require('./aho-corasick');
const { BehaviorTracker } = require('./behavior-tracker');

// Extended signature set covers crypto-miners, dynamic code execution, network abuse,
// and supply-chain worm patterns (postinstall fetchers, credential harvesters).
// High-confidence malicious signatures — trigger QUARANTINE/BLOCK on match.
const BLOCK_SIGNATURES = [
  '/dev/tcp/',
  // Reverse-shell redirect idiom (F-29): bare 'bash -i' / 'sh -i' also match ordinary
  // interactive-shell invocations of unrelated tools (push -i, fish -i, wash -i, ...).
  // Real reverse shells redirect stdio via '>&' — require that too.
  'bash -i >&',
  'sh -i >&',
  // Crypto-miner pool identifiers. F-29: bare 'stratum' matches the mining-protocol word
  // wherever it occurs in English prose (e.g. dictionary/word-list packages containing
  // "stratum", "substratum", "stratus"), so match the pool-URL scheme instead — that's
  // what real miner configs actually contain.
  'stratum+tcp',
  'stratum://',
  'pool.hashvault',
  'coin-hive',
  'xmr-stak',
  'nicehash',
  'coinhive',
  'cryptonight',
  // Additional browser/pool miner brands with no stratum literal (red-team group B). These
  // are distinctive product names that do not occur in ordinary prose or legitimate code.
  'coinimp',
  'jsecoin',
  'webminepool',
  'deepminer',
  // Supply-chain worm indicators
  '//pastebin',
  '//paste.ee',
  '| bash',
];

// Regex-tier block signatures for idioms that must be anchored beyond a literal substring.
// A bare '| sh' literal in the Aho-Corasick set would false-match '| shorten', '| sha256sum',
// '| ssh', etc.; the \b after the shell name prevents that. Covers the sh/dash/zsh stagers the
// literal '| bash' above misses (revsh-wget-pipe-sh, sc-preinstall-curl-sh): piping a
// downloaded payload straight into a shell is a high-confidence stager.
const BLOCK_REGEXES = [
  // Require whitespace after the pipe (`| sh`, not `|sh`): a `|word|word|` token list — e.g.
  // he.js's HTML-entity table `|dArr|dash|Sqrt|` — otherwise matches `|dash` as `| da + sh`.
  // All real stagers in the corpus (`curl … | sh`, `wget … | sh`) space the pipe. `|sh` without
  // a space is a documented residual gap (see THREAT-COVERAGE.md).
  { re: /\|\s+(?:ba|da|z)?sh\b/i, type: 'dynamic-code-exec', severity: 'HIGH', label: 'pipe-to-shell-stager' },
  // Reverse-shell tooling beyond /dev/tcp (red-team group E). Each is anchored to the exact
  // exploit idiom (a flag, a scheme, or an API path) so it cannot match ordinary prose or
  // legitimate command strings — none of these occur in benign npm module source.
  { re: /\bnc\s+-e\b/i,                          type: 'reverse-shell', severity: 'HIGH', label: 'netcat-exec' },
  { re: /\bncat\s+(?:--exec|-e)\b/i,             type: 'reverse-shell', severity: 'HIGH', label: 'ncat-exec' },
  { re: /\bsocat\b[^\n]{0,120}EXEC:/i,           type: 'reverse-shell', severity: 'HIGH', label: 'socat-exec' },
  { re: /\bmkfifo\b[^\n]{0,120}\bnc\b/i,         type: 'reverse-shell', severity: 'HIGH', label: 'mkfifo-backpipe' },
  { re: /\bfsockopen\s*\(/i,                      type: 'reverse-shell', severity: 'HIGH', label: 'php-fsockopen' },
  { re: /Net\s*\.\s*Sockets\s*\.\s*TCPClient/i,  type: 'reverse-shell', severity: 'HIGH', label: 'powershell-tcpclient' },
  { re: /\bruby\s+-r\s*socket\b/i,               type: 'reverse-shell', severity: 'HIGH', label: 'ruby-socket' },
  { re: /\blua\s+-e\b[^\n]{0,120}os\s*\.\s*execute/i, type: 'reverse-shell', severity: 'HIGH', label: 'lua-socket' },
];

// Crypto-miner signal hints — any BLOCK_SIGNATURES hit containing one of these is labeled a
// crypto-miner (CRITICAL) rather than the generic dynamic-code-exec (HIGH). Previously only
// stratum/pool/nicehash/cryptonight were treated as crypto, so coinhive/xmr-stak/coin-hive and
// the brands above were mislabeled dynamic-code-exec. Cosmetic (both still block) but correct.
const CRYPTO_SIGNAL_HINTS = ['stratum', 'pool', 'nicehash', 'cryptonight', 'coinhive', 'coin-hive', 'xmr-stak', 'coinimp', 'jsecoin', 'webminepool', 'deepminer'];

// Indicative patterns common in legitimate code — emit WARN/OBSERVE only, never block.
// Also includes patterns (exec, eval) that are caught by the behavioral DYNAMIC_CODE_EXEC_CHAIN
// rule when used dangerously — so static-only matches on these produce WARN, not hard block.
const WARN_SIGNATURES = [
  'buffer.from',
  'atob(',
  'btoa(',
  'https.request',
  'http.request',
  'net.createconnection',
  'socket.connect',
  // Broad exec/eval literals — moved from BLOCK (F-20): appear in legitimate build tools
  // and test frameworks. Behavioral DYNAMIC_CODE_EXEC_CHAIN still hard-blocks the
  // dangerous eval+exec combination.
  'eval(',
  'child_process.exec',
  'execsync',
  // Legitimate capabilities that false-positive on lodash/axios/express — warn, don't block.
  'new function',
  'process.binding',
  // Legitimate capabilities in bundlers/process libs (esbuild, execa, cross-spawn, ws, undici) — F-26
  'child_process.spawn',
  'spawnsync',
  'vm.runinnewcontext',
  'vm.runinthiscontext',
  // Bare words that also match prose/comments — F-26
  'curl ',
  'wget ',
];

class Detector {
  constructor(/** @reserved - future policy integration */ policyEngine) {
    this.policyEngine = policyEngine;
    this.blockMatcher = new AhoCorasick(BLOCK_SIGNATURES);
    this.warnMatcher = new AhoCorasick(WARN_SIGNATURES);
    this.behaviorTracker = new BehaviorTracker();

    this.stats = {
      calls: 0,
      automatonScans: 0,
      behaviorViolations: 0,
      warnOnlyDetections: 0,
    };
  }

  async scanModule(packageName, moduleContent) {
    return this.scanModuleSync(packageName, moduleContent);
  }

  /**
   * Synchronous O(N) compilation screening combining signature matching and behavioral analysis.
   */
  scanModuleSync(packageName, moduleContent, filename, packageKey) {
    this.stats.calls++;

    if (!moduleContent || typeof moduleContent !== 'string') {
      return { action: 'OBSERVE', detections: [], packageName, scanTime: Date.now() };
    }

    // Full-content scan: Aho-Corasick is O(N) so scanning the entire module is safe.
    const searchContent = moduleContent;

    this.stats.automatonScans++;
    const detections = [];

    // BLOCK-tier: high-confidence malicious patterns — always quarantine on match
    const blockMatch = this.blockMatcher.searchInsensitive(searchContent);
    if (blockMatch) {
      const isCrypto = CRYPTO_SIGNAL_HINTS.some(h => blockMatch.includes(h));
      detections.push({
        type: isCrypto ? 'crypto-miner' : 'dynamic-code-exec',
        severity: isCrypto ? 'CRITICAL' : 'HIGH',
        matched: blockMatch,
        timestamp: Date.now(),
      });
    }

    // Regex-tier block signatures (anchored idioms that literals can't express safely).
    for (const { re, type, severity, label } of BLOCK_REGEXES) {
      if (re.test(searchContent)) {
        detections.push({ type, severity, matched: label, timestamp: Date.now() });
      }
    }

    // WARN-tier: common in benign code — log for visibility but never block on these alone
    const warnMatch = this.warnMatcher.searchInsensitive(searchContent);
    if (warnMatch) {
      this.stats.warnOnlyDetections++;
      detections.push({
        type: 'indicative-pattern',
        severity: 'WARN',
        matched: warnMatch,
        timestamp: Date.now(),
        warnOnly: true,
      });
    }

    // Behavioral sequence analysis on full content (skipped when FW_ENABLE_BEHAVIORAL=0)
    const behaviorEnabled = process.env.FW_ENABLE_BEHAVIORAL !== '0';
    const behaviorViolations = behaviorEnabled
      ? this.behaviorTracker.analyzeModule(filename || packageName, moduleContent, packageKey)
      : [];

    // Cross-file correlation, scoped to this file's package. OPT-IN (FW_ENABLE_CROSSFILE=1,
    // default OFF): soak validation showed it false-positives on large legitimate packages that
    // legitimately split capabilities across files — mongodb reads AWS credentials and hits the
    // instance-metadata endpoint (indistinguishable from exfil), babel/knex generate code in one
    // file and spawn processes in another. Static co-occurrence cannot separate these from a real
    // split attack; that needs Phase 3 taint analysis. Left available for curated dependency sets
    // and mirrored by the registry batch scanner's finalizePackage() (which applies human review).
    const crossFileEnabled = behaviorEnabled && process.env.FW_ENABLE_CROSSFILE === '1';
    if (crossFileEnabled && packageKey !== undefined && packageKey !== null) {
      for (const v of this.behaviorTracker.analyzePackage(packageKey)) {
        behaviorViolations.push(v);
      }
    }
    if (behaviorViolations.length > 0) {
      this.stats.behaviorViolations++;
      for (const v of behaviorViolations) {
        // CRITICAL/HIGH behavioral violations are block-tier — escalate to quarantine
        if (v.severity === 'CRITICAL' || v.severity === 'HIGH') {
          detections.push({
            type: 'behavioral',
            severity: v.severity,
            rule: v.rule,
            description: v.description,
            timestamp: Date.now(),
          });
        } else {
          // WARN/MEDIUM violations are surfaced for logging and telemetry but never trigger QUARANTINE
          detections.push({
            type: 'behavioral',
            severity: v.severity,
            rule: v.rule,
            description: v.description,
            timestamp: Date.now(),
            warnOnly: true,
          });
        }
      }
    }

    // Only escalate to QUARANTINE if at least one non-WARN detection exists
    const hasBlockDetection = detections.some(d => !d.warnOnly);
    const action = hasBlockDetection ? 'QUARANTINE' : 'OBSERVE';
    return { action, detections, packageName, scanTime: Date.now(), behaviorViolations };
  }

  /**
   * Batch cross-file finalizer. Call once after scanModuleSync() has run over every file in a
   * package (with reset() between packages). Used by the registry's whole-package scanner
   * (scan-registry.js / watch-changes.js); the runtime firewall does not need it because it runs
   * scoped cross-file inline in scanModuleSync(). With no packageKey, analyzePackage() correlates
   * the whole moduleSignals map — which, given the caller resets per package, is exactly one
   * package's files.
   */
  finalizePackage() {
    const violations = this.behaviorTracker.analyzePackage();
    if (violations.length > 0) {
      this.stats.behaviorViolations++;
    }
    return violations.map(v => ({
      type: 'behavioral',
      severity: v.severity,
      rule: v.rule,
      description: v.description,
      files: v.files,
      timestamp: Date.now(),
    }));
  }

  static isSuspicious(content) {
    return content && typeof content === 'string' && content.length > 0;
  }
}

module.exports = { Detector };
