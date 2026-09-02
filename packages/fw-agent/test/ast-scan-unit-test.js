const assert = require('assert');
const { AstScanner, tokenize, Parser, foldNode, resolveIdentity } = require('../src/ast-scan');

// ── Tokenizer ────────────────────────────────────────────────────────────────────────────────
{
  const toks = tokenize("const x = 'a\\u0062c' + 1;");
  assert.strictEqual(toks.find(t => t.type === 'string').value, 'abc');
  assert.ok(tokenize('/* comment */ const x = 1; // trailing').length > 0);
  // An unterminated string/template truncates the token stream rather than throwing — `src` is
  // usually a bounded span sliced out of a larger file, and the span's own character budget can
  // itself land mid-construct (see tokenize()'s doc comment); the tokens found before the cutoff
  // must still be usable.
  assert.deepStrictEqual(tokenize('const x = `unterminated').map(t => t.value), ['const', 'x', '=']);
  assert.deepStrictEqual(tokenize("const x = 'unterminated").map(t => t.value), ['const', 'x', '=']);
  console.log('tokenizer: ok');
}

// ── Parser ───────────────────────────────────────────────────────────────────────────────────
{
  const stmts = new Parser(tokenize("const fn = this['ev' + 'al']; fn('x');")).parseProgram();
  assert.strictEqual(stmts.length, 2);
  assert.strictEqual(stmts[0].type, 'VariableDeclaration');
  assert.strictEqual(stmts[1].type, 'ExpressionStatement');

  // Unmodeled statements (for/if/class/async function) are gracefully skipped, not fatal —
  // and recovery must not swallow the valid statement that follows one.
  const messy = new Parser(tokenize(
    "class Foo { bar() { return 1; } }\nfor (const x of [1]) { console.log(x); }\nconst fn = eval; fn('1');"
  )).parseProgram();
  assert.ok(messy.some(s => s.type === 'VariableDeclaration' && s.name === 'fn'),
    'a valid declaration following unmodeled statements must still be parsed, not consumed by error recovery');

  // A destructuring declarator (unsupported) must not swallow the next real statement either.
  const destructured = new Parser(tokenize(
    "const { a, b } = require('./config'); const fn = eval; fn('1');"
  )).parseProgram();
  assert.ok(destructured.some(s => s.type === 'VariableDeclaration' && s.name === 'fn'),
    'recovery from a destructuring declarator must not consume the following valid statement');

  console.log('parser: ok');
}

// ── Folder (whitelist-only constant evaluator) ──────────────────────────────────────────────
{
  const fold = (src) => {
    const stmts = new Parser(tokenize(src)).parseProgram();
    return foldNode(stmts[0].expression, new Map(), 0);
  };
  assert.strictEqual(fold("'ev' + 'al';"), 'eval');
  assert.strictEqual(fold("['ch', 'ild'].join('');"), 'child');
  assert.strictEqual(fold("String.fromCharCode(99,111,105,110,104,105,118,101);"), 'coinhive');
  assert.strictEqual(fold("')1(trela'.split('').reverse().join('');"), 'alert(1)');
  assert.strictEqual(fold("Buffer.from('68656c6c6f', 'hex').toString();"), 'hello');
  assert.strictEqual(fold("decodeURIComponent('%68%65%6c%6c%6f');"), 'hello');

  // Folding never guesses across a non-foldable operand — a fold involving anything outside the
  // whitelist (an unresolved identifier, a call not in the whitelist) must return null, never a
  // wrong or partial value.
  assert.strictEqual(fold("unknownVar + 'x';"), null);
  assert.strictEqual(fold("Math.random().toString();"), null);
  console.log('folder: ok');
}

// ── Structural identity resolution (direct vs. obfuscated) ─────────────────────────────────
{
  const resolve = (src, bindings) => {
    const stmts = new Parser(tokenize(src)).parseProgram();
    return resolveIdentity(stmts[0].expression, bindings || new Map());
  };
  // Bare `eval` and the already-recognized (0, eval) idiom are "direct" — already visible to and
  // handled by the existing text/regex engine, so this module must not escalate them on its own.
  assert.deepStrictEqual(resolve('eval;'), { name: 'eval', direct: true });
  assert.deepStrictEqual(resolve('(0, eval);'), { name: 'eval', direct: true });

  // Bracket-fold, alias, and constructor-chase resolutions are genuinely obfuscated.
  assert.strictEqual(resolve("this['ev' + 'al'];").direct, false);
  assert.strictEqual(resolve('(function(){}).constructor;').direct, false);
  const withAlias = new Map([['fn', { kind: 'identity', value: 'eval' }]]);
  assert.strictEqual(resolve('fn;', withAlias).direct, false);

  assert.strictEqual(resolve('x.constructor;'), null, 'an ordinary .constructor access on a plain identifier must not resolve to anything');
  console.log('resolveIdentity: ok');
}

// ── AstScanner.scan() end-to-end: closes the target red-team knownBypass entries ───────────
{
  const s = new AstScanner();

  const standaloneCases = {
    'bracket-eval': "const fn = this['ev' + 'al']; fn('process.exit(0)'); module.exports = {};",
    'alias-eval': "const fn = eval; fn('1+1'); module.exports = {};",
    'join-require': "const m = require(['ch', 'ild', '_pro', 'cess'].join('')); m.exec('id'); module.exports = {};",
    'unicode-escape-eval': "const g = global; g['\\u0065val']('process.exit(0)'); module.exports = {};",
    'constructor-constructor': "const F = (function(){}).constructor; F('return 1')(); module.exports = {};",
    'generatorfunction': "const GF = Object.getPrototypeOf(function*(){}).constructor; const g = GF('yield 1'); g().next(); module.exports = {};",
  };
  for (const [name, code] of Object.entries(standaloneCases)) {
    const r = s.scan(code, name + '.js');
    assert.ok(r.detections.length > 0, `${name}: expected a standalone obfuscated-dynamic-code detection`);
    assert.ok(r.detections.every(d => d.type === 'obfuscated-dynamic-code' && d.severity), `${name}: detection shape`);
  }

  const codeDecodeCases = {
    'eval-decodeuri': "eval(decodeURIComponent('%61%6c%65%72%74')); module.exports = {};",
    'indirect-eval-decodeuri': "(0, eval)(decodeURIComponent('%61%6c%65%72%74')); module.exports = {};",
    'fromcharcode-eval': "const s = String.fromCharCode(97,108,101,114,116); eval(s); module.exports = {};",
    'reverse-eval': "const s = 'trela'.split('').reverse().join(''); eval(s); module.exports = {};",
  };
  for (const [name, code] of Object.entries(codeDecodeCases)) {
    const r = s.scan(code, name + '.js');
    assert.ok(r.codeDecode.length > 0, `${name}: expected a codeDecode signal for the existing OBFUSCATED_CODE_EXECUTION correlation rule to consume`);
    assert.strictEqual(r.detections.length, 0, `${name}: must NOT standalone-detect (relies on existing dynamicCode+codeDecode correlation)`);
  }

  const literalCases = {
    'miner-charcode-coinhive': ["const brand = String.fromCharCode(99,111,105,110,104,105,118,101); module.exports = brand;", 'coinhive'],
    'miner-concat-cryptonight': ["const algo = 'crypto' + 'night'; module.exports = algo;", 'cryptonight'],
    'exfil-concat-etc-shadow': ["const p = '/etc/' + 'sha' + 'dow'; module.exports = p;", '/etc/shadow'],
    'miner-hex-pool': [
      `const h = '${Buffer.from('stratum+tcp://pool.example.com:3333').toString('hex')}'; const pool = Buffer.from(h.trim(), 'hex').toString(); module.exports = pool;`,
      'stratum+tcp://pool.example.com:3333',
    ],
  };
  for (const [name, [code, expected]] of Object.entries(literalCases)) {
    const r = s.scan(code, name + '.js');
    assert.ok(r.literals.some(l => l.value === expected), `${name}: expected folded literal "${expected}", got ${JSON.stringify(r.literals)}`);
  }

  console.log('AstScanner.scan() target bypasses: ok');
}

// ── Benign controls: legitimate uses of the same primitives must never standalone-detect ────
{
  const s = new AstScanner();
  const benignCases = {
    'constructor-typecheck': "function isFn(x) { return x && x.constructor === Function; } module.exports = isFn;",
    'literal-require-child-process': "const cp = require('child_process'); cp.exec('ls'); module.exports = {};",
    'fromcharcode-i18n': "const greeting = String.fromCharCode(72,101,108,108,111); module.exports = greeting;",
    'buffer-base64-decode': "const data = Buffer.from('aGVsbG8=', 'base64').toString(); module.exports = data;",
    'indirect-eval-alone': "(0, eval)('1 + 1'); module.exports = {};",
  };
  for (const [name, code] of Object.entries(benignCases)) {
    const r = s.scan(code, name + '.js');
    assert.strictEqual(r.detections.length, 0, `${name}: must not produce a standalone detection (would be a false positive)`);
  }
  console.log('AstScanner.scan() benign controls: ok');
}

// ── Safety invariants: scan() never throws, degrades gracefully ────────────────────────────
{
  const s = new AstScanner();
  const inputs = [
    null, undefined, '', 42, {},
    "const x = this['ev' + 'al' /* unterminated",
    'a'.repeat(50000) + "this['ev'+'al']",
    'x'.repeat(20) + '['.repeat(5000),
  ];
  for (const input of inputs) {
    assert.doesNotThrow(() => s.scan(input, 'garbage.js'), `scan() must never throw for input: ${String(input).slice(0, 40)}`);
  }
  console.log('safety invariants: ok');
}

// ── Tokenizer: escape sequences, numbers, regex literals, error paths ──────────────────────
{
  const tv = (src) => tokenize(src).map(t => t.value);
  assert.deepStrictEqual(tv("'\\x41\\x42'"), ['AB']);
  assert.deepStrictEqual(tv("'\\u{1F600}'"), [pristineStringOf(0x1f600)]);
  assert.deepStrictEqual(tv('0x1F'), [31]);
  assert.deepStrictEqual(tv('1e3'), [1000]);
  assert.deepStrictEqual(tv('1.5'), [1.5]);
  // A bad escape or unrecognized character truncates the token stream at that point rather than
  // throwing — deliberately: throwing would let an attacker plant one of these immediately AFTER
  // a real payload specifically to make the whole span fail and discard the payload's own tokens
  // along with it (see tokenize()'s doc comment). Preceding valid tokens (here, none) survive;
  // the malformed construct itself never produces a token.
  assert.deepStrictEqual(tokenize("'\\xZZ'"), []);
  assert.deepStrictEqual(tokenize("'\\u{ZZ}'"), []);
  assert.deepStrictEqual(tokenize("'\\uZZZZ'"), []);
  assert.deepStrictEqual(tokenize("'\\q'"), []);
  assert.deepStrictEqual(tokenize('@'), []);
  // But content BEFORE the malformed construct is preserved.
  assert.deepStrictEqual(tv("this['ev'+'al'](1); const bad = '\\q';").slice(0, 3), ['this', '[', 'ev']);

  // Regex-vs-divide: a leading regex literal (not preceded by a value-producing token) tokenizes
  // as one opaque 'regex' token; the parser treats it as a non-foldable Opaque primary.
  const regexToks = tokenize('/abc[\\/]/gi');
  assert.strictEqual(regexToks[0].type, 'regex');
  const stmts = new Parser(tokenize('x = /abc/;')).parseProgram();
  assert.ok(stmts.length >= 0); // must not throw — division-context '=' then a regex primary

  function pristineStringOf(cp) { return String.fromCodePoint(cp); }
  console.log('tokenizer edge cases: ok');
}

// ── Parser: ternary, new, arrow (block + expression body), object literal, unmodeled keywords ──
{
  const parseOne = (src) => new Parser(tokenize(src)).parseProgram()[0];
  assert.strictEqual(parseOne('a ? b : c;').expression.type, 'Opaque');
  assert.strictEqual(parseOne('new Foo.Bar(1, 2);').expression.type, 'NewExpression');
  assert.strictEqual(parseOne('const f = (a, b) => { return a + b; };').init.type, 'FunctionExpression');
  assert.strictEqual(parseOne('const f = x => x + 1;').init.type, 'FunctionExpression');
  assert.strictEqual(parseOne('const o = { a: 1, b: 2 };').init.type, 'Opaque');
  assert.strictEqual(parseOne('a?.b;').expression.type, 'MemberExpression');
  assert.strictEqual(parseOne('a?.();').expression.type, 'CallExpression');
  assert.strictEqual(parseOne('[1, , ...rest];').expression.type, 'ArrayExpression');
  assert.throws(() => new Parser(tokenize('class Foo {}')).parseStatement(), /unmodeled/);
  console.log('parser edge cases: ok');
}

// ── Folder: refuses non-whitelisted operations without guessing ────────────────────────────
{
  const fold = (src) => foldNode(new Parser(tokenize(src)).parseProgram()[0].expression, new Map(), 0);
  assert.strictEqual(fold("'a' - 'b';"), null, 'non-+ binary operators must never fold');
  assert.strictEqual(fold("'abc'.charCodeAt(0);"), null, 'a method outside the whitelist must not fold');
  assert.strictEqual(fold('[1, ...x].join(",");'), null, 'a spread element makes an array non-foldable');
  // Node's own Buffer.from('zz', 'hex') stops at the first invalid hex digit and yields zero
  // bytes rather than throwing — real, deterministic built-in behavior, not a guess this module
  // is making; folding just reports what the real primitive actually does.
  assert.strictEqual(fold("Buffer.from('zz', 'hex').toString();"), '');
  console.log('folder edge cases: ok');
}

// ── computeSpan / findCandidateSpans: boundary clamping and the per-file span cap ──────────
{
  const s = new AstScanner();
  // A hit at the very start of the file must not underflow the backward window.
  const nearStart = "this['ev'+'al'](1);" + ' '.repeat(50);
  assert.doesNotThrow(() => s.scan(nearStart, 'x.js'));
  // A hit at the very end of a large file must not overflow the forward window.
  const nearEnd = 'x'.repeat(5000) + "; const fn = this['ev'+'al']; fn(1);";
  const r = s.scan(nearEnd, 'x.js');
  assert.ok(r.detections.length > 0, 'a hit near EOF must still resolve within the clamped window');
  // More candidate hits than the per-tier span budget must not throw or hang, and still catch one
  // within the budget (see the F-91 span-exhaustion block below for the priority/incomplete gate).
  const many = "this['ev'+'al'](1);\n".repeat(60);
  assert.doesNotThrow(() => s.scan(many, 'x.js'));
  console.log('span boundary edge cases: ok');
}

// ── scan() fail-open paths: a single bad span, and the absolute internal backstop ──────────
{
  const s = new AstScanner();
  // A span that reaches tokenize() but contains a genuinely bad escape (not a truncation — see
  // tokenize()'s doc comment for why truncation itself no longer throws) must only drop that one
  // span, never the rest of the scan.
  const badEscape = "this['ev'+'al'](1); const bad = '\\q';";
  assert.doesNotThrow(() => s.scan(badEscape, 'x.js'));

  // A `//` line comment sitting inside the span-boundary scan region must be skipped correctly
  // (not miscounted as a `/` division punctuator toward bracket depth).
  const withLineComment = "// setup\nconst fn = this['ev' + 'al']; fn(1);";
  const r2 = s.scan(withLineComment, 'x.js');
  assert.ok(r2.detections.length > 0, 'a payload following a // line comment must still resolve');

  // Absolute backstop: even an internal failure inside prescreening must never escape scan().
  const broken = new AstScanner();
  broken._prescreener.searchInsensitive = () => { throw new Error('simulated internal failure'); };
  assert.doesNotThrow(() => broken.scan("this['ev'+'al'](1);", 'x.js'));

  console.log('scan() fail-open paths: ok');
}

// ── Further tokenizer/parser/folder branch coverage ─────────────────────────────────────────
{
  const tv = (src) => tokenize(src).map(t => t.value);
  // \u escape decoded INSIDE a bare identifier name (not a string key) — eval === eval.
  assert.deepStrictEqual(tv('\\u0065val'), ['eval']);
  // A literal newline before the closing quote truncates the string (never a real JS string).
  assert.deepStrictEqual(tv("'abc\ndef'"), []);
  // A fully valid, non-interpolated template literal tokenizes as a plain string.
  assert.deepStrictEqual(tv('`hello`'), ['hello']);
  assert.deepStrictEqual(tv('`a\\tb`'), ['a\tb']);
  // MAX_TOKENS_PER_SPAN bound: a token-dense span still fails closed, not silently unbounded.
  assert.throws(() => tokenize('1+'.repeat(2000)), /span too large/);

  const parseOne = (src) => new Parser(tokenize(src)).parseProgram()[0];
  assert.strictEqual(parseOne('a && b;').expression.type, 'BinaryExpression');
  assert.strictEqual(parseOne('!x;').expression.type, 'UnaryExpression');
  assert.strictEqual(parseOne('typeof x;').expression.type, 'UnaryExpression');
  assert.strictEqual(parseOne('(async function(){});').expression.type, 'FunctionExpression');
  assert.throws(() => new Parser(tokenize('1 + super;')).parseStatement(), /unmodeled keyword expression: super/);

  const fold = (src) => foldNode(new Parser(tokenize(src)).parseProgram()[0].expression, new Map(), 0);
  assert.strictEqual(fold('x.y;'), null, 'a bare (non-called) member access is not itself foldable');
  assert.strictEqual(fold('!x;'), null, 'a node type outside the fold switch falls to the default null case');
  assert.strictEqual(fold("'a,b'.split(',').trim();"), null, 'a non-join/reverse method on an array-typed receiver must not fold');

  console.log('further tokenizer/parser/folder branch coverage: ok');
}

// ── walkExpression: SequenceExpression/UnaryExpression/ArrayExpression/NewExpression recursion ──
{
  const s = new AstScanner();
  const r1 = s.scan('new Foo(String.fromCharCode(97,108,101,114,116));', 'x.js');
  assert.ok(r1.codeDecode.length > 0, 'walkExpression must recurse into NewExpression arguments');
  assert.doesNotThrow(() => s.scan("const x = [this['ev'+'al'], 1]; module.exports = x;", 'x.js'));
  assert.doesNotThrow(() => s.scan("void this['ev'+'al'];", 'x.js'));
  console.log('walkExpression recursion coverage: ok');
}

// ── F-91: span-exhaustion / decoy-flood bypass ─────────────────────────────────────────────────
// Regression guard for the span-exhaustion attack: before the fix, scan() processed candidate
// spans in FILE-POSITION order and hard-stopped after a fixed count, so an attacker could place a
// flood of harmless prescreen-matching decoy spans AHEAD of the real payload and the payload span
// was never parsed. The fix scans HIGHEST-RISK-FIRST with a tiered budget, so a real payload is
// reached regardless of how many low-risk decoys precede it — and if a genuinely high-risk span is
// ever left unanalyzed, scan() must report result.incomplete rather than a clean partial scan.
{
  const s = new AstScanner();
  const filler = 'x'.repeat(2100); // > MAX_SPAN_CHARS so each decoy is its own distinct span
  // Low-risk decoy: String.fromCharCode is a real decode-primitive prescreen hit, but harmless.
  const decoyLines = Array.from({ length: 45 }, (_, i) => `const benign${i} = String.fromCharCode(65);${filler};`);
  // A bracket+concat obfuscated eval — no literal "eval(" call site; only the AST tier sees it.
  const payload = "\nconst run = this['ev' + 'al'];\nrun('1+1');\n";
  const caught = (r) => r.detections.some(d => d.matched === 'ast-resolved-eval-access');

  const atFront = s.scan(decoyLines.join('\n') + payload, 'front.js');
  assert.ok(caught(atFront), 'payload after a 45-decoy flood (>40) must still be caught (decoys at FRONT)');
  assert.strictEqual(atFront.incomplete, false, 'a low-risk decoy flood must not be reported as an incomplete scan');

  const atMiddle = s.scan(decoyLines.slice(0, 22).join('\n') + payload + '\n' + decoyLines.slice(22).join('\n'), 'middle.js');
  assert.ok(caught(atMiddle), 'payload in the MIDDLE of a decoy flood must still be caught');

  const atEnd = s.scan(payload + '\n' + decoyLines.join('\n'), 'end.js');
  assert.ok(caught(atEnd), 'payload before a trailing decoy flood must still be caught');

  // A large flood of BENIGN low-risk noise (require()/(0,) — pervasive in real bundles) must
  // neither detect nor be flagged incomplete: no false positive on ordinary large bundled code.
  const benignBundle = Array.from({ length: 300 }, (_, i) => `const a${i} = (0, require)('m${i}');${filler}`).join('\n');
  const bundleScan = s.scan(benignBundle, 'bundle.js');
  assert.strictEqual(bundleScan.detections.length, 0, 'benign low-risk bundle noise must not produce detections');
  assert.strictEqual(bundleScan.incomplete, false, 'benign low-risk bundle noise must not trip the incomplete gate');

  // A flood of HIGH-RISK spans exceeding the high-risk budget must set result.incomplete, so a
  // payload that an attacker buries among engineered high-risk decoys can never slip past silently:
  // either it is scanned (detected) or the module is flagged incomplete.
  const hiRiskDecoys = Array.from({ length: 300 }, (_, i) => `const z${i} = obj['xx' + 'yy'];${filler}`).join('\n');
  const flood = s.scan(hiRiskDecoys + payload, 'flood.js');
  assert.ok(flood.incomplete, 'a high-risk span flood that exceeds the budget must be reported incomplete');
  assert.ok(caught(flood) || flood.incomplete, 'buried payload is either scanned or the module is flagged incomplete');

  console.log('F-91 span-exhaustion / decoy-flood: ok');
}

console.log('AST scan unit test passed.');
