// packages/fw-agent/src/ast-scan.js
// Phase 3: narrow, hand-rolled AST-level obfuscation detection.
//
// This is NOT a general-purpose JavaScript parser. It understands only the slice of ECMAScript
// expression/declaration grammar needed to see through the specific obfuscation idioms the
// red-team corpus documents as `knownBypass: true` (bracket/alias/unicode-escape eval,
// constructor-chase sandbox escapes, decode-primitive chains, string-literal reassembly). Every
// construct outside that grammar simply fails to parse for the affected span — the caller
// (AstScanner.scan) treats that as "no additional signal from here," never as an error condition
// that propagates. The existing text-based scanners (aho-corasick signatures, behavioral regex
// correlation) always run over the full raw source regardless of what this module does, so a gap
// or bug here can only ever reduce how much MORE this module sees — it cannot make the agent see
// less than it already does today, and it never blocks anything by itself outside the narrow,
// intentional exception in `detectStandaloneObfuscation` below.
//
// Zero runtime dependencies: no parser library. See docs/THREAT-COVERAGE.md and SECURITY.md for
// why (aletheia-firewall ships zero npm dependencies by design).
'use strict';

// ── Pristine primitive capture ──────────────────────────────────────────────────────────────────
// Same discipline as index.js's pristineCreateHash (F-62) and the canonicalPayload() lessons
// (F-80/F-83/F-84): this module's own constant-folder calls a small whitelist of real, built-in
// string/decode primitives to resolve literal values (e.g. actually calling String.fromCharCode
// on literal numeric args rather than reimplementing it). If allowed code running earlier in the
// process could monkeypatch those globals, a folded value could be spoofed. Captured at module
// load, before any later-loaded code has run.
const pristineStringFromCharCode = String.fromCharCode;
const pristineStringPrototype = {
  split: String.prototype.split,
  reverse: Array.prototype.reverse,
  join: Array.prototype.join,
  trim: String.prototype.trim,
  slice: String.prototype.slice,
  substring: String.prototype.substring,
  toUpperCase: String.prototype.toUpperCase,
  toLowerCase: String.prototype.toLowerCase,
  repeat: String.prototype.repeat,
  concat: String.prototype.concat,
  charAt: String.prototype.charAt,
};
const pristineBufferFrom = typeof Buffer !== 'undefined' ? Buffer.from : null;
const pristineBufferToString = typeof Buffer !== 'undefined' ? Buffer.prototype.toString : null;
const pristineDecodeURIComponent = decodeURIComponent;
const pristineUnescape = unescape;

// ── Bounds (mirrors the fixed-backstop discipline behavior-tracker.js already established for
// CORRELATION_MAX_SEPARATORS/CORRELATION_MAX_CHARS — every hand-rolled analyzer in this codebase
// bounds its own cost with a fixed, documented ceiling rather than an adaptive one) ─────────────
const MAX_SPANS_PER_FILE = 40;
const MAX_SPAN_CHARS = 2000;
const MAX_TOKENS_PER_SPAN = 1200;
const MAX_FOLD_DEPTH = 24;
const MAX_PARSE_DEPTH = 60;

class AstUnsupported extends Error {}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Tokenizer
// ══════════════════════════════════════════════════════════════════════════════════════════════

const PUNCTUATORS_3 = ['===', '!==', '...', '**='];
const PUNCTUATORS_2 = ['=>', '?.', '??', '==', '!=', '<=', '>=', '&&', '||', '++', '--'];
const KEYWORDS = new Set([
  'const', 'let', 'var', 'function', 'class', 'new', 'typeof', 'void', 'delete', 'return',
  'if', 'else', 'for', 'while', 'do', 'try', 'catch', 'finally', 'switch', 'case', 'break',
  'continue', 'throw', 'in', 'of', 'instanceof', 'async', 'await', 'yield', 'this', 'super',
  'true', 'false', 'null', 'undefined',
]);

function isIdStart(c) {
  return c === 95 /* _ */ || c === 36 /* $ */ || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c > 127;
}
function isIdPart(c) {
  return isIdStart(c) || (c >= 48 && c <= 57);
}
function isDigit(c) {
  return c >= 48 && c <= 57;
}

// Decodes \n \t \r \\ \' \" \` \0 \xHH \uHHHH \u{H...H} and line continuations. Used for both
// string literals and identifier unicode escapes (g['eval'] and eval as bare identifier
// text resolve to the same decoded character either way).
function decodeEscape(src, i) {
  // src[i] === '\\'; returns { char, next }
  const c = src[i + 1];
  switch (c) {
    case 'n': return { char: '\n', next: i + 2 };
    case 't': return { char: '\t', next: i + 2 };
    case 'r': return { char: '\r', next: i + 2 };
    case 'b': return { char: '\b', next: i + 2 };
    case 'f': return { char: '\f', next: i + 2 };
    case 'v': return { char: '\v', next: i + 2 };
    case '0': return { char: '\0', next: i + 2 };
    case '\\': case '\'': case '"': case '`': return { char: c, next: i + 2 };
    case '\n': return { char: '', next: i + 2 }; // line continuation
    case 'x': {
      const hex = src.slice(i + 2, i + 4);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new AstUnsupported('bad \\x escape');
      return { char: String.fromCharCode(parseInt(hex, 16)), next: i + 4 };
    }
    case 'u': {
      if (src[i + 2] === '{') {
        const end = src.indexOf('}', i + 3);
        if (end === -1) throw new AstUnsupported('bad \\u{} escape');
        const hex = src.slice(i + 3, end);
        if (!/^[0-9a-fA-F]+$/.test(hex)) throw new AstUnsupported('bad \\u{} escape');
        return { char: pristineStringFromCharCode(...codePointToUnits(parseInt(hex, 16))), next: end + 1 };
      }
      const hex = src.slice(i + 2, i + 6);
      if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new AstUnsupported('bad \\u escape');
      return { char: String.fromCharCode(parseInt(hex, 16)), next: i + 6 };
    }
    default:
      throw new AstUnsupported('unsupported escape');
  }
}

function codePointToUnits(cp) {
  if (cp <= 0xffff) return [cp];
  const c = cp - 0x10000;
  return [0xd800 + (c >> 10), 0xdc00 + (c & 0x3ff)];
}

// Tokenizes `src`, returning whatever tokens were found. An unterminated string/template/block
// comment stops tokenizing at that point rather than throwing — deliberately, because `src` here
// is usually a bounded SPAN sliced out of a larger file (see findCandidateSpans/computeSpan), and
// slicing can itself land the span boundary mid-construct (concretely: a long trailing run of
// benign padding comments, truncated by the span's own MAX_SPAN_CHARS budget, produces exactly
// this). Throwing for the whole span in that case would discard a perfectly valid, fully-parsed
// payload at the FRONT of the span purely because of where our own windowing cut it off at the
// back. Returning the prefix instead costs nothing (parseProgram() below already copes with a
// trailing partial/empty statement) and can only ever recover more signal, never fewer — an
// actually malformed span still fails downstream in the parser as before.
function tokenize(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;
  let prevType = null; // for regex-vs-divide disambiguation
  scan: while (i < n) {
    const c = src.charCodeAt(i);

    if (c === 32 || c === 9 || c === 13 || c === 10) { i++; continue; }

    // Comments
    if (c === 47 /* / */ && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      i = nl === -1 ? n : nl;
      continue;
    }
    if (c === 47 && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end === -1) break scan; // truncated trailing comment — see function-level comment
      i = end + 2;
      continue;
    }

    const start = i;

    // Identifiers (incl. \uXXXX escapes inside identifier names). A malformed \u escape, or a
    // bare '\' that never resolves to a real identifier character, stops tokenizing here rather
    // than throwing — same reasoning as the unterminated-construct cases in tokenize()'s doc
    // comment, and not merely a truncation concern: an attacker who knows this module exists
    // could otherwise plant a deliberately malformed escape immediately AFTER a real payload
    // specifically to make the whole span throw and discard everything, payload included. A
    // syntax error can only cost content at and after itself now, never content before it.
    if (isIdStart(c) || (c === 92 /* \ */ && src[i + 1] === 'u')) {
      let name = '';
      while (i < n) {
        const cc = src.charCodeAt(i);
        if (cc === 92 && src[i + 1] === 'u') {
          let dec;
          try { dec = decodeEscape(src, i); } catch (e) { break scan; }
          name += dec.char;
          i = dec.next;
        } else if (isIdPart(cc)) {
          name += src[i];
          i++;
        } else {
          break;
        }
      }
      if (name.length === 0) break scan;
      tokens.push({ type: KEYWORDS.has(name) ? 'keyword' : 'identifier', value: name, start, end: i });
      prevType = 'identifier';
      continue;
    }

    // Numbers (decimal, hex, octal, binary — value only needs to be numerically correct for
    // fromCharCode-style folding; underscores/bigint suffix tolerated but not evaluated specially)
    if (isDigit(c) || (c === 46 /* . */ && isDigit(src.charCodeAt(i + 1)))) {
      let text = '';
      if (c === 48 && (src[i + 1] === 'x' || src[i + 1] === 'X')) {
        text = src[i] + src[i + 1]; i += 2;
        while (i < n && /[0-9a-fA-F_]/.test(src[i])) { text += src[i]; i++; }
        tokens.push({ type: 'number', value: parseInt(text.replace(/_/g, ''), 16), start, end: i });
      } else {
        while (i < n && /[0-9_]/.test(src[i])) { text += src[i]; i++; }
        if (src[i] === '.') { text += src[i]; i++; while (i < n && /[0-9_]/.test(src[i])) { text += src[i]; i++; } }
        if (src[i] === 'e' || src[i] === 'E') {
          text += src[i]; i++;
          if (src[i] === '+' || src[i] === '-') { text += src[i]; i++; }
          while (i < n && isDigit(src.charCodeAt(i))) { text += src[i]; i++; }
        }
        if (src[i] === 'n') i++; // bigint suffix, ignored
        tokens.push({ type: 'number', value: parseFloat(text.replace(/_/g, '')), start, end: i });
      }
      prevType = 'number';
      continue;
    }

    // Strings
    if (c === 39 /* ' */ || c === 34 /* " */) {
      const quote = src[i];
      let value = '';
      i++;
      while (i < n && src[i] !== quote) {
        if (src[i] === '\\') {
          let dec;
          try { dec = decodeEscape(src, i); } catch (e) { break scan; }
          value += dec.char;
          i = dec.next;
        } else if (src[i] === '\n') {
          break scan; // unterminated string — truncate here, see tokenize()'s doc comment
        } else {
          value += src[i];
          i++;
        }
      }
      if (i >= n) break scan; // unterminated string (ran off the end of the span)
      i++; // closing quote
      tokens.push({ type: 'string', value, start, end: i });
      prevType = 'string';
      continue;
    }

    // Template literals — only plain (no `${`) templates are supported; anything with
    // interpolation is opaque (not needed for the target bypass grammar, and correctly parsing
    // nested expressions inside `${...}` would roughly double this file's size for no bypass this
    // phase closes).
    if (c === 96 /* ` */) {
      let value = '';
      i++;
      while (i < n && src[i] !== '`') {
        if (src[i] === '\\') {
          let dec;
          try { dec = decodeEscape(src, i); } catch (e) { break scan; }
          value += dec.char;
          i = dec.next;
        } else if (src[i] === '$' && src[i + 1] === '{') {
          break scan; // template interpolation unsupported — see tokenize()'s doc comment
        } else {
          value += src[i];
          i++;
        }
      }
      if (i >= n) break scan; // unterminated template — truncate here, see tokenize()'s doc comment
      i++;
      tokens.push({ type: 'string', value, start, end: i });
      prevType = 'string';
      continue;
    }

    // Regex-vs-divide: a '/' after a value-producing token (identifier/number/string/`)`/`]`) is
    // division; otherwise attempt a conservative regex-literal scan. On any ambiguity, bail for
    // the whole span rather than guess wrong — a mis-tokenized regex can desync every subsequent
    // token boundary.
    if (c === 47 /* / */) {
      const divideContext = prevType === 'identifier' || prevType === 'number' ||
        prevType === 'string' || prevType === 'punct-close';
      if (!divideContext) {
        let j = i + 1;
        let inClass = false;
        while (j < n) {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '[') inClass = true;
          else if (src[j] === ']') inClass = false;
          else if (src[j] === '/' && !inClass) break;
          else if (src[j] === '\n') break scan; // unterminated regex — see tokenize()'s doc comment
          j++;
        }
        if (j >= n) break scan; // unterminated regex (ran off the end of the span)
        j++; // closing /
        while (j < n && /[a-z]/i.test(src[j])) j++; // flags
        tokens.push({ type: 'regex', value: src.slice(start, j), start, end: j });
        i = j;
        prevType = 'regex';
        continue;
      }
    }

    // Punctuators
    const three = src.slice(i, i + 3);
    const two = src.slice(i, i + 2);
    if (PUNCTUATORS_3.includes(three)) {
      tokens.push({ type: 'punct', value: three, start, end: i + 3 });
      i += 3;
    } else if (PUNCTUATORS_2.includes(two)) {
      tokens.push({ type: 'punct', value: two, start, end: i + 2 });
      i += 2;
    } else if ('(){}[],.;:+-*/%!~<>=?&|^'.includes(src[i])) {
      tokens.push({ type: 'punct', value: src[i], start, end: i + 1 });
      i++;
    } else {
      break scan; // unrecognized character — see tokenize()'s doc comment
    }
    prevType = (tokens[tokens.length - 1].value === ')' || tokens[tokens.length - 1].value === ']')
      ? 'punct-close' : 'punct';

    if (tokens.length > MAX_TOKENS_PER_SPAN) throw new AstUnsupported('span too large');
  }
  return tokens;
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Parser — expressions, plus single-declarator const/let/var. Everything else (loops, classes,
// destructuring, control flow) is deliberately out of grammar; parseStatement() skips over
// constructs it doesn't recognize rather than failing the whole span (see parseStatement).
// ══════════════════════════════════════════════════════════════════════════════════════════════

class Parser {
  constructor(tokens) {
    this.toks = tokens;
    this.pos = 0;
    this.depth = 0;
  }

  peek(offset) { return this.toks[this.pos + (offset || 0)]; }
  at(value) { const t = this.peek(); return t && (t.value === value); }
  atType(type) { const t = this.peek(); return t && t.type === type; }
  next() {
    const t = this.toks[this.pos];
    if (!t) throw new AstUnsupported('unexpected end of input');
    this.pos++;
    return t;
  }
  expect(value) {
    const t = this.next();
    if (t.value !== value) throw new AstUnsupported(`expected '${value}', got '${t.value}'`);
    return t;
  }
  guardDepth() {
    if (++this.depth > MAX_PARSE_DEPTH) throw new AstUnsupported('expression too deep');
  }

  parseProgram() {
    const statements = [];
    while (this.pos < this.toks.length) {
      const before = this.pos;
      try {
        statements.push(this.parseStatement());
      } catch (e) {
        if (!(e instanceof AstUnsupported)) throw e;
        // ALWAYS restart the recovery skip from the failed statement's own start (`before`), even
        // though parseStatement may have already partially consumed tokens (e.g. a destructuring
        // declarator consumes 'const' and '{' before throwing on the pattern). Recovering from
        // wherever the partial parse happened to stop is unsound: skipToStatementBoundary's
        // own depth counter would start unaware of brackets already consumed, and worse, once a
        // botched statement leaves behind orphaned trailing tokens (e.g. the `= require(...);`
        // remnant after a destructuring pattern fails), EACH of those throws its own recovery
        // call — and the LAST one can land exactly at the start of the NEXT, perfectly valid
        // statement and silently swallow it whole via the bare-semicolon fallback, since that
        // fallback can't distinguish "mid-recovery from garbage" from "sitting at a clean
        // statement start". Restarting every skip from the untouched original position keeps
        // each recovery bounded to the ONE statement that actually failed.
        this.pos = before;
        this.skipToStatementBoundary();
      }
    }
    return statements;
  }

  // Skips exactly the unparseable construct starting at the current position — no further. Must
  // stop the INSTANT bracket depth returns to 0 after having gone positive (the construct's own
  // close), not merely at the next depth-0 semicolon: for a bodyless `for (...)`/`if (...)` the
  // paren depth returns to 0 well before that statement's own trailing `;`, and continuing to
  // scan for a semicolon would run straight through the NEXT, perfectly-parseable statement and
  // silently discard it — including, concretely, an obfuscation payload that happens to follow an
  // unrelated `for`/`if`/`class`/`async function` elsewhere in the same file. Only a depth-0 `;`
  // seen BEFORE ever going positive (a bare stray semicolon, or a keyword statement with no
  // parens/braces at all, e.g. `continue;`) still uses the semicolon fallback. Token `.value` is
  // compared only for punctuator-typed tokens — a string literal whose decoded content happens to
  // equal a bracket character must never be mistaken for one.
  skipToStatementBoundary() {
    let depth = 0;
    let wentPositive = false;
    while (this.pos < this.toks.length) {
      const t = this.toks[this.pos];
      if (t.type === 'punct') {
        if (t.value === '{' || t.value === '(' || t.value === '[') {
          depth++; wentPositive = true;
        } else if (t.value === '}' || t.value === ')' || t.value === ']') {
          if (depth === 0) { this.pos++; return; } // unmatched closer: belongs to an outer scope
          depth--;
          if (depth === 0 && wentPositive) { this.pos++; return; }
        } else if (t.value === ';' && depth === 0) {
          this.pos++;
          return;
        }
      }
      this.pos++;
    }
  }

  parseStatement() {
    const t = this.peek();
    if (!t) throw new AstUnsupported('eof');
    if (t.type === 'keyword' && (t.value === 'const' || t.value === 'let' || t.value === 'var')) {
      return this.parseVariableDeclaration();
    }
    // Anything else that opens with a statement keyword we don't model (function/class/if/for/
    // etc.) is out of grammar — treat as an opaque statement to skip, NOT a parse error, so the
    // caller keeps analyzing the rest of the span.
    if (t.type === 'keyword' && t.value !== 'this' && t.value !== 'true' && t.value !== 'false' &&
        t.value !== 'null' && t.value !== 'undefined' && t.value !== 'typeof' && t.value !== 'void' &&
        t.value !== 'delete' && t.value !== 'new' && t.value !== 'async') {
      throw new AstUnsupported('unmodeled statement keyword: ' + t.value);
    }
    const expr = this.parseSequence();
    if (this.at(';')) this.next();
    return { type: 'ExpressionStatement', expression: expr };
  }

  parseVariableDeclaration() {
    const kind = this.next().value;
    const nameTok = this.next();
    if (nameTok.type !== 'identifier') throw new AstUnsupported('destructuring pattern unsupported');
    let init = null;
    if (this.at('=')) {
      this.next();
      init = this.parseAssignLevel();
    }
    if (this.at(',')) throw new AstUnsupported('multi-declarator unsupported');
    if (this.at(';')) this.next();
    return { type: 'VariableDeclaration', kind, name: nameTok.value, init };
  }

  // No real AssignmentExpression support needed (only declarator inits use this level) — this is
  // just "sequence-or-below", named for clarity at the call site.
  parseAssignLevel() { return this.parseConditional(); }

  parseSequence() {
    let expr = this.parseAssignLevel();
    if (this.at(',')) {
      const expressions = [expr];
      while (this.at(',')) { this.next(); expressions.push(this.parseAssignLevel()); }
      expr = { type: 'SequenceExpression', expressions };
    }
    return expr;
  }

  parseConditional() {
    const test = this.parseNullish();
    if (this.at('?')) {
      this.next();
      this.parseAssignLevel(); // consequent, discarded — ternaries aren't foldable/structural targets
      this.expect(':');
      this.parseAssignLevel(); // alternate, discarded
      return { type: 'Opaque' };
    }
    return test;
  }

  parseNullish() { return this.parseBinaryLevel(['??', '||', '&&', '===', '!==', '==', '!=', '<=', '>=', '<', '>', 'instanceof', 'in', '|', '^', '&', '<<', '>>', '>>>', '*', '/', '%', '-'].concat([]), 0); }

  // Single precedence-agnostic left-associative binary climber. We don't need real ECMAScript
  // precedence for correctness here (folding only ever cares about '+', everything else is
  // parsed-through opaquely) — a flat left-to-right chain still parses valid input without
  // erroring, which is all the caller needs from operators the folder will refuse to fold anyway.
  parseBinaryLevel(ops) {
    this.guardDepth();
    let left = this.parseAdditive();
    while (this.peek() && ops.includes(this.peek().value)) {
      const op = this.next().value;
      const right = this.parseAdditive();
      left = { type: 'BinaryExpression', operator: op, left, right };
    }
    this.depth--;
    return left;
  }

  parseAdditive() {
    this.guardDepth();
    let left = this.parseUnary();
    while (this.at('+') || this.at('-')) {
      const op = this.next().value;
      const right = this.parseUnary();
      left = { type: 'BinaryExpression', operator: op, left, right };
    }
    this.depth--;
    return left;
  }

  parseUnary() {
    const t = this.peek();
    if (t && (t.value === '!' || t.value === '-' || t.value === '+' || t.value === '~' ||
        t.value === 'typeof' || t.value === 'void' || t.value === 'delete')) {
      this.next();
      const argument = this.parseUnary();
      return { type: 'UnaryExpression', operator: t.value, argument };
    }
    return this.parsePostfix();
  }

  parsePostfix() {
    this.guardDepth();
    let expr = this.parsePrimary();
    for (;;) {
      if (this.at('.')) {
        this.next();
        const prop = this.next();
        if (prop.type !== 'identifier' && prop.type !== 'keyword') throw new AstUnsupported('bad member access');
        expr = { type: 'MemberExpression', object: expr, property: { type: 'Identifier', name: prop.value }, computed: false };
      } else if (this.at('?.')) {
        this.next();
        if (this.at('(')) {
          expr = this.finishCall(expr);
        } else {
          const prop = this.next();
          if (prop.type !== 'identifier' && prop.type !== 'keyword') throw new AstUnsupported('bad optional member access');
          expr = { type: 'MemberExpression', object: expr, property: { type: 'Identifier', name: prop.value }, computed: false };
        }
      } else if (this.at('[')) {
        this.next();
        const property = this.parseSequence();
        this.expect(']');
        expr = { type: 'MemberExpression', object: expr, property, computed: true };
      } else if (this.at('(')) {
        expr = this.finishCall(expr);
      } else {
        break;
      }
    }
    this.depth--;
    return expr;
  }

  finishCall(callee) {
    this.expect('(');
    const args = [];
    while (!this.at(')')) {
      if (this.at('...')) { this.next(); this.parseAssignLevel(); args.push({ type: 'Opaque' }); }
      else args.push(this.parseAssignLevel());
      if (this.at(',')) this.next();
      else break;
    }
    this.expect(')');
    return { type: 'CallExpression', callee, arguments: args };
  }

  parsePrimary() {
    const t = this.peek();
    if (!t) throw new AstUnsupported('unexpected end of input');

    if (t.type === 'string') { this.next(); return { type: 'Literal', value: t.value }; }
    if (t.type === 'number') { this.next(); return { type: 'Literal', value: t.value }; }
    if (t.type === 'regex') { this.next(); return { type: 'Opaque' }; }

    if (t.value === '(') {
      this.next();
      const inner = this.parseSequence();
      this.expect(')');
      if (this.at('=>')) { this.next(); return this.skipArrowBody(); }
      return inner;
    }

    if (t.value === '[') {
      this.next();
      const elements = [];
      while (!this.at(']')) {
        if (this.at(',')) { this.next(); elements.push(null); continue; }
        if (this.at('...')) { this.next(); this.parseAssignLevel(); elements.push({ type: 'Opaque' }); }
        else elements.push(this.parseAssignLevel());
        if (this.at(',')) this.next();
        else break;
      }
      this.expect(']');
      return { type: 'ArrayExpression', elements };
    }

    if (t.value === '{') { return this.skipObjectLiteral(); }

    if (t.type === 'keyword' && t.value === 'function') return this.skipFunctionExpression();
    if (t.type === 'keyword' && t.value === 'async' && this.peek(1) && this.peek(1).value === 'function') {
      this.next(); return this.skipFunctionExpression();
    }
    if (t.type === 'keyword' && t.value === 'new') {
      this.next();
      const callee = this.parsePostfixNoCall();
      let args = [];
      if (this.at('(')) { const call = this.finishCall(callee); args = call.arguments; }
      return { type: 'NewExpression', callee, arguments: args };
    }
    if (t.type === 'keyword' && (t.value === 'class' || t.value === 'yield' || t.value === 'await' || t.value === 'super')) {
      throw new AstUnsupported('unmodeled keyword expression: ' + t.value);
    }
    if (t.type === 'keyword' && (t.value === 'true' || t.value === 'false' || t.value === 'null' || t.value === 'undefined' || t.value === 'this')) {
      this.next();
      return { type: 'Identifier', name: t.value };
    }

    if (t.type === 'identifier' || t.type === 'keyword') {
      this.next();
      if (this.at('=>')) { this.next(); return this.skipArrowBody(); }
      return { type: 'Identifier', name: t.value };
    }

    throw new AstUnsupported('unexpected token: ' + t.value);
  }

  // `new Foo.Bar` callee resolution shouldn't itself consume the call parens (finishCall does
  // that separately above) — a member chain only, no call.
  parsePostfixNoCall() {
    let expr = this.parsePrimaryNoCallForNew();
    while (this.at('.')) {
      this.next();
      const prop = this.next();
      if (prop.type !== 'identifier' && prop.type !== 'keyword') throw new AstUnsupported('bad member access');
      expr = { type: 'MemberExpression', object: expr, property: { type: 'Identifier', name: prop.value }, computed: false };
    }
    return expr;
  }
  parsePrimaryNoCallForNew() {
    const t = this.next();
    if (t.type !== 'identifier' && t.type !== 'keyword') throw new AstUnsupported('bad new-expression callee');
    return { type: 'Identifier', name: t.value };
  }

  skipArrowBody() {
    if (this.at('{')) { this.skipBalanced('{', '}'); } else { this.parseAssignLevel(); }
    return { type: 'FunctionExpression', generator: false, opaque: true };
  }

  skipFunctionExpression() {
    this.next(); // 'function'
    const generator = this.at('*');
    if (generator) this.next();
    if (this.atType('identifier')) this.next(); // optional name
    this.expect('(');
    this.skipBalancedFrom('(', ')', 1);
    this.expect('{');
    this.skipBalancedFrom('{', '}', 1);
    return { type: 'FunctionExpression', generator, opaque: true };
  }

  skipObjectLiteral() {
    this.expect('{');
    this.skipBalancedFrom('{', '}', 1);
    return { type: 'Opaque' };
  }

  // Consumes tokens until the matching close for a bracket we've already consumed the open of
  // (openDepth counts the already-consumed opener).
  skipBalancedFrom(openCh, closeCh, openDepth) {
    let depth = openDepth;
    while (depth > 0) {
      const t = this.next();
      if (t.value === openCh) depth++;
      else if (t.value === closeCh) depth--;
    }
  }
  skipBalanced(openCh, closeCh) {
    this.expect(openCh);
    this.skipBalancedFrom(openCh, closeCh, 1);
  }
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Folder — whitelist-only constant evaluator. Returns a string, or null if any part of the
// expression isn't in the whitelist. Never partial-guesses: a single non-foldable operand fails
// the whole fold, which can only omit a signal, never fabricate a wrong one.
// ══════════════════════════════════════════════════════════════════════════════════════════════

// Pure String.prototype methods safe to invoke on an already-fully-resolved literal string. Each
// is a real, deterministic, side-effect-free built-in — never eval/Function, never anything that
// can itself execute attacker-authored code.
const FOLDABLE_STRING_METHODS = new Set(['trim', 'toUpperCase', 'toLowerCase', 'charAt', 'slice', 'substring', 'repeat', 'concat', 'split', 'reverse', 'join']);

function foldNode(node, bindings, depth) {
  if (depth > MAX_FOLD_DEPTH) return null;
  if (!node) return null;
  switch (node.type) {
    case 'Literal':
      return typeof node.value === 'string' ? node.value : String(node.value);
    case 'Identifier': {
      const b = bindings.get(node.name);
      return b && b.kind === 'literal' ? b.value : null;
    }
    case 'ArrayExpression': {
      const vals = [];
      for (const el of node.elements) {
        if (el === null || el.type === 'Opaque') return null;
        const v = foldNode(el, bindings, depth + 1);
        if (v === null) return null;
        vals.push(v);
      }
      return { __array: vals }; // only meaningful as a receiver for .join(); not itself a string
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return null;
      const l = foldNode(node.left, bindings, depth + 1);
      const r = foldNode(node.right, bindings, depth + 1);
      if (typeof l !== 'string' || typeof r !== 'string') return null;
      return l + r;
    }
    case 'CallExpression':
      return foldCall(node, bindings, depth);
    case 'MemberExpression': {
      // A bare (non-called) member access can still be a foldable value only via the special
      // call-based primitives handled in foldCall; on its own it resolves to nothing textual.
      return null;
    }
    default:
      return null;
  }
}

function foldCall(node, bindings, depth) {
  const callee = node.callee;

  // String.fromCharCode(<all-literal-numeric-args>)
  if (callee.type === 'MemberExpression' && !callee.computed &&
      callee.property.name === 'fromCharCode' &&
      callee.object.type === 'Identifier' && callee.object.name === 'String') {
    const codes = [];
    for (const a of node.arguments) {
      if (a.type !== 'Literal' || typeof a.value !== 'number') return null;
      codes.push(a.value);
    }
    try { return pristineStringFromCharCode(...codes); } catch (e) { return null; }
  }

  // decodeURIComponent(<foldable>) / unescape(<foldable>)
  if (callee.type === 'Identifier' && (callee.name === 'decodeURIComponent' || callee.name === 'unescape')) {
    if (node.arguments.length !== 1) return null;
    const arg = foldNode(node.arguments[0], bindings, depth + 1);
    if (typeof arg !== 'string') return null;
    try {
      return callee.name === 'decodeURIComponent' ? pristineDecodeURIComponent(arg) : pristineUnescape(arg);
    } catch (e) { return null; }
  }

  // Buffer.from(<foldable>, 'base64'|'hex').toString(['utf8'])
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.name === 'toString' &&
      callee.object.type === 'CallExpression') {
    const inner = callee.object;
    const innerCallee = inner.callee;
    if (innerCallee.type === 'MemberExpression' && !innerCallee.computed &&
        innerCallee.property.name === 'from' && innerCallee.object.type === 'Identifier' &&
        innerCallee.object.name === 'Buffer' && pristineBufferFrom) {
      if (inner.arguments.length < 2) return null;
      const data = foldNode(inner.arguments[0], bindings, depth + 1);
      const enc = foldNode(inner.arguments[1], bindings, depth + 1);
      if (typeof data !== 'string' || (enc !== 'base64' && enc !== 'hex')) return null;
      try {
        const buf = pristineBufferFrom(data, enc);
        return pristineBufferToString.call(buf, 'utf8');
      } catch (e) { return null; }
    }
  }

  // Pure String/Array chain methods on an already-foldable receiver: X.split(sep) /
  // X.reverse() / X.join(sep) / X.trim() / etc. — receiver may itself be another such call.
  if (callee.type === 'MemberExpression' && !callee.computed && FOLDABLE_STRING_METHODS.has(callee.property.name)) {
    const receiver = foldNode(callee.object, bindings, depth + 1);
    if (receiver === null) return null;
    const method = callee.property.name;
    const args = [];
    for (const a of node.arguments) {
      const v = foldNode(a, bindings, depth + 1);
      if (v === null) return null;
      args.push(v);
    }
    try {
      if (receiver && typeof receiver === 'object' && Array.isArray(receiver.__array)) {
        if (method === 'join') return pristineStringPrototype.join.call(receiver.__array, args[0]);
        if (method === 'reverse') return { __array: pristineStringPrototype.reverse.call(receiver.__array.slice()) };
        return null;
      }
      if (typeof receiver !== 'string') return null;
      if (method === 'split') return { __array: pristineStringPrototype.split.call(receiver, args[0]) };
      const fn = pristineStringPrototype[method];
      if (!fn) return null;
      const out = fn.apply(receiver, args);
      return typeof out === 'string' ? out : null;
    } catch (e) { return null; }
  }

  return null;
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Structural matcher — recognizes obfuscated-access-to-a-dangerous-primitive shapes that don't
// need value folding at all, plus drives the folder for the shapes that do. Produces:
//   - standalone: {severity, matched, pos} — a deliberate obfuscation idiom no legitimate code
//     has a reason to produce (bracket/alias/unicode-escape eval, constructor-chase sandbox
//     escape, obfuscated-specifier require of a sensitive module). Fed directly into detector.js
//     as a block-tier detection — this is the one place this module's finding IS the finding,
//     not merely a signal for the existing correlation engine.
//   - codeDecode / dynamicCode / processExec / sensitivePath positions — fed into
//     behaviorTracker.analyzeModule() as additional signal positions for the EXISTING correlation
//     rules (DYNAMIC_CODE_EXEC_CHAIN, OBFUSCATED_CODE_EXECUTION, REMOTE_FETCH_EXEC) to consume.
//   - literals — folded literal string values, re-tested by detector.js against the existing
//     BLOCK_SIGNATURES/WARN_SIGNATURES/BLOCK_REGEXES matchers unchanged.
// ══════════════════════════════════════════════════════════════════════════════════════════════

const DECODE_PRIMITIVE_NAMES = new Set(['fromCharCode', 'decodeURIComponent', 'unescape']);

// Returns { name: 'eval'|'Function'|'GeneratorFunction', direct: boolean } | null.
//
// `direct` distinguishes a reference the EXISTING text/regex engine already sees and already
// handles correctly (a bare `eval` identifier, or the `(0, eval)`/`(void 0, eval)` indirect-eval
// idiom that SIGNAL_PATTERNS.DYNAMIC_CODE already matches as raw text) from one reached only
// through genuine obfuscation (a bracket/concat-folded computed-member key, a local alias
// binding, or a constructor-chase sandbox escape). Only `direct: false` results get the
// standalone hard-block treatment in walkExpression — escalating `direct: true` cases too would
// make this module hard-block the ordinary, already-permitted `(0, eval)(code)` idiom (used
// legitimately by some polyfills/sandboxing shims for global-scope eval) purely because it now
// also runs the AST pass, which is not this phase's job: bare/idiomatic references stay exactly
// as permissive as they are today (WARN-only unless already chained via existing correlation).
function resolveIdentity(node, bindings) {
  if (!node) return null;
  if (node.type === 'Identifier') {
    if (node.name === 'eval') return { name: 'eval', direct: true };
    const b = bindings.get(node.name);
    return b && b.kind === 'identity' ? { name: b.value, direct: false } : null;
  }
  if (node.type === 'SequenceExpression') {
    // (0, eval) / (void 0, eval) — already-recognized indirect-eval idiom; propagate whatever
    // the last element resolves to as-is (an alias reached via a sequence, e.g. `(0, fn)` where
    // fn is a local alias, is still obfuscated — only a literal `eval` tail is direct).
    const last = node.expressions[node.expressions.length - 1];
    return resolveIdentity(last, bindings);
  }
  if (node.type === 'MemberExpression') {
    // `.constructor` sandbox-escape chase: (fnExpr).constructor -> Function;
    // Object.getPrototypeOf(genExpr).constructor -> GeneratorFunction; chained .constructor.constructor.
    const propName = node.computed ? foldNode(node.property, bindings, 0) : node.property.name;
    if (propName !== 'constructor') {
      // Non-'constructor' computed/bracket access: resolve via folding the key, e.g.
      // this['ev'+'al'], global['eval']. Always obfuscated — legitimate code has no reason to
      // reach a sensitive global through a computed property access.
      const key = node.computed ? foldNode(node.property, bindings, 0) : null;
      if (key === 'eval' || key === 'Function' || key === 'GeneratorFunction') return { name: key, direct: false };
      return null;
    }
    const obj = node.object;
    if (obj.type === 'FunctionExpression') return { name: obj.generator ? 'GeneratorFunction' : 'Function', direct: false };
    if (obj.type === 'CallExpression' && obj.callee.type === 'MemberExpression' &&
        !obj.callee.computed && obj.callee.property.name === 'getPrototypeOf' &&
        obj.callee.object.type === 'Identifier' && obj.callee.object.name === 'Object' &&
        obj.arguments.length === 1 && obj.arguments[0].type === 'FunctionExpression') {
      return { name: obj.arguments[0].generator ? 'GeneratorFunction' : 'Function', direct: false };
    }
    // Chained .constructor.constructor — a second constructor-chase on an already-resolved
    // Function/GeneratorFunction identity is still just 'Function' (Function.constructor === Function).
    const inner = resolveIdentity(obj, bindings);
    if (inner && (inner.name === 'Function' || inner.name === 'GeneratorFunction')) return { name: 'Function', direct: false };
    return null;
  }
  return null;
}

// Walks a statement's expression tree for CallExpressions and classifies each. `emit` receives
// { kind: 'standalone'|'signal'|'literal', ... }.
function walkExpression(node, bindings, emit, depth) {
  if (!node || depth > MAX_PARSE_DEPTH) return;
  if (node.type === 'CallExpression') {
    const identity = resolveIdentity(node.callee, bindings);
    if (identity && !identity.direct) {
      emit({ kind: 'standalone', severity: 'CRITICAL', label: 'ast-resolved-' + identity.name.toLowerCase() + '-access', pos: node.__pos });
    } else if (node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments.length === 1) {
      const spec = foldNode(node.arguments[0], bindings, 0);
      if (typeof spec === 'string' && node.arguments[0].type !== 'Literal') {
        // Only a NON-trivial fold (join/concat, not a bare literal) counts — a plain
        // require('literal') is already fully visible to the existing text scanners.
        if (/child_process/.test(spec)) {
          emit({ kind: 'standalone', severity: 'HIGH', label: 'ast-resolved-obfuscated-require:' + spec, pos: node.__pos });
        }
      }
    } else {
      const mname = node.callee.type === 'MemberExpression' && !node.callee.computed ? node.callee.property.name : null;
      const isFromCharCode = mname === 'fromCharCode' && node.callee.object.type === 'Identifier' && node.callee.object.name === 'String';
      const isDecodeURI = node.callee.type === 'Identifier' && (node.callee.name === 'decodeURIComponent' || node.callee.name === 'unescape');
      const isSplitReverseJoin = mname === 'join' && node.callee.object.type === 'CallExpression' &&
        node.callee.object.callee.type === 'MemberExpression' && !node.callee.object.callee.computed &&
        node.callee.object.callee.property.name === 'reverse' &&
        node.callee.object.callee.object.type === 'CallExpression' &&
        node.callee.object.callee.object.callee.type === 'MemberExpression' &&
        !node.callee.object.callee.object.callee.computed &&
        node.callee.object.callee.object.callee.property.name === 'split';
      const isBufferDecode = mname === 'toString' && node.callee.object.type === 'CallExpression' &&
        node.callee.object.callee.type === 'MemberExpression' && !node.callee.object.callee.computed &&
        node.callee.object.callee.property.name === 'from' &&
        node.callee.object.callee.object.type === 'Identifier' && node.callee.object.callee.object.name === 'Buffer';
      if (isFromCharCode || isDecodeURI || isSplitReverseJoin || isBufferDecode) {
        emit({ kind: 'signal', category: 'codeDecode', pos: node.__pos });
      }
      // General literal re-match: any successfully-folded call result from a non-trivial chain.
      const folded = foldCall(node, bindings, 0);
      if (typeof folded === 'string') {
        emit({ kind: 'literal', value: folded, pos: node.__pos });
      }
    }
    for (const a of node.arguments) walkExpression(a, bindings, emit, depth + 1);
    walkExpression(node.callee, bindings, emit, depth + 1);
    return;
  }
  if (node.type === 'BinaryExpression') {
    const folded = foldNode(node, bindings, 0);
    if (typeof folded === 'string') emit({ kind: 'literal', value: folded, pos: node.__pos });
    walkExpression(node.left, bindings, emit, depth + 1);
    walkExpression(node.right, bindings, emit, depth + 1);
    return;
  }
  if (node.type === 'MemberExpression') {
    walkExpression(node.object, bindings, emit, depth + 1);
    if (node.computed) walkExpression(node.property, bindings, emit, depth + 1);
    return;
  }
  if (node.type === 'SequenceExpression') {
    for (const e of node.expressions) walkExpression(e, bindings, emit, depth + 1);
    return;
  }
  if (node.type === 'UnaryExpression') { walkExpression(node.argument, bindings, emit, depth + 1); return; }
  if (node.type === 'ArrayExpression') {
    for (const el of node.elements) if (el) walkExpression(el, bindings, emit, depth + 1);
    return;
  }
  if (node.type === 'NewExpression') {
    for (const a of node.arguments) walkExpression(a, bindings, emit, depth + 1);
  }
}

// Directly-invoked bracket-eval with no intermediate alias, e.g. `this['ev'+'al']('code')` — the
// standalone-CallExpression check in walkExpression already covers this via resolveIdentity(callee).

function analyzeStatements(statements, basePos, emit) {
  const bindings = new Map();
  for (const stmt of statements) {
    if (stmt.type === 'VariableDeclaration') {
      if (stmt.init) {
        const identity = resolveIdentity(stmt.init, bindings);
        if (identity) {
          // Once bound to a local name, ANY further use is an alias reference regardless of how
          // directly the identity itself was reached — `const fn = eval;` evades the `eval(`
          // call-site pattern purely by existing as an assignment, so it must carry forward as
          // non-direct even though resolveIdentity(bare `eval`) reports direct:true in isolation.
          bindings.set(stmt.name, { kind: 'identity', value: identity.name });
        } else {
          const folded = foldNode(stmt.init, bindings, 0);
          if (typeof folded === 'string') {
            bindings.set(stmt.name, { kind: 'literal', value: folded });
          }
        }
        walkExpression(stmt.init, bindings, emit, 0);
      }
    } else if (stmt.type === 'ExpressionStatement') {
      walkExpression(stmt.expression, bindings, emit, 0);
    }
  }
}
// NOTE: literal/signal emission for a declarator's init lives entirely in walkExpression() (its
// BinaryExpression and CallExpression branches each fold-and-emit themselves) — the loop above
// only ever WALKS the init, it must not also emit for it, or every folded declarator init would
// be reported twice.

// ══════════════════════════════════════════════════════════════════════════════════════════════
// Orchestrator
// ══════════════════════════════════════════════════════════════════════════════════════════════

const { AhoCorasick } = require('./aho-corasick');
// Reused so a folded literal (e.g. '/etc/'+'sha'+'dow') can be classified as a sensitive-path
// signal with the EXACT same rule behavior-tracker.js already applies to literal path text —
// this module still invents no new pattern/rule definitions, it only widens what text reaches
// the existing ones. One-directional dependency (behavior-tracker.js does not import ast-scan.js).
const { SIGNAL_PATTERNS } = require('./behavior-tracker');

const PRESCREEN_KEYWORDS = [
  'fromcharcode', 'getprototypeof', '.constructor', 'decodeuricomponent', 'unescape(',
  'buffer.from', '.reverse()', '.reverse ()', '(0,', '(0 ,', '(void 0,', 'require(', '.join(',
];
const UNICODE_ESCAPE_RE = /\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}/;
// Regex-tier prescreen triggers (mirrors detector.js's BLOCK_REGEXES coexisting with its
// Aho-Corasick literal matcher) for idioms that leave NO recognizable literal substring in raw
// text at all — that's the entire point of e.g. `this['ev'+'al']`, so a substring prescreener can
// never gate it. A broader match here only costs an extra bounded parse attempt on a span that
// turns out uninteresting; it can never cause a false positive, since detection precision lives
// entirely downstream in the folder/structural-matcher, not in the prescreen.
const PRESCREEN_REGEXES = [
  /\[\s*['"]/,                                                    // computed access with a fresh string-literal key
  /=\s*eval\s*[;,)]/,                                             // bare `= eval` aliasing
  // Adjacent short string-literal concatenation. Deliberately NOT restricted to word/dot/hyphen
  // characters (an earlier version was, and missed payloads like 'nc ' + '-e /bin/sh' — the
  // fragments of an assembled command/path routinely contain spaces and slashes). Bounded to
  // short (<=24 char) literals only so it stays a narrow shape, not "any two adjacent strings" —
  // template-literal-heavy or long-literal-heavy legitimate code doesn't match this either way.
  /['"][^'"\n]{0,24}['"]\s*\+\s*['"][^'"\n]{0,24}['"]/,
];

class AstScanner {
  constructor() {
    this._prescreener = new AhoCorasick(PRESCREEN_KEYWORDS);
  }

  scan(content, filename) {
    const result = { detections: [], dynamicCode: [], processExec: [], codeDecode: [], sensitivePath: [], literals: [] };
    try {
      if (!content || typeof content !== 'string') return result;
      if (!this._prescreener.searchInsensitive(content) && !UNICODE_ESCAPE_RE.test(content) &&
          !PRESCREEN_REGEXES.some(re => re.test(content))) {
        return result;
      }

      const spans = findCandidateSpans(content);
      let spanCount = 0;
      for (const span of spans) {
        if (spanCount++ >= MAX_SPANS_PER_FILE) break;
        try {
          this._scanSpan(content, span, result);
        } catch (e) {
          // A single unparseable span never affects any other span or the existing scanners.
          continue;
        }
      }
    } catch (e) {
      // Absolute backstop: scan() must never throw. Whatever succeeded before the exception is
      // still returned; the caller's existing scanners run over the full raw content regardless.
    }
    return result;
  }

  _scanSpan(content, span, result) {
    const text = content.slice(span.start, span.end);
    const tokens = tokenize(text);
    if (tokens.length === 0) return;
    const parser = new Parser(tokens);
    const statements = parser.parseProgram();
    annotatePositions(statements, span.start);

    const emit = (item) => {
      if (item.kind === 'standalone') {
        result.detections.push({ type: 'obfuscated-dynamic-code', severity: item.severity, matched: item.label, pos: item.pos });
      } else if (item.kind === 'signal') {
        result[item.category].push(item.pos);
      } else if (item.kind === 'literal') {
        result.literals.push({ value: item.value, pos: item.pos });
        // A folded literal that itself reads as a sensitive filesystem path (e.g. '/etc/' +
        // 'sha' + 'dow') is a sensitivePath signal at the fold site — feeds the EXISTING
        // CREDENTIAL_EXFILTRATION correlation in behavior-tracker.js unchanged (see
        // detector.js's astSignalsForBehavior wiring), same reuse discipline as codeDecode.
        if (SIGNAL_PATTERNS.SENSITIVE_PATH.some((p) => p.test(item.value))) {
          result.sensitivePath.push(item.pos);
        }
      }
    };
    analyzeStatements(statements, span.start, emit);
  }
}

// Annotates every node reachable from `statements` with an absolute source offset (__pos), used
// only for reporting — best-effort (falls back to the span start when a node has no directly
// tracked position, which is fine: positions only need to be roughly right for proximity
// correlation, not exact).
function annotatePositions(statements, base) {
  // Tokens already carry absolute start/end (tokenize() is called on a slice, but Parser doesn't
  // offset them — do it once here rather than threading `base` through every parse* method).
  const stamp = (node) => {
    if (!node || typeof node !== 'object') return;
    if (node.__pos === undefined) node.__pos = base;
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (Array.isArray(v)) v.forEach(stamp);
      else if (v && typeof v === 'object' && v.type) stamp(v);
    }
  };
  statements.forEach(stamp);
}

// Locates bounded, statement-ish spans around each prescreener hit, capped at MAX_SPAN_CHARS.
// Bracket/paren/brace-DEPTH-aware (relative to the hit), not merely "nearest ;{}" — a naive
// nearest-separator scan breaks on exactly the constructs this module most needs to see, e.g.
// `(function(){}).constructor`: the function body's OWN closing `}` sits one character before
// `.constructor`, so a depth-blind backward scan would stop there and chop off the `const F =
// (function(){})` prefix entirely. Scanning outward while tracking depth relative to the hit (an
// unmatched closer means "still inside a construct that encloses the hit," not "found a
// boundary") gets the whole enclosing statement instead. A slightly-too-wide or too-narrow span
// only ever changes whether THIS module sees an extra bypass — it never changes what the existing
// text scanners see, so imprecision here is a coverage tradeoff, not a correctness risk.
// Both directions must be string/comment-AWARE, not just bracket-depth-aware: the reversed-string
// idiom this module specifically targets (')1(trela'.split('').reverse().join('')) puts literal
// '(' ')' characters INSIDE a string, which a naive char-level bracket counter misreads as real
// brackets — breaking span-boundary detection on exactly the payload this phase exists to catch.
// findSpanStart reframes "scan backward" as "scan forward from a bounded safe anchor, remembering
// the last depth-0 statement boundary reached before the hit" so it can reuse the same
// string/comment-skipping logic as findSpanEnd instead of a second, backward-only implementation.
function skipStringOrComment(content, i, limit) {
  const ch = content[i];
  if (ch === '\'' || ch === '"' || ch === '`') {
    const quote = ch;
    let j = i + 1;
    while (j < limit && content[j] !== quote) { if (content[j] === '\\') j++; j++; }
    return j + 1;
  }
  if (ch === '/' && content[i + 1] === '/') {
    const nl = content.indexOf('\n', i);
    return (nl === -1 || nl > limit) ? limit : nl;
  }
  if (ch === '/' && content[i + 1] === '*') {
    const end = content.indexOf('*/', i + 2);
    return (end === -1 || end + 2 > limit) ? limit : end + 2;
  }
  return -1; // not a string/comment start
}

// Extends past up to a few (not just the immediately adjacent) depth-0 statement boundaries on
// EITHER side of the hit, bounded by MAX_SPAN_CHARS. Two distinct cross-statement shapes both
// need this: an obfuscated call target is often declared in one statement and invoked a statement
// or two later (`const fn = this['ev'+'al']; fn(...)` — needs trailing room), and a value folded
// at the hit itself is often built from a binding declared a statement or two EARLIER (`const h =
// '...'; ...Buffer.from(h.trim(), 'hex')...` — needs leading room). A span limited to the single
// statement touching the hit would see neither. Mirrors the small-number-of-statements philosophy
// CORRELATION_MAX_SEPARATORS already uses in behavior-tracker.js, just applied to span width.
const SPAN_LEADING_STATEMENTS = 2;
const SPAN_TRAILING_STATEMENTS = 3;

// A single continuous forward scan from a bounded window before the hit through a bounded window
// after it, with ONE running depth counter for the whole pass. This must be one pass, not two
// independent start/end scans: the hit is frequently nested inside a construct that opened BEFORE
// it (e.g. `decodeURIComponent` nested inside `eval(...)`) — an end-scan that started its own
// depth counter at 0 from the hit position would misread `eval`'s own closing paren as an
// out-of-scope closer and truncate the span mid-expression, losing the very call site this module
// needs to see. Threading one counter through both halves keeps depth accurate the whole way.
function computeSpan(content, hitIdx) {
  const windowStart = Math.max(0, hitIdx - MAX_SPAN_CHARS / 2);
  const windowEnd = Math.min(content.length, hitIdx + MAX_SPAN_CHARS / 2);
  let i = windowStart;
  let depth = 0;
  const boundariesBeforeHit = [windowStart];
  let statementsSeenAfterHit = 0;
  let end = windowEnd;
  while (i < windowEnd) {
    const skipped = skipStringOrComment(content, i, windowEnd);
    if (skipped !== -1) { i = skipped; continue; }
    const ch = content[i];
    if (ch === '{' || ch === '(' || ch === '[') {
      depth++;
    } else if (ch === '}' || ch === ')' || ch === ']') {
      if (i >= hitIdx && depth === 0) { end = i; break; } // closer belonging to an outer, not-opened-here construct
      depth = Math.max(0, depth - 1);
      if (depth === 0) {
        if (i < hitIdx && ch === '}') boundariesBeforeHit.push(i + 1);
        else if (i >= hitIdx && ch === '}' && ++statementsSeenAfterHit >= SPAN_TRAILING_STATEMENTS) { end = i + 1; break; }
      }
    } else if (ch === ';' && depth === 0) {
      if (i < hitIdx) {
        boundariesBeforeHit.push(i + 1);
      } else if (++statementsSeenAfterHit >= SPAN_TRAILING_STATEMENTS) {
        end = i + 1;
        break;
      }
    }
    i++;
  }
  const startIdx = Math.max(0, boundariesBeforeHit.length - 1 - SPAN_LEADING_STATEMENTS);
  return { start: boundariesBeforeHit[startIdx], end };
}

function findCandidateSpans(content) {
  const hits = [];
  const lower = content.toLowerCase();
  for (const kw of PRESCREEN_KEYWORDS) {
    let idx = lower.indexOf(kw);
    while (idx !== -1) { hits.push(idx); idx = lower.indexOf(kw, idx + 1); }
  }
  for (const re of [UNICODE_ESCAPE_RE, ...PRESCREEN_REGEXES]) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    while ((m = g.exec(content)) !== null) {
      hits.push(m.index);
      if (g.lastIndex === m.index) g.lastIndex++;
    }
  }
  if (hits.length === 0) return [];

  hits.sort((a, b) => a - b);
  const spans = [];
  let lastEnd = -1;
  for (const hit of hits) {
    if (hit < lastEnd) continue; // already covered by a previous span
    const { start, end } = computeSpan(content, hit);
    if (end <= start) continue;
    spans.push({ start, end });
    lastEnd = end;
  }
  return spans;
}

module.exports = { AstScanner, AstUnsupported, tokenize, Parser, foldNode, resolveIdentity, findCandidateSpans };
