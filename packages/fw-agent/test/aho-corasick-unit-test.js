const assert = require('assert');
const { AhoCorasick } = require('../src/aho-corasick');

const matcher = new AhoCorasick(['stratum', 'pool.hashvault', 'eval(', 'new function', 'net.createconnection']);

assert.strictEqual(matcher.search('this is a stratum miner'), 'stratum');
assert.strictEqual(matcher.search('here goes pool.hashvault payload'), 'pool.hashvault');
assert.strictEqual(matcher.search('eval('), 'eval(');
assert.strictEqual(matcher.search('new FUNCTION body'.toLowerCase()), 'new function');
assert.strictEqual(matcher.search('socket connect net.createConnection'.toLowerCase()), 'net.createconnection');
assert.strictEqual(matcher.search('no matches here'), null);

// ── Unicode-aliasing regression ──────────────────────────────────────────────────────────────
// Previously, searchInsensitive()/search() folded any code point via `code & 0x7f`, so a
// non-ASCII character whose value happened to share the low 7 bits of an ASCII letter was
// silently treated as that letter. A sequence of such characters could therefore spell out an
// entire ASCII signature (e.g. "stratum+tcp") without containing a single real ASCII byte,
// triggering a false BLOCK/QUARANTINE on benign non-ASCII content. Fixed: non-ASCII code points
// now fold to a dedicated, keyword-unreachable bucket instead of aliasing any real ASCII index.
const cryptoMatcher = new AhoCorasick(['stratum+tcp']);

// Each character below is the real ASCII character of "stratum+tcp" plus 128 (e.g. 's' (115) ->
// U+00F3 'ó' (243)) -- exactly the shape that `code & 0x7f` used to fold back to "stratum+tcp".
const unicodeLookalike = 'óôòáôõí«ôãð';
assert.strictEqual(
  [...unicodeLookalike].map((c) => String.fromCharCode(c.codePointAt(0) & 0x7f)).join(''),
  'stratum+tcp',
  'sanity: the lookalike string must reproduce "stratum+tcp" under the OLD buggy `& 0x7f` fold'
);

assert.strictEqual(cryptoMatcher.search('stratum+tcp'), 'stratum+tcp', 'real "stratum+tcp" must match');
assert.strictEqual(cryptoMatcher.search('STRATUM+TCP'.toLowerCase()), 'stratum+tcp', 'case-varied "STRATUM+TCP" must match');
assert.strictEqual(cryptoMatcher.searchInsensitive('stratum+tcp'), 'stratum+tcp', 'real "stratum+tcp" must match (searchInsensitive)');
assert.strictEqual(cryptoMatcher.searchInsensitive('STRATUM+TCP'), 'stratum+tcp', 'case-varied "STRATUM+TCP" must match (searchInsensitive)');
assert.strictEqual(cryptoMatcher.searchInsensitive(unicodeLookalike), null, 'Unicode low-bit lookalike must NOT match (searchInsensitive)');
assert.strictEqual(cryptoMatcher.search(unicodeLookalike), null, 'Unicode low-bit lookalike must NOT match (search)');

// Ordinary international text unrelated to any signature must never false-match, with or
// without characters that happen to be non-ASCII.
const internationalText = 'Café résumé naïve façade Zürich Москва 東京 déjà vu';
assert.strictEqual(cryptoMatcher.searchInsensitive(internationalText), null, 'ordinary international text must not produce a false match');
assert.strictEqual(matcher.searchInsensitive(internationalText), null, 'ordinary international text must not false-match any real signature either');

// A genuine signature immediately following non-ASCII text must still be found -- the fix must
// only stop non-ASCII from ALIASING a signature, not from resetting cleanly back to a match.
assert.strictEqual(cryptoMatcher.searchInsensitive('naïve stratum+tcp'), 'stratum+tcp', 'a real signature after non-ASCII text must still match');

console.log('AhoCorasick unit test passed.');

