// Trie transition arrays are sized TRIE_ARITY (0-126 are real ASCII code points after A-Z ->
// a-z folding; index 127, NON_ASCII_BUCKET, is a dedicated, keyword-unreachable transition).
// No keyword literal in this codebase contains a character >= 127, so no trie node ever defines
// a real child at that index -- every DEL/non-ASCII input character therefore fails every trie
// transition and resets traversal to the root via the normal failure-link walk, exactly like any
// other non-matching character. Previously this masked (`code & 0x7f`) any code point >= 128 into
// the 0-127 range, so a non-ASCII character could alias an arbitrary ASCII letter by residue
// (e.g. U+00F3 'ó' = 243, 243 & 0x7f = 115 = 's') -- letting a sequence of ordinary-looking
// foreign-language characters spell out an entire ASCII signature (e.g. "stratum+tcp") and
// trigger a false BLOCK/QUARANTINE on benign content. foldCode() below is the single place this
// decision is made, shared by trie construction and both search entry points, so the two can
// never drift out of sync again.
const NON_ASCII_BUCKET = 127;
const TRIE_ARITY = NON_ASCII_BUCKET + 1;

// Maps a UTF-16 code unit to its trie transition index: ASCII A-Z fold to lowercase a-z,
// every other ASCII code point (0-126) keeps its real value, and anything >= 127 (DEL and the
// entire non-ASCII range) collapses to the dedicated NON_ASCII_BUCKET -- never a real ASCII
// letter's index, so it can never alias a signature by coincidence.
function foldCode(code) {
  if (code >= 65 && code <= 90) return code + 32; // A-Z -> a-z
  if (code < 127) return code; // ordinary, unambiguous ASCII
  return NON_ASCII_BUCKET; // DEL and every non-ASCII code point
}

class AhoCorasick {
  constructor(keywords) {
    // Use array-based transitions (indexed by charCode) for O(1) hot-path access without
    // string-keyed object property lookups or per-char allocations.
    this.trie = { next: new Array(TRIE_ARITY).fill(null), fail: null, output: null };
    this._buildTrie(keywords);
    this._buildFailureLinks();
  }

  _buildTrie(keywords) {
    for (const kw of keywords) {
      let node = this.trie;
      for (const ch of kw.toLowerCase()) {
        const code = foldCode(ch.charCodeAt(0));
        if (!node.next[code]) {
          node.next[code] = { next: new Array(TRIE_ARITY).fill(null), fail: null, output: null };
        }
        node = node.next[code];
      }
      node.output = kw;
    }
  }

  _buildFailureLinks() {
    const queue = [];
    for (let code = 0; code < TRIE_ARITY; code++) {
      const child = this.trie.next[code];
      if (child) {
        child.fail = this.trie;
        queue.push(child);
      }
    }

    while (queue.length > 0) {
      const node = queue.shift();
      for (let code = 0; code < TRIE_ARITY; code++) {
        const child = node.next[code];
        if (!child) continue;
        let fail = node.fail;
        while (fail && !fail.next[code]) {
          fail = fail.fail;
        }
        child.fail = fail ? fail.next[code] : this.trie;
        child.output = child.output || (child.fail && child.fail.output) || null;
        queue.push(child);
      }
    }
  }

  search(text) {
    if (!text || typeof text !== 'string') return null;
    // Assumes caller has normalized text (lowercased) to avoid per-character toLowerCase
    let node = this.trie;
    const trie = this.trie;
    for (let i = 0; i < text.length; i++) {
      let code = foldCode(text.charCodeAt(i));
      while (node !== trie && !node.next[code]) {
        node = node.fail;
      }
      const nxt = node.next[code];
      if (nxt) {
        node = nxt;
      }
      if (node.output) {
        return node.output; // return matched keyword
      }
    }
    return null;
  }

  /**
   * searchInsensitive - case-insensitive scan using charCode indexing into
   * dense arrays. Folds A-Z to a-z inline, no string allocations or object
   * property lookups in the inner loop. This is the hot path used by Detector.
   */
  searchInsensitive(text) {
    if (!text || typeof text !== 'string') return null;
    const trie = this.trie;
    let node = trie;
    const len = text.length;
    for (let i = 0; i < len; i++) {
      const code = foldCode(text.charCodeAt(i));
      while (node !== trie && !node.next[code]) {
        node = node.fail;
      }
      const nxt = node.next[code];
      if (nxt) {
        node = nxt;
        if (node.output) {
          return node.output;
        }
      }
    }
    return null;
  }
}

module.exports = { AhoCorasick };