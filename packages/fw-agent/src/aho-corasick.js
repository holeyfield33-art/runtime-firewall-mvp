class AhoCorasick {
  constructor(keywords) {
    // Use array-based transitions (indexed by charCode 0-127) for O(1) hot-path access
    // without string-keyed object property lookups or per-char allocations.
    this.trie = { next: new Array(128).fill(null), fail: null, output: null };
    this._buildTrie(keywords);
    this._buildFailureLinks();
  }

  _buildTrie(keywords) {
    for (const kw of keywords) {
      let node = this.trie;
      for (const ch of kw.toLowerCase()) {
        const code = ch.charCodeAt(0) & 0x7f; // ASCII
        if (!node.next[code]) {
          node.next[code] = { next: new Array(128).fill(null), fail: null, output: null };
        }
        node = node.next[code];
      }
      node.output = kw;
    }
  }

  _buildFailureLinks() {
    const queue = [];
    for (let code = 0; code < 128; code++) {
      const child = this.trie.next[code];
      if (child) {
        child.fail = this.trie;
        queue.push(child);
      }
    }

    while (queue.length > 0) {
      const node = queue.shift();
      for (let code = 0; code < 128; code++) {
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
      let code = text.charCodeAt(i) & 0x7f;
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
      let code = text.charCodeAt(i);
      // Fold uppercase ASCII letters to lowercase range, mask to 0-127
      if (code >= 65 && code <= 90) code += 32;
      code &= 0x7f;
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