// demo/modules/evil-miner.js
//
// A stand-in for a crypto-mining payload smuggled into a dependency. It never
// gets to run: the firewall's signature detector matches the mining-pool
// identifiers below and hard-blocks compilation before this file executes.
//
// Triggers: BLOCK_SIGNATURES ("stratum", "cryptonight") -> CRITICAL crypto-miner.

const minerConfig = {
  pool: 'stratum+tcp://pool.hashvault.pro:443',
  algo: 'cryptonight/r',
  wallet: '48Attacker000000000000000000000000000000000000000000000000000000',
  threads: 4,
};

function startMining() {
  // In a real payload this would spin up worker threads and hammer the CPU.
  // The firewall ensures we never reach this point.
  return `mining to ${minerConfig.pool} with ${minerConfig.algo}`;
}

module.exports = { minerConfig, startMining };
