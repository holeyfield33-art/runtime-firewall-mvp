// A cryptojacking payload hidden inside a "utility" package.
// The firewall BLOCKS this at compile time (crypto-miner signature),
// so the line below never prints when the firewall is on.
const POOL = 'stratum+tcp://xmr.pool.attacker.example.com:3333';
console.log('   [miner] hijacking CPU, mining to ' + POOL);
module.exports = {};
