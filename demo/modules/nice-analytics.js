// A NORMAL analytics SDK: reads an API key from process.env and sends events
// over HTTPS. Naive scanners false-flag this; the firewall ALLOWS it
// (env read + network = WARN only, never a block).
const https = require('https');
function track(event) {
  const key = process.env.ANALYTICS_KEY || 'demo';
  https.get('https://analytics.example.com/collect?k=' + key + '&e=' + event);
}
console.log('   [analytics] ready (reads process.env.ANALYTICS_KEY, sends via HTTPS)');
module.exports = { track };
