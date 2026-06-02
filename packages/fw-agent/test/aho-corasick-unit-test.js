const assert = require('assert');
const { AhoCorasick } = require('../src/aho-corasick');

const matcher = new AhoCorasick(['stratum', 'pool.hashvault', 'eval(', 'new function', 'net.createconnection']);

assert.strictEqual(matcher.search('this is a stratum miner'), 'stratum');
assert.strictEqual(matcher.search('here goes pool.hashvault payload'), 'pool.hashvault');
assert.strictEqual(matcher.search('eval('), 'eval(');
assert.strictEqual(matcher.search('new FUNCTION body'.toLowerCase()), 'new function');
assert.strictEqual(matcher.search('socket connect net.createConnection'.toLowerCase()), 'net.createconnection');
assert.strictEqual(matcher.search('no matches here'), null);

console.log('AhoCorasick unit test passed.');
