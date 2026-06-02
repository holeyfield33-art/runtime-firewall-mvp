const { AhoCorasick } = require('../src/aho-corasick');
const matcher = new AhoCorasick(['stratum','pool.hashvault','eval(','new function','net.createconnection']);
console.log('match1', matcher.search('this is a stratum miner'));
console.log('match2', matcher.search('here goes pool.hashvault payload'));
console.log('match3', matcher.search('eval('));
console.log('match4', matcher.search('new FUNCTION body'.toLowerCase()));
console.log('match5', matcher.search('socket connect net.createConnection'.toLowerCase()));
