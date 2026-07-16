// red-team/corpus/index.js
// Aggregates every attack catalog into a single ordered corpus.
// Each category file exports an array of attack objects with the shape:
//   { id, category, technique, severity, expected, knownBypass?, description, code }

const catalogs = [
  require('./crypto-miner'),
  require('./reverse-shell'),
  require('./credential-exfil'),
  require('./dynamic-code-exec'),
  require('./supply-chain'),
  require('./benign-controls'),
];

const corpus = catalogs.flat();

// Fail fast on a malformed corpus so a typo never silently drops an attack.
const seen = new Set();
for (const a of corpus) {
  for (const field of ['id', 'category', 'technique', 'expected', 'code']) {
    if (!a[field]) throw new Error(`Corpus entry missing "${field}": ${JSON.stringify(a.id || a)}`);
  }
  if (!['BLOCK', 'PASS'].includes(a.expected)) {
    throw new Error(`Corpus entry "${a.id}" has invalid expected="${a.expected}" (must be BLOCK or PASS)`);
  }
  if (seen.has(a.id)) throw new Error(`Duplicate corpus id: ${a.id}`);
  seen.add(a.id);
}

module.exports = { corpus };
