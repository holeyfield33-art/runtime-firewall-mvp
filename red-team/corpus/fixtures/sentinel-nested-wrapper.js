// red-team/corpus/fixtures/sentinel-nested-wrapper.js
// TEST FIXTURE — NOT MALWARE. Requires ./sentinel-block.js one level deep so the "nested
// require()" matrix row exercises the firewall hook through an intermediate module rather
// than a direct top-level require.
'use strict';
module.exports = require('./sentinel-block.js');
