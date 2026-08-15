// red-team/corpus/fixtures/sentinel-block.js
//
// TEST FIXTURE — NOT MALWARE. Deliberately labeled and isolated under fixtures/ (not part of
// the red-team `corpus` aggregation in ../index.js, so it never runs as an attack-suite row).
//
// Contains a literal BLOCK_SIGNATURE (see packages/fw-agent/src/detector.js) so any harness that
// loads it through a hooked Module.prototype._compile reliably throws a "[Firewall] ..." error.
// If the firewall's hook never sees this file (e.g. the execution path bypasses _compile), the
// module loads cleanly and sets a marker so the caller can tell "ran" apart from "blocked".
'use strict';

var SENTINEL_MARKER = 'stratum+tcp://sentinel.invalid';

if (typeof globalThis !== 'undefined') {
  globalThis.__SENTINEL_RAN__ = true;
}

if (typeof module !== 'undefined') {
  module.exports = { marker: SENTINEL_MARKER, ran: true };
}
