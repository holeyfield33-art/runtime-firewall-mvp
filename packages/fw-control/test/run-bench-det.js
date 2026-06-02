// tiny runner to ensure FW_ENABLE_DETECTION is set reliably
process.env.FW_ENABLE_DETECTION = '1';
require('./bench.js');
