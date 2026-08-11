const { BehaviorTracker, SIGNAL_PATTERNS, BEHAVIOR_PRESCREENER_KEYWORDS } = require('../src/behavior-tracker');
const { AhoCorasick } = require('../src/aho-corasick');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertRegexAndKeyword(aho, groupName, pattern, canary) {
  assert(pattern.test(canary), `${groupName} regex did not match canary: ${pattern} :: ${canary}`);
  assert(
    !!aho.searchInsensitive(canary),
    `${groupName} prescreener missed canary: ${pattern} :: ${canary}`
  );
}

function runKeywordSupersetCanaryTests() {
  const aho = new AhoCorasick(BEHAVIOR_PRESCREENER_KEYWORDS);

  const canaries = {
    SENSITIVE_READ: [
      'fs.readFile("/tmp/a")',
      'fs.readFileSync("/tmp/a")',
      'fs.open("/tmp/a")',
    ],
    ENV_READ: [
      'process.env.NODE_ENV',
    ],
    SENSITIVE_PATH: [
      '"/.env"',
      '"/tmp/credentials"',
      '"/.ssh/config"',
      '"id_rsa"',
      '"/.netrc"',
      '"/.aws/credentials"',
      '"/tmp/secret.txt"',
      '"/tmp/passwd"',
      '"/tmp/shadow"',
    ],
    SENSITIVE_CONFIG_PATH: [
      '"/.kube/config"',
      '"/.docker/config.json"',
      '"/Users/x/Library/Application Support/Google/Chrome/Default/Login Data"',
    ],
    NPMRC_READ: [
      '".npmrc"',
    ],
    NPMRC_TOKEN: [
      '_authToken=abc',
      '_auth=abc',
      '_password=abc',
      'authToken=abc',
    ],
    HOST_OPTION: [
      "{ host: 'evil.example' }",
    ],
    NETWORK_EGRESS: [
      'http.request("https://a")',
      'https.request("https://a")',
      'http.get("https://a")',
      'https.get("https://a")',
      'fetch("https://a")',
      'net.connect(443, "x")',
      'net.createConnection(443, "x")',
      'socket.connect(443, "x")',
      'new WebSocket("wss://x")',
      'new XMLHttpRequest()',
      'tls.connect(443, "x")',
      'dgram.createSocket("udp4")',
      'require("https").get("https://x")',
      'require("net").connect(443, "x")',
      'dns.resolve("x.example")',
      'navigator.sendBeacon("https://x", "d")',
    ],
    DYNAMIC_CODE: [
      'eval("1")',
      'new Function("return 1")',
      'Function("return 1")',
      'vm.runInNewContext("1", {})',
      'vm.Script("1")',
      'setTimeout("x", 1)',
      'setInterval("x", 1)',
      'Script.runInNewContext("1", {})',
      'require("vm").runInThisContext("1")',
      '(0,eval)("1")',
    ],
    CODE_DECODE: [
      'atob("QQ==")',
      'Buffer.from("41", "hex")',
    ],
    PROCESS_EXEC: [
      'child_process.exec("id")',
      'execSync("id")',
      'spawnSync("id")',
      'execFile("id")',
      'execFileSync("id")',
      'ShellString("x")',
      'process.binding("spawn_sync")',
    ],
    DYNAMIC_REQUIRE: [
      'require.resolve("x")',
      'module._load("x")',
      'const y = module._load("x"); require(modName)',
    ],
  };

  for (const [groupName, patterns] of Object.entries(SIGNAL_PATTERNS)) {
    const groupCanaries = canaries[groupName];
    assert(Array.isArray(groupCanaries), `Missing canary list for group ${groupName}`);
    assert(
      groupCanaries.length === patterns.length,
      `Canary count mismatch for ${groupName}: expected ${patterns.length}, got ${groupCanaries.length}`
    );
    for (let i = 0; i < patterns.length; i++) {
      assertRegexAndKeyword(aho, groupName, patterns[i], groupCanaries[i]);
    }
  }

  console.log('  ✓ Prescreener canary coverage matches all SIGNAL_PATTERNS regexes');
}

function runCrossFileRegressionCase() {
  const tracker = new BehaviorTracker();
  const pkg = 'pkg:prescreener-cross-file';

  const fileA = "module.exports = Function('return 21+21');";
  const fileB = "module.exports = () => require('child_process').execSync('id');";

  const a = tracker.analyzeModule('fileA.js', fileA, pkg);
  const b = tracker.analyzeModule('fileB.js', fileB, pkg);
  const cross = tracker.analyzePackage(pkg);

  assert(a.length === 0, 'fileA should not trigger an intra-module chain by itself');
  assert(b.length === 0, 'fileB should not trigger an intra-module chain by itself');

  const found = cross.find(v => v.rule === 'DYNAMIC_CODE_EXEC_CHAIN_CROSS_FILE');
  assert(!!found, 'Expected DYNAMIC_CODE_EXEC_CHAIN_CROSS_FILE in cross-file analysis');

  console.log('  ✓ Cross-file Function + execSync split triggers DYNAMIC_CODE_EXEC_CHAIN_CROSS_FILE');
}

function main() {
  runKeywordSupersetCanaryTests();
  runCrossFileRegressionCase();
  console.log('All prescreener superset tests passed.');
}

main();
