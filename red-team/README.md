# Helios Runtime Firewall — Red-Team Attack Suite

A full adversarial attack suite that fires a corpus of malicious (and benign)
JavaScript module payloads at the firewall's detector and **logs what gets
through and what gets blocked**, with per-category gap analysis and a
false-positive check.

Methodology is borrowed from the
[`aletheia-redteam-kit`](https://github.com/holeyfield33-art/aletheia-redteam-kit)
command-center flow (corpus → run → decision logging → gap report →
`summary.json`), but adapted to this firewall's real input surface. The kit
red-teams an **LLM audit API** with prompt payloads; this firewall is a
**code scanner** that takes JavaScript/npm module *source* and returns
`QUARANTINE` (block) or `OBSERVE` (pass). So the corpus here is module source,
not prompts, and "what got through" means a malicious module the detector let
compile.

## What it measures

Each payload is fed through `Detector.scanModuleSync` and classified using the
**exact** block rule `index.js` applies on every `require()`:

> a module is **BLOCKED** iff the detector produces at least one non-`warnOnly`
> detection (`scanResult.detections.filter(d => !d.warnOnly)`), otherwise it is
> **PASSED**.

| Verdict          | Meaning                                                             |
|------------------|--------------------------------------------------------------------|
| `caught`         | malicious payload → BLOCKED (firewall did its job)                  |
| `known-bypass`   | malicious payload → PASSED, but a **documented** static-analysis gap|
| `REGRESSION`     | malicious payload → PASSED that we did **not** expect — a real hole |
| `clean`          | benign control → PASSED (no false positive)                        |
| `FALSE-POSITIVE` | benign control → BLOCKED (over-blocking)                            |

The suite **fails (exit 1)** only on `REGRESSION`s or `FALSE-POSITIVE`s. Known
bypasses are logged as accepted gaps and never fail the build — so this doubles
as a CI guardrail: if someone weakens a detector rule, a `caught` flips to
`REGRESSION` and CI goes red.

## Running it

```bash
npm run redteam                       # full suite, human-readable report + JSON
npm run redteam:bypass                # only show what got through
node red-team/run.js --category credential-exfil
node red-team/run.js --quiet          # summary block only
node red-team/run.js -o runs/x.json   # choose the JSON output path
```

A machine-readable `results/redteam-summary.json` is written on every run
(`results/` is git-ignored — it's a generated artifact). Its shape:

- `totals` — attacks, malicious/benign split, blocked/passed, caught,
  bypasses, knownBypasses, regressions, falsePositives, detectionRatePct
- `categories` — per-category rollup
- `gap_report` — every malicious payload that got through (the "what gets
  through" log), each tagged `knownBypass: true|false`
- `false_positives` — benign controls that were over-blocked
- `results` — full per-attack rows (expected, outcome, verdict, rules fired)

## Corpus

**151 payloads** across 6 threat categories (125 malicious, 26 benign), each
category split into a core catalog and an `-extended` catalog under `corpus/`,
all aggregated by `corpus/index.js` (which validates every entry and rejects
duplicate ids):

| Category            | Count | Covers                                                                             |
|---------------------|:-----:|------------------------------------------------------------------------------------|
| `crypto-miner`      |  26   | stratum pools, coinhive/xmr-stak/cryptonight/nicehash, uncovered brands, concat/hex/wasm evasions |
| `reverse-shell`     |  22   | `/dev/tcp` + curl\|bash (caught); nc/ncat/socat/php/ruby/powershell/lua, http-beacon, mkfifo (bypass) |
| `credential-exfil`  |  28   | `.env`/`.ssh`/`.aws`/`.npmrc`/shadow/passwd theft over http/ws/tls/udp; docker/kube/cookie stores + DNS/beacon/inline-require evasions |
| `dynamic-code-exec` |  30   | eval/Function/vm+exec, base64/hex/atob→exec; bracket/alias/unicode/fromCharCode/constructor/wasm evasions |
| `supply-chain`      |  21   | pastebin/paste.ee/postinstall (caught); raw-github/transfer.sh/ngrok/telegram/IP-literal/base64-domain beacons (bypass) |
| `benign-controls`   |  24   | axios/dotenv/JWT/npm-tooling/word-list, ws/udp/tls clients, git/ffprobe wrappers, template compilers — must **not** block |

Files: `corpus/<category>.js` (core) and `corpus/<category>-extended.js` (the
100+ added variants).

### Adding an attack

Append an object to the relevant catalog:

```js
{
  id: 'exfil-new-trick',          // unique across the whole corpus
  category: 'credential-exfil',
  technique: 'short-slug',
  severity: 'CRITICAL',
  expected: 'BLOCK',              // 'BLOCK' (malicious) or 'PASS' (benign / by-design WARN)
  knownBypass: true,             // OPTIONAL: set only if you expect it to slip past today
  description: 'One line on what it does and why it (does not) get caught',
  code: `/* the module source to scan */`,
}
```

If you add a malicious payload without `knownBypass` and it slips through, the
suite reports a `REGRESSION` and fails — which is exactly the signal you want
when probing for a genuinely new hole. If you're demonstrating a *known* gap,
set `knownBypass: true` and it's logged under `gap_report` as `[known]`.

## Known gaps this suite documents

The current run catches **69/125** malicious payloads (≈55%) with **zero false
positives** on the 26 benign controls. The 56 documented bypasses are
fundamental limits of static/signature analysis and require runtime/AST
instrumentation to close. They cluster into these classes:

- **String-level evasion of literals** — `eval` via bracket/alias/unicode
  escape/`fromCharCode`/reverse/`constructor.constructor`; module names or pool
  URLs reassembled by concatenation/`join`; C2 domains held as base64.
- **Inline-require dodges the behavioral regexes** *(surfaced by this suite)* —
  the egress and dynamic-code rules match a **bound** call (`const tls =
  require('tls'); tls.connect(…)`) but **not** the inline
  `require('tls').connect(…)` form. Only `http`/`https` have a dedicated
  inline-require pattern, so inline `net`/`tls`/`dgram`/`vm` calls slip past
  `CREDENTIAL_EXFILTRATION` and `DYNAMIC_CODE_EXEC_CHAIN`. See
  `exfil-inline-require-net` / `dce-inline-require-vm` (bypass) vs.
  `exfil-aws-netconnect` / `dce-vm-runinthis-spawn` (bound form, blocked).
- **Egress channels outside the signal set** — exfil over `dns.resolve`,
  `navigator.sendBeacon`, or by shelling out to `curl` (the outbound call is a
  child process, not a recognised `NETWORK_EGRESS` primitive).
- **Uncovered brands / paths** — miner brands not in the signature list
  (coinimp, jsecoin, webminepool, deepMiner, wasm cores); credential stores not
  in `SENSITIVE_PATH` (`.docker/config.json`, `.kube/config`, `id_ecdsa`,
  browser cookie stores).
- **Reverse-shell tooling beyond `/dev/tcp`** — `nc -e`, `ncat --exec`,
  `socat`, php/ruby/powershell/lua one-liners, mkfifo backpipes, and an
  HTTP-polling C2 beacon (network + process-exec is not, by itself, a blocking
  rule).
- **Stager literals not on the list** — `wget … | sh` and `curl … | sh` (only
  `| bash` is a block literal); fetch-then-`eval` from a host that isn't a
  known-bad literal.
- **Config obfuscation** — a miner pool URL kept as a base64/hex blob and
  decoded at runtime without ever being `eval`'d.

These are intentional trade-offs the detector makes to keep false positives at
zero on the benign corpus. The value of logging them is a live, regression-
guarded inventory of the firewall's real blind spots — the full machine-readable
list is the `gap_report` array in `results/redteam-summary.json`.
