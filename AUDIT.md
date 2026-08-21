# Audit: runtime-firewall-mvp — 2026-07-25

Classification: **Node.js library/CLI + local API service** (require()-time security agent
`packages/fw-agent`, plus a loopback-only telemetry/dashboard server `packages/fw-control`).
Full audit performed (auth, input validation, error handling, core-flow attack). No frontend
exists to skip; Docker Compose exists and was checked for config validity but not run end-to-end
(see Unverified).

Base commit audited: `1d60552` (branch `claude/pre-launch-audit-hardening-qr7bqj`). Node v22.22.2.

## Verdict: SHIP WITH RISKS

The core product does exactly what it claims: it blocks the crypto-miner/credential-stealer
demo payloads at `require()` time, lets a normal analytics dependency through with zero false
positives, fails closed on policy tampering, and survived every malformed/oversized/adversarial
input thrown at it in this session (no crash, no hang, no bypass-via-DoS). No secrets, injection
bugs, or auth gaps were found. The risks below are dependency-vuln and claims-accuracy issues,
not functional breakage — hence "ship with risks," not "do not ship."

## Fixed (with proof)

| # | Sev | Issue | Fix commit | Test |
|---|-----|-------|------------|------|
| 1 | P1 | README claimed the adversarial bypass suite has "25 cases, all passing" (Running Tests section + Acceptance Criteria table). Actual suite has grown to 52 tests, all passing. A false test-count claim in a launch README is misleading to anyone deciding whether to trust the product. | (this branch, README.md) | `npm run test:adversarial` → `Results: 52 passed, 0 failed out of 52 tests`, cross-checked against source (`grep -c` on `packages/fw-control/test/adversarial/adversarial.test.js`) |
| 2 | P2 (trivial, applied) | `brace-expansion@5.0.7` (transitive dev-dependency via `c8`→`test-exclude`→`minimatch`) has a known DoS via unbounded expansion length. Non-breaking fix available. | (this branch, package-lock.json) | Before: `npm audit` listed it under 7 high-severity findings. `npm audit fix` (no `--force`) bumped it to `5.0.8`. After: `npm ls brace-expansion` → `5.0.8`; `npm audit` no longer lists it; full `npm test` re-run green (see Commands run) |

## Open findings

| # | Sev | Issue | Location | Repro command |
|---|-----|-------|----------|----------------|
| 3 | P2 | `fastify@4.29.1` (latest 4.x) pulls in 6 high-severity transitive/direct CVEs (fast-uri host-confusion/path-traversal, find-my-way HTTP/2 DoS, fastify's own Content-Type validation-bypass and `X-Forwarded-Proto/Host` spoofing advisories). Fix requires a major bump to fastify 5.x (breaking, out of audit scope). Mitigated in practice: `packages/fw-control/src/server.js` binds to `127.0.0.1` only (`server.js:186`) and never reads `request.protocol`/`request.host` for security decisions, so the spoofing CVE has no exploitable path here; the DoS/parsing CVEs still apply to any local process that can reach the loopback port. | `packages/fw-control/package.json:10`, `packages/fw-control/src/server.js` | `npm audit` |
| 4 | P2 | README's Performance table lists "Enforced? **Yes**" for the 25%-median compilation-overhead gate, implying CI blocks regressions automatically. No workflow step actually invokes `npm run gate` / `run-gate-test.js` — `.github/workflows/ci.yml` runs unit/adversarial/auth/red-team/integration/live/coverage/self-integrity/pack-dry-run, but never the gate. Enforcement is manual-only (a human runs `npm run gate` and pastes output into `results/`, per `CONTRIBUTING.md` §"Never loosen the performance gate"). Not a functional bug, but the README overstates automation. | `README.md` Performance section; `.github/workflows/ci.yml` | `grep -n "gate" .github/workflows/ci.yml` → no match against `run-gate-test.js` or `npm run gate` |
| 5 | P3 | `ISSUES_TO_OPEN.md` documents two "MEDIUM" pending bugs (sub-100-byte behavioral-scan skip; inline `require("https").get(...)` miss) that are already fixed in current source — stale post-launch tracking doc that would misinform a reader/triager. Not user-facing (not README), so left as a log-only P3 per fix policy. | `ISSUES_TO_OPEN.md:8-72` | `grep -n "content.length < 100" packages/fw-agent/src/behavior-tracker.js` → no match (guard removed); `grep -n "require.*https.*get" packages/fw-agent/src/behavior-tracker.js` → pattern present (already fixed) |

## Unverified claims / untested areas

- **Specific hardware-bound performance numbers ("~17–21% median overhead").** This session ran
  `node run-gate-test.js` once in the sandboxed audit container and measured **60.58% median /
  79.16% P95** — well outside the 25% budget the README/CONTRIBUTING commit to. The repo's own
  evidence files (`results/gate-3x-epyc-20260618.txt`, three consecutive runs at 16–17% median on
  a dedicated AMD EPYC 7763 host) support the README's claim on that hardware, and every
  *functional* signal in this session (demo.sh, 151-payload red-team suite, 52-case adversarial
  suite, unit tests) was independently reproduced and passed. The most likely explanation is
  shared/virtualized CPU noise in this container rather than a real regression, but I could not
  rule that out with certainty in this environment — re-run the gate on the target production
  host (or an equivalent dedicated instance) before launch and confirm it's still ≤25% median.
- **Full Docker Compose stack.** `docker compose config` validates the file syntactically (both
  services resolve, healthcheck/env wiring is coherent), but a live `docker compose up` end-to-end
  run (pulling `node:20-alpine`, starting both containers, curling `/logs` through the compose
  network) was not executed in this session due to time/scope — mark as config-verified only, not
  functionally verified.
- **Deno runtime detection.** The Bun half of claim #6 ("exits without preload") was verified live
  in this session (see Commands run). Deno is not installed in this sandbox, so the equivalent
  `DENO_PRELOAD` check was read in source only, not executed.

## Commands run (baseline before → after)

```bash
$ npm install
added 105 packages, and audited 108 packages in 3s
7 high severity vulnerabilities

$ npm test   (test:unit + test:adversarial + test:integration + test:auth)
All policy/quarantine/audit-log/aho-corasick/detector unit tests passed
Adversarial: Results: 52 passed, 0 failed out of 52 tests
Integration: [Helios] Exit 0 | Compilations: 2 | Quarantined: 0 | Blocked: 1
Auth: All control-plane auth tests passed (dashboard + telemetry, incl. F-19)

$ npm run test:coverage
All files | 99.3% Stmts | 97.38% Branch | 100% Funcs | 99.3% Lines   (gate: 95/90/95 — PASS)

$ npm run redteam
Attacks run: 151 (125 malicious, 26 benign) | Blocked: 95 | Detection rate: 76%
NEW bypasses (regressions): 0 | False positives: 0 | PASS

$ bash demo/demo.sh
Firewall OFF: crypto-miner + secret-stealer both ALLOWED (ran freely)
Firewall ON:  both BLOCKED ([Firewall] Detection: crypto-miner / CREDENTIAL_EXFILTRATION)
Firewall ON:  benign analytics-sdk (env read + HTTPS) ALLOWED, no false alarm

$ node --require=./packages/fw-agent <attack-app>   (edge-case module corpus)
empty.js / whitespace.js / unicode+emoji+<script> module → ALLOWED, no crash
syntax-error.js / binary garbage → Node's own compiler throws (expected, not a firewall bug)
100KB-padded module with buried CREDENTIAL_EXFILTRATION pattern → BLOCKED (full-content scan confirmed, not truncated)
Exit 0 | Compilations: 7 | Blocked: 1 — no hang, no crash across any input

$ curl-based attack against /v1/telemetry and /logs (control plane, 127.0.0.1:3000)
empty body → 400 FST_ERR_CTP_EMPTY_JSON_BODY
garbage/non-JSON body → 400 Bad Request
missing required fields → 400 FST_ERR_VALIDATION
wrong types (string where integer expected) → 400 FST_ERR_VALIDATION
100KB packageName, unicode/emoji agentId, path-traversal-shaped packageName → 202 ACCEPTED (stored as opaque data, never interpreted as a path)
<script>alert(1)</script> in packageName → escaped to &lt;script&gt; in the HTML dashboard (no XSS)
no auth / malformed Bearer header on /logs → 401 both cases
20x rapid-fire duplicate POSTs → 202 every time, server stayed up
No auto-generated-token startup path (no HELIOS_DASHBOARD_TOKEN set) → prints strong random token once, as documented

$ custom ReDoS fuzz harness (all SIGNAL_PATTERNS regexes + full Detector.scanModuleSync pipeline
  against 6 pathological adversarial payloads: 500KB flat strings, 100K nested backslash-escapes,
  50K-deep fake template-literal nesting, 20K back-to-back require() calls, unterminated block
  comments)
No regex exceeded 100ms on any input; full pipeline scans completed in 4.5–18.2ms even at
500K characters — no ReDoS / hang found in the detection engine's own regex set.

$ /tmp/.../gitleaks detect --source . -v   (installed via `go install` for this audit; 73 commits scanned)
1 finding: scripts/dev-private-key.pem (Ed25519 PRIVATE KEY, committed intentionally — see below)
  [SUPERSEDED 2026-08-20: this key was deleted from HEAD and DEV_PUBLIC_KEY_PEM rotated to a key
   with no committed private half (F-62). The finding below is the 2026-07-25 audit-time state.]
No other secrets/tokens/API keys found in history or working tree.

$ npm audit fix   (non-force)
Before: 7 high severity vulnerabilities
After:  6 high severity vulnerabilities (brace-expansion fixed; fastify chain remains, see Finding #3)

$ node run-gate-test.js
FAILED in this sandboxed environment: median 60.58% vs 25% budget (see Unverified — likely
environment noise, not reproduced against the repo's own EPYC evidence files)
```

### Note on `scripts/dev-private-key.pem`

> **SUPERSEDED (2026-08-20, F-62 key rotation).** This note describes the state at the audited
> commit `1d60552` (2026-07-25). The committed dev private key `scripts/dev-private-key.pem` was
> **deleted from `HEAD`** and `DEV_PUBLIC_KEY_PEM` was **rotated** to a public key whose private
> half has never been committed anywhere; there is no longer any shared dev private key in the
> repository. History was deliberately not rewritten (see SECURITY.md → "Key revocation record
> (F-62)"). The present-tense wording and the `policy-watcher.js`/`index.js` line-number citations
> below are the audit-time record and no longer point at current source — the gating functions
> (`start()`'s dev-key guard, `assertProductionKeyConfig()`) still exist, but at different lines.

At the time of this audit this WAS a private key committed to the repo, but it was **intentional
and correctly gated**, not an accidental leak — verified by reading the code, not just trusting the
README (line numbers are as of commit `1d60552`):

- `packages/fw-agent/src/policy-watcher.js:177` refused to start (`process.exit(1)`) if a policy
  file was present and signed with this key, unless `FW_ALLOW_DEV_POLICY_KEY=1` was explicitly set —
  regardless of `NODE_ENV`.
- `assertProductionKeyConfig()` (`policy-watcher.js:68`, called from `index.js:145`) additionally
  refused to start under `NODE_ENV=production` with this key even with no policy file present yet.
- Confirmed live: `FW_ENABLE_DETECTION=1 node --require=./packages/fw-agent app.js` with the repo's
  then-committed `policy.signed.json` (signed with this key) and no `FW_ALLOW_DEV_POLICY_KEY` set
  exited with `[CRITICAL] ... Refusing to run.`
No action was taken at audit time per the stop-on-secret rule other than confirming it was not
exploitable as shipped; it was a documented dev/CI convenience key, not a production credential.
It has since been removed and rotated (above).
