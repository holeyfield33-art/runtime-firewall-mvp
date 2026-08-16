# State Machine

The `.agent/` control plane models exactly one state machine per phase run. A "run" is a
directory under `.agent/runs/<run-id>/` created fresh for each attempt at a directive.

```
DIRECTIVE
   |
   v
A1_WRITE            (boundary-engineer implements the scoped change)
   |
   v
CHECKPOINT          (checkpoint.js create <runDir> a1-candidate)
   |
   v
A2_VERIFY           (red-team-verifier checks out candidate_sha fresh, attacks it)
   |
   +--> FAIL --> A1_REWORK --> CHECKPOINT --> A2_VERIFY   (loop)
   |
   +--> PASS
         |
         v
      A3_GATE        (release-warden.js evaluate, deterministic only)
         |
         +--> BLOCK  --> A1_REWORK --> CHECKPOINT --> A2_VERIFY   (loop)
         |
         +--> FREEZE --> STOP. No further automated action. Human required.
         |
         +--> PASS
               |
               v
         RELEASE_CANDIDATE
               |
               +--------------------------+
               |                          |
               v                          v
         HUMAN_APPROVAL              A4_DOCS   (docs-scribe drafts CHANGELOG.md / docs/*.md;
   (out of scope for automation --         re-validated by release-warden.js on next run;
    see repo root release procedure)       out-of-allowlist changed_files => FREEZE)
```

`A4_DOCS` is not on the critical path to `RELEASE_CANDIDATE` — it runs after that state is
already reached and never gates `HUMAN_APPROVAL`. It exists so the changelog isn't hand-written
after the fact from memory; every claim it writes must trace back to a field already present in
`engineer-receipt.json` or `warden-receipt.json`.

## Artifacts per state

| State | Artifact written | Script |
|---|---|---|
| `A1_WRITE` | `engineer-receipt.json` | (agent-authored, schema in `contracts/engineer-receipt.schema.json`) |
| `CHECKPOINT` (post-A1) | `checkpoints.json` entry `label: "a1-candidate"` | `.agent/scripts/checkpoint.js create <runDir> a1-candidate` |
| `A2_VERIFY` (start) | `checkpoints.json` entry `label: "a2-verify-start"` | `.agent/scripts/checkpoint.js create <runDir> a2-verify-start` |
| `A2_VERIFY` (work) | `verifier-receipt.json`, `evidence/*.json` | (agent-authored + `.agent/scripts/collect-evidence.js`) |
| `A2_VERIFY` (end) | `checkpoints.json` entry `label: "a2-verify-end"` | `.agent/scripts/checkpoint.js create <runDir> a2-verify-end` |
| `A3_GATE` | `warden-receipt.json` | `.agent/scripts/release-warden.js <runDir> <phaseId>` |
| `A4_DOCS` (optional, post-`RELEASE_CANDIDATE`) | `docs-receipt.json` | (agent-authored, schema in `contracts/docs-receipt.schema.json`; re-validated by a subsequent `.agent/scripts/release-warden.js` run) |

## Invariants enforced mechanically, not by agent honesty

1. **Candidate SHA immutability.** `a2-verify-start` and `a2-verify-end` checkpoints must record
   the identical git SHA. If they differ, `release-warden.js` FREEZEs the run — this is exactly
   the "Agent 1 changed the code mid-verification" attack.
2. **SHA agreement across artifacts.** `engineer-receipt.candidate_sha`,
   `verifier-receipt.candidate_sha`, and every checkpoint SHA must be the same value.
3. **No self-promotion.** `release-warden.js` is a separate deterministic script. Nothing in
   `A1_WRITE` or `A2_VERIFY` can set `warden-receipt.status`; only `release-warden.js`'s own
   evaluation logic writes that file.
4. **Evidence must exist on disk.** Any evidence ID cited in a receipt must appear in
   `evidence/index.json`, written only by `collect-evidence.js` after actually running a command.

## Loop termination

`A1_REWORK` re-enters `A1_WRITE` in the *same* run directory but engineer must bump
`candidate_sha` (a real new commit) and a fresh `a1-candidate` checkpoint. There is no bound on
rework iterations enforced by tooling — that is a human/process call — but every iteration is
fully recorded in `checkpoints.json`, so the run directory itself is the audit trail.
