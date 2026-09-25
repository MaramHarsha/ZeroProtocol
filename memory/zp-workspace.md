---
name: zp-workspace
description: The .zeroprotocol/ engagement workspace layout and the rule that state lives in files, not in the session.
metadata:
  type: project
---

Every ZeroProtocol engagement keeps its state in `.zeroprotocol/` in the working directory,
created by `zp-init`:

```
scope.yaml      the gate - the only source of truth for what may be touched
notes.md        line 1 is the MODE (bug-bounty|pentest|own-asset); then objective, budget, log
queue.md        ranked surface: P1 / P2 / blocked / chain-pending / killed
surface/        hosts.txt urls.txt live.jsonl endpoints.txt tech.md js-findings.md
coverage/       per host+class: attempts, variants, encodings, blocker, not-applicable reasons
evidence/       redacted at capture, gitignored
findings/       one report-shaped file per finding
submissions.md  what was sent where, and the outcome - including N/A and duplicate
```

**Why:** a long session drifts and a file does not. A resumed session must not have to
rediscover context, and "exhausted" is only meaningful if coverage was written down as it
happened.

**How to apply:** write artifacts as you go, never at the end. On resume, read `notes.md` and
`queue.md` before touching the target. Record KILL verdicts in `coverage/` so the same lead is
not re-tested. Record platform outcomes in `submissions.md` - class priors are the part of bug
bounty that compounds. See [[zp-operating-rules]].
