---
name: zp-hunt
description: "Run the full ZeroProtocol pipeline against a target - scope gate, recon, ranked surface, class hunt, proof, triage, report draft. Usage: /zp-hunt target.com"
---

# /zp-hunt

Load `skills/zeroprotocol/SKILL.md` and run its pipeline against **$ARGUMENTS**.

Do not improvise a pipeline. The router owns phase order, the ranking formula and the dispatch
table; follow it.

Start at **phase 0**: set the engagement mode on line 1 of `.zeroprotocol/notes.md`, declare one
objective, pick one or two classes, and allocate the budget. Then phase 1, the scope gate.

Passive recon may start while the scope is unconfirmed. **Nothing** that touches the target runs
until `zp-scope check` returns 0.

Report at the end with: what was covered, what was found, what was killed and why, and what you
did not test. An evidenced "nothing exploitable here" is a valid result.
