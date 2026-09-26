---
name: zp-validate
description: "Adversarially verify a finding by trying to refute it. Usage: /zp-validate"
---

# /zp-validate

Try to **refute** the current finding. Default stance: it is wrong.

Work the checks in `skills/zp-triage/SKILL.md` under "Two adversarial gates", in this order,
because the first one kills the most findings:

1. Is the data actually private? Check logged out, in a clean session.
2. Is this the intended feature? Read the docs and the permission model.
3. Does the impact match the claim, or was the last step assumed?
4. Can you reproduce it independently - rebuilt from scratch, second stack for High/Critical?
5. Is it tooling? Cache, sticky session, load balancer, jitter, soft-404, wildcard DNS.
6. Is the severity provable, vector by vector?
7. Is it a duplicate, or a bypass of a deployed fix (which is a new bug)?

Verdict: SURVIVES / DOWNGRADE / REFUTED. **When uncertain, REFUTED** - a false positive costs
signal, a false negative costs one more round.

For a heavier pass, dispatch the `zp-verifier` agent, which has no Write tool by design.
