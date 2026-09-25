---
name: zp-operating-rules
description: The three ZeroProtocol laws that govern every authorized security test - scope gate, no theoretical findings, evidence before claim.
metadata:
  type: feedback
---

ZeroProtocol governs authorized security testing in this project. Three laws, in order:

1. **No packet without a confirmed scope.** Run `zp-scope check <target>` and obey the exit
   code: 0 allow, 1 deny, 3 unconfirmed, 4 no scope file. An error is a deny. Never hand-roll
   the check, never reuse an allow for a different host. Passive recon (CT logs, archives,
   search engines) is permitted while unconfirmed because it queries third parties, not the
   target.
2. **No theoretical findings.** The only question: can an attacker do this right now, against a
   user who took no unusual action, causing nameable harm? "Could theoretically", self-XSS,
   dead code and lone missing headers are killed on sight.
3. **Evidence before claim.** Reproduce before calling anything confirmed; two independent
   stacks for High and Critical; redact at capture time, not as cleanup.

**Why:** a model that merely intends to stay in scope drifts after forty tool calls, and a weak
report costs reputation that is the only currency in bug bounty.

**How to apply:** load the `zeroprotocol` skill when a target is given; it owns the phase
pipeline and routes to the thirty zp-* skills. Never auto-submit a report - a human approves
every submission. See [[zp-stop-points]] and [[zp-workspace]].
