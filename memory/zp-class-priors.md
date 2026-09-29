---
name: zp-class-priors
description: Measured base rates for vulnerability classes over 12,768 labelled publicly disclosed reports - which classes are rising, which get paid, and how to read the numbers without over-trusting them.
metadata:
  type: reference
---

ZeroProtocol ships a measured calibration layer, not just a checklist. `intel/class-priors.csv`
holds 68 weakness classes derived from 12,768 labelled publicly disclosed HackerOne reports across
379 programs, 2013-2026 (deduplicated out of a 221,091-document corpus). Query it with
`zp-intel priors` (`--sort trend`, `--sort bounty`, `--gaps`, `--skill <name>`). Rebuild it with
`scripts/build_class_priors.py --corpus <dir>`.

**The headline: the field moved to access control.** `Improper Access Control` went from 3.3% of
labelled disclosures in 2014-2020 to 11.0% in 2023-2026 - the largest rise of any class, and the
largest single class at 734 reports. IDOR went 1.7% -> 4.5%, business logic 2.3% -> 3.9%.
Over the same span CSRF fell 5.0% -> 1.7%, open redirect 2.9% -> 1.2%, clickjacking 1.4% -> 0.1%.

**Two numbers worth remembering at triage time.** Stored XSS discloses a bounty 58% of the time
against 39% for reflected - so a reflected finding is worth ten more minutes hunting its stored
sibling. And `Insufficient Logging` has 24 disclosed reports and **zero** disclosed bounties; it
is pentest hygiene, never a bounty finding.

**Why it exists:** a class weight encodes *impact* - what a bug is worth if it is there. It says
nothing about *likelihood* - whether the field is still finding and getting paid for that class.
The queue needs both, and without measurement the second one is guesswork.

**How to apply:**
- Phase 0: `zp-intel priors --sort trend` before choosing classes; +10 to the queue score for a
  rising class, -10 for a falling one.
- Phase 7: run it on the class you are about to report. A low disclosed-bounty rate means the
  bar is the **impact story**, not the payload - which is `zp-triage`'s calibration section.
- Never let a number become the verdict. Disclosure is not a census: programs choose what to
  disclose, most reports are never disclosed, the bounty rate is a lower bound because amounts
  are often withheld, the two trend windows differ in size, and some of the apparent collapse in
  generic XSS is HackerOne relabelling to reflected/stored/DOM. Evidence decides; this only sets
  the prior. Full limits in `intel/README.md`.
- **There is no severity column and there must not be one.** Measured across this corpus,
  severity labels are not comparable between sources - one labelled 5,313 of 12,618 reports
  "critical" and only 66 "high", another used P1-P5 - so any aggregate flips with file read
  order. A first version of this file shipped such a column before the sources were compared.
  Score severity in the program's own system.
- A falling class is not a dead class. It needs a stronger impact story, or a chain.

**Known coverage gap, stated rather than hidden:** the memory-safety family (723 reports, the
highest disclosed-bounty rates in the set - 82% for memory corruption) has **no** zp-* skill.
Those reports come from the Internet Bug Bounty, curl, Node.js and similar open-source C/C++
programs, and the work is fuzzing and crash triage, not a web pipeline. `zp-intel priors --gaps`
lists it. If the target is a native codebase, say this pack does not cover it.

See [[zp-operating-rules]], [[zp-stop-points]], [[zp-workspace]].
