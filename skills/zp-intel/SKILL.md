---
name: zp-intel
description: ZeroProtocol prior-art and calibration layer over 14,900+ publicly disclosed bug bounty reports plus measured base rates for 68 vulnerability classes. Use before hunting a program to learn what actually gets found and paid there, before choosing a class to see which classes are rising or dying and how accepted reports were framed, and always at triage time to check whether a finding is a duplicate. Wraps the zp-intel index, which holds public metadata, report links and derived counts only. Exit code 8 from a dedup check means likely duplicate.
---

# zp-intel - hunt where the bugs already were

**Phase:** 0 (program priors) and **7** (dedup, mandatory) | **Gate:** none. The index is local
and the links are public; nothing here touches the target.

Bug bounty compounds through prior art. The same programs keep shipping the same classes of
mistake, and the reports they disclosed tell you which. Two minutes here reshapes a whole session,
and duplicates are the single largest waste of effort in this game.

---

## What the index is

`intel/hackerone-reports.csv` - **14,972 publicly disclosed HackerOne reports**, 428 programs,
211 weakness types, 3,216 with a disclosed bounty (median $500, max $50,000).

It stores **public metadata only**: program, title, report URL, upvotes, bounty, weakness. No
report bodies are vendored - follow the link to read one. Provenance and licensing in
`intel/README.md`.

```bash
zp-intel stats          # what is in it
zp-intel update         # refresh from upstream
```

**Which tool for which question.** `zp-intel` is about *this program and this finding*: has it
been reported, what pays here, what are the base rates. **`zp-corpus` is the library** - 138,400
public write-ups, for *how has this class, CVE or stack been written up before*. Reach for
`zp-corpus` when you want to read how someone found a bug; reach for `zp-intel` when you want to
know whether yours is a duplicate or worth writing up.

---

## The calibration layer - `zp-intel priors`

The index tells you about **one program**. `intel/class-priors.csv` tells you about **the
field**: 68 weakness classes measured over 12,768 labelled disclosed HackerOne reports
across 379 programs, 2013-2026, each mapped to the skill that owns it.

```bash
zp-intel priors                      # every class, by volume
zp-intel priors --sort trend         # what is rising and what is dying
zp-intel priors --sort bounty        # which classes actually get paid
zp-intel priors --skill authz        # the classes one skill owns
zp-intel priors --gaps               # families no skill in this pack covers
```

Use it twice: at **phase 0** to choose what to hunt, and at **phase 7** to sanity-check the
severity you are about to claim.

**What the measurement says.** Access control has become the centre of the field. "Improper
Access Control - Generic" went from 3.3% of labelled disclosures in 2014-2020 to 11.0% in
2023-2026 - the largest rise of any class - and IDOR from 1.7% to 4.5%. Together with business
logic that is the highest-yield third of the queue. Meanwhile CSRF fell from 5.0% to 1.7%,
clickjacking from 1.4% to 0.1%, and open redirect from 2.9% to 1.2%.

| Read it as | Not as |
|---|---|
| a rising class is where triage is currently accepting impact | proof a falling class is unexploitable |
| a low `paid` rate means this class needs a **stronger impact story**, not that it is worthless | a probability your report pays |
| `paid` ranks classes against each other | an absolute rate - undisclosed bounties make every figure a lower bound |
| a gap family is outside this pack's scope | a family nobody pays for - memory safety pays best of all, on OSS programs |

**The honest caveats, because a number in a table invites over-trust.** Disclosure is not a
census: programs choose what to disclose and most reports are never disclosed. The two windows
differ in size. Some of the collapse in `XSS - Generic` is HackerOne relabelling to
reflected/stored/DOM rather than XSS disappearing. Severity is the disclosure's own label, not a
recomputed CVSS. Full method and limits in `intel/README.md`.

---

## Phase 0 - program priors, before you pick a target

```bash
zp-intel program shopify
```

Returns what gets found on that program and the highest-value disclosures. Read it for:

| Signal | What to do with it |
|---|---|
| a class appears repeatedly | the codebase has a *pattern* of it - look for the siblings nobody reported |
| a class is absent entirely | either well-defended, or unhunted. Check the policy before assuming the second |
| bounty range | tells you whether a Medium is worth writing up here |
| recurring endpoints or subdomains | the surface their own researchers keep returning to |
| recent disclosures | what triage is currently accepting |

The most useful move is the **patch-bypass hunt**: take a disclosed report, find the endpoint,
and check whether the fix holds. A bypass of a deployed fix is a *new* bug, it is never a
duplicate, and it is often the fastest high-value finding on a picked-over program.

A program with no disclosed reports is **not evidence it is unpicked** - most programs never
disclose. Say that honestly rather than assuming open ground.

---

## Phase 5 - learn the class before you hunt it

```bash
zp-intel class idor --min-bounty 500 --limit 15
zp-intel class proto-pollution
zp-intel search "password reset" host
```

`class` understands ZeroProtocol's own names (`idor`, `ssrf`, `proto-pollution`, `open-redirect`,
`business-logic`, `llm`, …) and maps them onto the corpus vocabulary, which uses CWE-ish weakness
names instead.

Read the **titles** of reports that paid well. They teach two things at once: which variants of
the class are actually valued, and the title formula triage responds to. Then open two or three
of the highest-bounty ones and read how impact was argued - that is the framing `zp-report` wants.

---

## Phase 7 - dedup, and this one is mandatory

```bash
zp-intel dedup shopify idor orders customer
```

| Exit | Meaning | What you do |
|---|---|---|
| **8** | at least one indexed report shares **>= 50%** of your terms | **read them before writing anything** |
| 0 | no report crossed that threshold | **read the output anyway** - reports below 50% still print as ` related `, and so does a program with nothing indexed |

The exit code is a threshold, not a verdict: anything branching on it alone will call a
screen full of adjacent prior art "clean". Read the lines.

A likely-duplicate hit is not automatically fatal. Ask the question that matters: **is yours
materially different?** A different endpoint, a different parameter, a higher impact, or a bypass
of the fix they shipped are all new findings. If it is genuinely the same bug on the same
endpoint, kill it - `zp-triage` question 6 exists for this.

When your finding *is* adjacent to a prior report, link that report in your submission and say
explicitly how yours differs. Triagers reward that; they have to do the search otherwise.

**This index is one source, not the whole check.** `zp-triage` also requires: the program's own
hacktivity page, its CHANGELOG and release notes, `security.txt`, the issue tracker, published
audits, and a web search. Most reports are never disclosed, so a clean `zp-intel` result is
encouraging rather than conclusive.

---

## Feeding it back

The part of bug bounty that actually compounds is your own outcome data. After every submission,
record the result in `.zeroprotocol/submissions.md` - **including N/A and duplicate outcomes**,
which are the most informative - and write the durable lesson into your memory notes:

```
class priors      which classes this program pays for, and which it rejects
framing           the wording that got accepted, and the wording that got downgraded
surface           the endpoints and subdomains that keep producing
```

Next engagement on the same program starts from that instead of from zero.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| `dedup` returns exit 8 and the report is the same bug, same endpoint | **kill.** Do not submit |
| exit 8 but yours bypasses the fix they shipped | **new bug** - submit, and link the prior report |
| exit 8 but a different endpoint or a materially higher impact | submit, state the difference explicitly |
| exit 0 | proceed, and finish the rest of the `zp-triage` dedup sources |
| no reports indexed for the program | inconclusive. Not a green light |
| a class dominates the program's history | high-prior area - hunt the siblings, not the reported instance |
| the disclosed report is years old | check whether the endpoint still exists before assuming anything |

---

## Pitfalls

- **Skipping dedup because the finding feels novel.** It is thirty seconds against thirty minutes of writing.
- **Treating an empty index result as proof of novelty.** Most reports are never disclosed.
- **Re-reporting a disclosed bug verbatim.** It is an instant duplicate and it costs signal.
- **Hunting only the exact endpoint from a disclosure** instead of the sibling surface around it.
- **Ignoring the bounty column** and writing a long report for a class that pays nothing on that program.
- **Copying a disclosed report's wording** into your own submission. Learn the framing; write your own.
- **Forgetting to record N/A and duplicate outcomes.** They are the data that improves the next session.
- **Assuming a years-old disclosure still reflects the current app.**

---

## Hand off to

Priors -> the router's phase 0 budget and class selection.
Class technique -> the matching hunter skill.
Dedup verdict -> `zp-triage` (question 6), then `zp-report`, which should link any adjacent
prior disclosure.

Sources: `intel/hackerone-reports.csv` from `reddelexc/hackerone-reports`;
`intel/class-priors.csv` derived from a 221,091-write-up corpus of public disclosures across 126
sources, deduplicated to 109,885 unique reports of which 12,768 carry a class label. Method, licensing and the honest limits
of both are in `intel/README.md`. Neither file carries anyone's report text.
