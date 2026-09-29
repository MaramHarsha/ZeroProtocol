---
name: zp-corpus
description: ZeroProtocol offline library of 138,400 public security write-ups - HackerOne disclosures, vendor advisories, researcher blogs, CTF and audit reports, Exploit-DB and the GitHub Advisory Database. Use before hunting a class to find how real bugs of that shape were found, when a CVE or version banner needs prior art, when a target's stack or program needs background reading, or whenever the question is "has anyone written about this before". Ships with the pack so nothing has to be scraped. Holds titles and source links only - you fetch the URL to read the write-up.
---

# zp-corpus - the card catalogue, not the books

**Phase:** 0, 5 and 7 | **Gate:** **none.** The index is local and every link is public. Nothing
here touches the target, so it runs before a scope is confirmed. (For anything that *does* send
traffic, `zp-scope check <target>` must exit 0 — 1 refuse · 3 stop · 4 stop.)

138,400 distinct write-ups from 97 sources, 1995 to today, shipped in the repo. **Nobody using
this pack needs to scrape anything.**

---

## The two-step, and why it is two steps

```bash
zp-corpus search idor graphql --limit 10     # 1. find which write-up to read
```

Then **fetch the URL** of the one that looks right and read it.

The index holds a title and a link per write-up and **no body text**. That is a licensing
decision, not an oversight: 97 sources means 97 licences, and the prose belongs to the
researchers who wrote it. Titles and URLs are factual metadata about public disclosures; the
text is theirs.

**A search result is a reading list, not an answer.** The single worst failure mode of this
skill is reading a title, inferring the technique, and reporting the inference as fact. Titles
compress and titles mislead. If you did not fetch the page, you do not know what it says.

---

## Searching

```bash
zp-corpus search <terms...>              # all terms must appear; title hits rank first
zp-corpus search idor --any graphql      # match ANY term instead
zp-corpus search --class ssrf --since 2023
zp-corpus search --cve CVE-2024-3400     # everything indexed mentioning one CVE
zp-corpus search --program shopify --bounty
zp-corpus search --source portswigger-research
zp-corpus show ajaysenr-h1:984965        # one record, and the URL to fetch
zp-corpus sources                        # the 97 sources and what each contributes
zp-corpus stats                          # what is in the index, and what is missing from it
```

Every subcommand takes `--json`. Branch on the exit code, never on the prose:

| Exit | Meaning | What you do |
|---|---|---|
| 0 | results | read the titles, pick two or three, fetch them |
| 4 | ran fine, matched nothing | say so. Widen: fewer terms, `--any`, drop `--since`, try `--class` |
| 2 | index not installed | **say the capability is unavailable.** Do not answer from memory and call it prior art |
| 1 | usage or runtime error | fix the invocation |

`--class` understands ZeroProtocol's own names (`idor`, `ssrf`, `proto-pollution`,
`memory-safety`, `business-logic`, …) and maps them onto the weakness vocabulary the sources
use. Use it when a bare term search is too noisy.

---

## When to reach for it

| Moment | Query | What you are looking for |
|---|---|---|
| **Phase 0**, picking a target | `--program <handle>` | what has been written up about this program, by anyone, not just on HackerOne |
| **Phase 0**, picking a class | `--class <c> --since 2023` | how this class is currently being found, in the researchers' own words |
| **Phase 3**, a version banner | `--cve CVE-…` or the product name | is there a public write-up for this exact build |
| **Phase 5**, before a hunter | `--class <c> <stack term>` | this class *on this stack* — `--class ssti laravel` beats either alone |
| **Phase 5**, stuck | the exact parameter or endpoint shape | someone has usually met this control before |
| **Phase 7**, triage | the endpoint plus the class | prior art you must cite, or a duplicate you must kill |

Two minutes of reading before a hunt reshapes it. This is the cheapest step in the whole
pipeline and the one most often skipped.

---

## Reading what you find

Fetch the URL, then take from it the things a title cannot carry:

- the **precondition** — what had to be true about the target for the bug to exist
- the **control that was bypassed**, and the shape of the bypass
- what the researcher tried that **did not** work, which is usually the most valuable paragraph
  and never appears in a summary
- how **impact was argued**, which is what `zp-report` needs
- whether the fix is described, so you can check whether it holds today

A write-up about a deployed fix is a lead: **a bypass of a shipped fix is a new bug, never a
duplicate.** That is often the fastest high-value finding on a picked-over program.

---

## What the index does not tell you

Stating these plainly is the difference between prior art and false confidence.

| Limit | Consequence |
|---|---|
| titles and links only | you must fetch to know anything. See above |
| no `severity` field | sources label severity incompatibly, so it is not indexed. Read the URL |
| 25,636 records have **no date** | their source gave only a scrape time. `--since` excludes them |
| only 12,713 carry a `weakness` label | a bare-term search reaches far more than `--class` does |
| `cves` records a *mention* | not a claim the write-up is about that CVE |
| `bounty` is a lower bound | absent does not mean unpaid; amounts are usually withheld |
| 97 sources, not the whole field | **a zero result never means nobody has written about it** |
| links rot | a 404 is expected on older records; try the Wayback Machine |

Full field-by-field contract, including why severity is absent: `intel/SCHEMA.md`.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| a write-up describes your exact bug on your exact endpoint | likely duplicate → `zp-intel dedup`, then `zp-triage` question 6 |
| it describes the bug and the **fix** | test whether the fix holds. A bypass is a new bug |
| it describes the class on a sibling endpoint | strong lead. Hunt the sibling the author did not |
| a title looks perfect but the page is gone | do not cite it. An inaccessible source is not evidence |
| you inferred the technique from the title alone | **not a finding.** Fetch it or drop it |
| nothing matched | record it and move on. Absence of prior art is not absence of the bug |

---

## Pitfalls

- **Treating a title as the write-up.** The one that matters most.
- **Searching one term.** `idor` returns 677 records; `idor graphql` returns 12 useful ones.
- **Forgetting `--class`** when the bare term is drowning in noise.
- **Using `--since` and not knowing it drops the 25,636 undated records.**
- **Reading a zero result as novelty.** It means nothing indexed matched.
- **Citing a rotted link** in a report without checking it resolves.
- **Mixing counts with `class-priors.csv`.** Different dedup, different denominator — see
  `intel/SCHEMA.md`.
- **Copying a write-up's wording** into your own report. Learn the framing, write your own.

---

## Hand off to

Program and class priors → the router's phase 0 budget and class selection, and `zp-intel priors`
for the measured base rates.
A technique you have now *read* → the matching hunter skill.
A possible duplicate → `zp-intel dedup`, then `zp-triage`.
Prior art to cite → `zp-report`, which should link it and say how yours differs.

Provenance, licensing and the full data contract: `intel/SCHEMA.md`, `intel/README.md` and
`NOTICE.md`. Rebuild the index with `scripts/build_writeups_index.py --corpus <dir>`.
