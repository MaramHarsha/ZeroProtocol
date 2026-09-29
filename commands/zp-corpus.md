---
name: zp-corpus
description: "Search 138,400 shipped public security write-ups by title, class, CVE or program, then fetch the URL to read one. Usage: /zp-corpus idor graphql | /zp-corpus --class ssrf --since 2023 | /zp-corpus --cve CVE-2024-3400"
---

# /zp-corpus

Load `skills/zp-corpus/SKILL.md`. Arguments: **$ARGUMENTS**

```bash
zp-corpus search <terms...>                  # all terms; title matches rank first
zp-corpus search --class ssrf --since 2023   # by ZeroProtocol class name
zp-corpus search --cve CVE-2024-3400         # everything indexed mentioning a CVE
zp-corpus search --program shopify --bounty  # a program, paid disclosures only
zp-corpus show <id>                          # one record and the URL to fetch
zp-corpus sources                            # the 97 sources and their counts
zp-corpus stats                              # what is in the index, and what is missing
```

Add `--json` for machine output. Exit codes: **0** results · **1** usage error ·
**2** index not installed (say the capability is unavailable — do not answer from memory) ·
**4** ran fine and matched nothing (an answer, not a failure).

**Two steps, always.** The index holds titles and source links, never body text — 97 sources
means 97 licences and the prose belongs to its authors. So: search to find which write-up to
read, then **fetch that URL and read it.**

A result is a reading list, not an answer. Inferring a technique from a title and reporting it
as fact is the one failure mode this skill exists to prevent.
