# intel/ — disclosed-report index

## What is here

`hackerone-reports.csv` — an index of **publicly disclosed HackerOne reports**.

```
program,title,link,upvotes,bounty,vuln_type
```

14,972 rows · 428 programs · 211 weakness types · 3,216 with a disclosed bounty.

Query it with `zp-intel` (see `skills/zp-intel/SKILL.md`):

```bash
zp-intel stats
zp-intel program <name>                 # priors: what gets found and paid there
zp-intel class idor --min-bounty 500    # how accepted reports of a class were framed
zp-intel dedup <program> <terms...>     # exit 8 == likely duplicate
zp-intel update                         # refresh from upstream
```

## What is deliberately NOT here

**No report bodies.** This index holds only factual metadata and the public URL of each report.
It does not vendor, mirror or redistribute the text, screenshots or proof-of-concept content of
anyone's report — those belong to their authors and the programs that disclosed them. To read a
report, follow its link to hackerone.com.

That is both the correct thing to do and the practical one: the metadata is what makes dedup and
prior-art lookup fast, and it keeps this repository small enough to clone.

**No private or undisclosed data.** Every row corresponds to a report the program chose to
disclose publicly.

## Provenance

Compiled from [`reddelexc/hackerone-reports`](https://github.com/reddelexc/hackerone-reports),
which fetches and ranks publicly disclosed reports from HackerOne's own hacktivity. Upstream:

```
https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv
```

`zp-intel update` re-fetches from that URL. It validates the download parses as CSV and refuses
to replace the index with a file containing fewer than 1,000 rows, so a failed or truncated fetch
cannot quietly destroy your local copy.

The underlying report titles and URLs are facts about public disclosures. Credit for compiling
and maintaining the upstream dataset goes to its author.

## Coverage, honestly

This index is **one dedup source, not the whole check**. Most bug bounty reports are never
disclosed, so an empty result means "nothing found here", never "nobody has reported this".
`zp-triage` requires the other sources too: the program's own hacktivity page, its CHANGELOG and
release notes, `security.txt`, the issue tracker, published audits, and a plain web search.

Disclosures also age. A report from several years ago may describe an endpoint that no longer
exists — or a fix whose bypass is still sitting there, which is usually the more interesting
case.
