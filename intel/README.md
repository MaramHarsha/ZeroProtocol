# intel/ — disclosed-report index and measured class priors

Two files, two jobs. `hackerone-reports.csv` answers *has this specific bug been reported on
this program* (dedup and prior art). `class-priors.csv` answers *which classes are actually
being disclosed now, and which ones get closed without a bounty* (calibration).

## class-priors.csv — the calibration layer

```
weakness,zp_skill,reports,disclosed_bounty,bounty_pct,
share_2014_2020_pct,share_2023_2026_pct,trend_pts
```

68 weakness classes, each mapped to the `zp-*` skill that owns it. Query it with
`zp-intel priors` (`--sort trend`, `--sort bounty`, `--gaps`, `--skill authz`).

**How it was measured.** A local corpus of 221,091 publicly disclosed vulnerability write-ups
from 126 public sources (HackerOne disclosures, vendor advisories, researcher blogs, CTF and
audit reports) was deduplicated by report id across the overlapping sources, giving 109,885
unique reports. Of those, **12,768 carry a weakness label, across 379 programs, 2013-2026** —
and those labelled reports are the entire basis of this table. Classes with fewer than 15
reports were dropped as too thin to carry a rate.

Regenerate it with `python3 scripts/build_class_priors.py --corpus <dir>` (stdlib only, reads
only metadata fields, never report bodies).

**There is no severity column, on purpose.** Severity labels in this corpus are not comparable
across sources: one source labelled 5,313 of its 12,618 reports "critical" and only 66 "high",
while other sources covering the same reports showed the normal pyramid (medium > low > high >
critical), and a Bugcrowd source used P1–P5 instead. Merging them yields a figure that changes
with the order the files happen to be read — an artifact dressed as a measurement. A first pass
of this work did ship such a column; it was removed once the sources were compared. Use the
program's own severity system at triage time, not a corpus average.

`trend_pts` compares each class's share of *labelled* disclosures in two windows —
2014-2020 (n=7,851) and 2023-2026 (n=2,522) — and reports the change in percentage points.

**Read these numbers as relative, not absolute.**

- `bounty_pct` is the share with a **publicly disclosed** bounty. Many paid reports never
  disclose the amount, so every figure is a lower bound. It ranks classes against each other;
  it is not a probability that your report pays.
- Disclosure is not a census. Programs choose what to disclose, most reports are never
  disclosed at all, and the two windows differ in size and in platform labelling habits. Part
  of the apparent collapse of `Cross-site Scripting (XSS) - Generic` is HackerOne's own move to
  the more specific reflected/stored/DOM labels, not a real disappearance of XSS.
- A falling class is not a dead class. It means disclosures of it are a smaller share of the
  record — usually because triage now expects a stronger impact story for it, not because the
  bug stopped existing. `zp-triage` uses these rates that way.
- The trend windows differ in size (n=7,851 against n=2,529) and the recent one is still
  filling: reports disclose months to years after they are filed. Treat a trend as a direction,
  not a rate of change.

**No report bodies here either.** This file holds counts. The corpus it was derived from is not
vendored and is not required to use the pack; the numbers are.

### Families this pack does not cover

`zp-intel priors --gaps` lists them. As of this measurement that is the memory-safety family —
723 reports, the highest disclosed-bounty rates in the whole set (Memory Corruption 82%, Buffer
Over-read 63%), concentrated in the Internet Bug Bounty, curl, Node.js and similar
**open-source C/C++** programs rather than in web applications.

That is a deliberate scope boundary, not an oversight: ZeroProtocol is a web and cloud
application pack, and crash triage on a native codebase is a different discipline with
different tooling. The gap is recorded here so the pack does not silently imply coverage it
does not have. If you hunt those programs, use a fuzzing and crash-triage workflow, not this
pack.

## hackerone-reports.csv — the dedup index

An index of **publicly disclosed HackerOne reports**.

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
