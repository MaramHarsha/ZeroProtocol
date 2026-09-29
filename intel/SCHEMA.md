# intel/ — data contract

Three files. Read this before aggregating anything out of them, because two of the fields you
would reach for first are the two that will mislead you.

| File | What it answers | Rows |
|---|---|---|
| `writeups-index.jsonl.gz` | *which public write-up should I read about X, and where is it* | 138,400 |
| `class-priors.csv` | *which vulnerability classes are disclosed now, and which get paid* | 68 |
| `hackerone-reports.csv` | *has this bug been reported on this program* (dedup, bounty amounts) | 14,972 |

Query them with `zp-corpus` and `zp-intel`. Both take `--json` on every subcommand. Do not
hand-parse the files unless you need something the tools do not expose.

---

## The one rule

**The index holds titles and links. It holds no body text, and it never will.**

97 sources means 97 licences — researcher blogs, HackerOne reports owned by their authors,
vendor advisories, CTF write-ups. Titles and URLs are factual metadata about public
disclosures. The prose is not ours to redistribute.

So the workflow is always two steps:

```bash
zp-corpus search idor graphql --limit 10     # 1. find the write-up
# 2. fetch the URL of the one that looks right, and read it at the source
```

A search result is a **reading list, not an answer**. If you report a technique as fact because
a title implied it, you have invented it. Fetch the page.

---

## writeups-index.jsonl.gz

Gzipped newline-delimited JSON, one object per line, 5.7 MB (33 MB raw). Read it streaming:

```python
import gzip, json
with gzip.open("intel/writeups-index.jsonl.gz", "rt", encoding="utf-8") as fh:
    for line in fh:
        rec = json.loads(line)
```

A full scan plus filter takes about 0.2 s, so there is no index-building step and no database.

| Field | Always? | Meaning | Trust |
|---|---|---|---|
| `id` | yes | `<source>:<native id>`; the handle for `zp-corpus show` | stable across rebuilds unless the source changes its ids |
| `source` | yes | which of the 97 sources this came from | reliable |
| `title` | yes | the write-up's own title, whitespace-normalised | the author's words. Often the single most informative field |
| `url` | yes | canonical link. **Fetch this to read it** | reliable; may 404 as sites rot |
| `date` | **no** — 112,764 of 138,400 | publication or disclosure date, `YYYY-MM-DD` | only ever a real publication date (see below) |
| `program` | no — 18,195 | the bug bounty program | reliable where present |
| `weakness` | no — 12,713 | the class label, e.g. `Insecure Direct Object Reference (IDOR)` | reliable, but only HackerOne-family sources carry it |
| `cves` | no — 61,899 | list of CVE ids mentioned | a *mention*, not a claim the write-up is about that CVE |
| `bounty` | no — 4,101 | `true` when a bounty was publicly disclosed | a lower bound. Absent ≠ unpaid; amounts are usually withheld |

### There is no `severity` field, and adding one would be a bug

Severity labels in the underlying corpus are **not comparable across sources**. Measured:
one source labels 5,313 of its 12,618 reports `critical` and only 66 `high`; other sources
covering the same reports show the normal pyramid (medium > low > high > critical); a Bugcrowd
source uses `P1`–`P5` instead. Merging them yields a number that changes depending on which
file the merge reads first.

A first version of this work did ship a "critical count" column. It looked entirely plausible
and was an artifact. It was caught by diffing two builds with different source orders, and
removed.

**If you need severity, read the record's URL.** If you want to add the field, first prove the
sources agree on the same report ids.

### `date` is absent rather than wrong

25,636 records have no `date`. Their sources gave only a scrape timestamp, and dating a 2014
advisory to the day it was downloaded would make `--since` quietly wrong — so those records
are left undated instead. `zp-corpus search --since` therefore **excludes** them; `zp-corpus
stats` prints the count so the loss is never silent.

Dates that parsed to outside 1995–2027 were dropped as parser artifacts (one source produced
`0001-01-01`).

### Deduplication, and what it deliberately keeps

Raw corpus 221,091 records → 138,400 distinct write-ups. Duplicates were removed by canonical
URL, then by body digest, because nine HackerOne-family sources overlap heavily.

What survives on purpose: the **same bug written up in two places** — the HackerOne disclosure
*and* a researcher's blog post about it — stays as two records. Those are two different things
to read, often with very different detail. Do not treat a second record as a duplicate.

Consequence: **counts here are not comparable with `class-priors.csv`.** That file dedups by
HackerOne report id and counts only labelled reports (12,768 across 379 programs). This index
dedups by URL across all sources and counts write-ups (138,400). Different question, different
denominator. Never mix the two in one claim.

---

## class-priors.csv

```
weakness,zp_skill,reports,disclosed_bounty,bounty_pct,
share_2014_2020_pct,share_2023_2026_pct,trend_pts
```

Derived from the 12,768 labelled disclosed HackerOne reports across 379 programs, 2013–2026.
`zp_skill` names the owning skill, or `NONE-gap` where this pack has no skill for that family.
Read `bounty_pct` as a ranking between classes, never as a probability; read `trend_pts` as a
direction, not a rate. Full limits in `README.md`.

---

## Staleness

Every file is a snapshot. Rebuild from a local corpus of write-up metadata:

```bash
python3 scripts/build_writeups_index.py --corpus <dir>   # the index
python3 scripts/build_class_priors.py   --corpus <dir>   # the priors
```

Both are stdlib-only, read only metadata fields, and never read or write body text. `zp-intel
update` refreshes `hackerone-reports.csv` from its upstream.

Old is not useless: a write-up from years ago may describe an endpoint that no longer exists —
or a fix whose bypass is still sitting there, which is the more interesting case.

---

## Exit codes

Branch on these rather than parsing prose.

| Tool | Code | Meaning |
|---|---|---|
| `zp-corpus` | 0 | results found |
| | 1 | usage or runtime error |
| | 2 | index not installed — **say so**, do not answer from memory instead |
| | 4 | the query ran and matched nothing. An answer, not a failure |
| `zp-intel dedup` | 8 | likely duplicate — read the hits before writing anything |
| `zp-scope check` | 0 / 1 / 3 / 4 | allow / deny / unconfirmed / no scope file |

A zero-result search means *nothing indexed matches*. It never means nobody has written about
it: most reports are never disclosed, and this index is 97 sources out of a much larger field.
