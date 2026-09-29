#!/usr/bin/env python3
"""Build intel/writeups-index.jsonl.gz - a searchable index of public write-ups.

WHAT THIS SHIPS, AND WHAT IT DELIBERATELY DOES NOT
The index carries a TITLE and a SOURCE LINK per write-up, plus factual metadata (source,
date, program, weakness label, CVE ids, whether a bounty was disclosed). It carries **no
body text at all**. When something in the index looks relevant, the reader fetches that one
URL and reads it at the source.

That is the whole licensing design. 126 sources means 126 licences - researcher blogs,
HackerOne disclosures owned by their authors, vendor advisories, CTF write-ups. Titles and
URLs are factual metadata about public disclosures; the prose is not ours to redistribute.
So the pack ships the card catalogue, never the books.

There is also no `severity` column, and that is on purpose. Severity labels in this corpus
are not comparable across sources: one source labels 5,313 of its 12,618 reports "critical"
and only 66 "high", while other sources covering the same reports show the normal pyramid,
and a Bugcrowd source uses P1-P5. Anything aggregated from that is an artifact of which file
was read first. Read a record's URL for its real severity.

    python3 scripts/build_writeups_index.py --corpus /path/to/data/writeups
    python3 scripts/build_writeups_index.py --corpus DIR --dry-run

INPUT: a directory of newline-delimited JSON, one record per line, searched recursively.
Fields read: id, source, native_id, title, url, canonical_url, program, weakness, cves,
disclosed_at, published_at, bounty, body_sha256. `fetched_at` is deliberately NOT used as a
date fallback - see the `date` handling below. `body_markdown` is read only to
compute nothing - it is never copied, and the builder never writes it out.

DEDUP: by canonical URL, then by body digest. Nine HackerOne-family sources overlap heavily,
so this collapses roughly 221k raw records to ~138k distinct write-ups. Note that the same
underlying bug written up in two places (a disclosure AND a blog post about it) stays as two
records on purpose - they are two different things to read.

Stdlib only.
"""

from __future__ import annotations

import argparse
import collections
import gzip
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "intel" / "writeups-index.jsonl.gz"

# Never emitted, whatever the input holds. Listed so the intent is greppable.
NEVER_EMIT = ("body_markdown", "blocks", "body_sha256", "raw_sha256", "severity",
              "redaction", "gated_blocks", "is_partial")


def clean(value: object) -> str:
    """One line, no tabs - the index is read by machines and skimmed by humans."""
    return " ".join(str(value or "").split())


_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
# e.g. Bugcrowd's Crowdstream renders "4 Nov 2024" rather than an ISO timestamp.
_DMY = re.compile(r"^(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?\s+(\d{4})$")

# Anything outside this window is a parser artifact, not a date. One source yielded
# "0001-01-01". Shipping a wrong date is worse than shipping none, because `--since`
# silently filters on it.
YEAR_MIN, YEAR_MAX = 1995, 2027


def iso_date(raw: object) -> str:
    """Return YYYY-MM-DD, or "" when the value is not a date we can trust."""
    s = clean(raw)
    if not s:
        return ""
    m = _ISO.match(s)
    if m:
        y, mo, d = (int(x) for x in m.groups())
    else:
        m = _DMY.match(s)
        if not m:
            return ""
        d, mon, y = int(m.group(1)), _MONTHS.get(m.group(2).lower()), int(m.group(3))
        if not mon:
            return ""
        mo = mon
    if not (YEAR_MIN <= y <= YEAR_MAX and 1 <= mo <= 12 and 1 <= d <= 31):
        return ""
    return f"{y:04d}-{mo:02d}-{d:02d}"


def build(corpus: Path, exclude: set[str] | None = None) -> tuple[list[dict], dict]:
    files = sorted(corpus.rglob("*.jsonl"))
    if not files:
        sys.exit(f"build_writeups_index: no .jsonl files under {corpus}")

    seen_url: set[str] = set()
    seen_body: set[str] = set()
    out: list[dict] = []
    read = skipped_dupe = skipped_thin = unparseable = skipped_excluded = 0
    per_source: collections.Counter = collections.Counter()

    for path in files:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    unparseable += 1
                    continue
                read += 1

                url = clean(rec.get("canonical_url") or rec.get("url"))
                title = clean(rec.get("title"))
                if not url or not title:
                    # No link or no title means nothing to look up later.
                    skipped_thin += 1
                    continue

                digest = rec.get("body_sha256")
                if url in seen_url or (digest and digest in seen_body):
                    skipped_dupe += 1
                    continue
                seen_url.add(url)
                if digest:
                    seen_body.add(digest)

                source = clean(rec.get("source")) or "unknown"
                if exclude and source in exclude:
                    skipped_excluded += 1
                    continue
                rid = clean(rec.get("id")) or f"{source}:{clean(rec.get('native_id'))}"
                # ONLY a real disclosure or publication date. `fetched_at` is the scrape
                # time, which 46,867 records have instead - emitting it would date a 2014
                # advisory to the day we downloaded it and make `--since` silently wrong.
                # Better to leave those undated and say so.
                date = iso_date(rec.get("disclosed_at")) or iso_date(rec.get("published_at"))

                entry = {"id": rid, "source": source, "title": title, "url": url}
                if date:
                    entry["date"] = date
                for src_field, key in (("program", "program"), ("weakness", "weakness")):
                    v = clean(rec.get(src_field))
                    if v:
                        entry[key] = v
                cves = [clean(c) for c in (rec.get("cves") or []) if clean(c)]
                if cves:
                    entry["cves"] = cves
                if rec.get("bounty"):
                    entry["bounty"] = True

                assert not any(k in entry for k in NEVER_EMIT), "body/severity field leaked"
                out.append(entry)
                per_source[source] += 1

    meta = {"files": len(files), "read": read, "kept": len(out),
            "dupes": skipped_dupe, "thin": skipped_thin, "unparseable": unparseable,
            "excluded": skipped_excluded,
            "sources": per_source,
            "with_weakness": sum(1 for e in out if e.get("weakness")),
            "with_program": sum(1 for e in out if e.get("program")),
            "with_cve": sum(1 for e in out if e.get("cves")),
            "with_bounty": sum(1 for e in out if e.get("bounty")),
            "with_date": sum(1 for e in out if e.get("date"))}
    return out, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True, type=Path,
                    help="directory of .jsonl write-up metadata (searched recursively)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--exclude-source", action="append", default=[], metavar="NAME",
                    help="omit a source entirely; repeatable. This is the takedown path - if a "
                         "publisher asks not to be indexed, name their source here and rebuild")
    ap.add_argument("--dry-run", action="store_true", help="report and write nothing")
    args = ap.parse_args()

    if not args.corpus.is_dir():
        sys.exit(f"build_writeups_index: no such directory: {args.corpus}")

    print(f"\n  corpus: {args.corpus}")
    rows, meta = build(args.corpus, set(args.exclude_source))
    print(f"  read {meta['read']:,} records from {meta['files']} file(s)"
          + (f", {meta['unparseable']:,} unparseable" if meta["unparseable"] else ""))
    print(f"  dropped {meta['dupes']:,} duplicates and {meta['thin']:,} records with no "
          f"title or link")
    if meta["excluded"]:
        print(f"  omitted {meta['excluded']:,} records from excluded source(s): "
              f"{', '.join(sorted(args.exclude_source))}")
    print(f"  kept {meta['kept']:,} distinct write-ups from {len(meta['sources'])} sources")
    print(f"       {meta['with_date']:,} carry a real publication date · "
          f"{meta['with_weakness']:,} a weakness label · "
          f"{meta['with_program']:,} a program · {meta['with_cve']:,} a CVE · "
          f"{meta['with_bounty']:,} a disclosed bounty")
    print("\n  top sources:")
    for src, n in meta["sources"].most_common(10):
        print(f"    {src:34} {n:>7,}")

    payload = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n"
                      for r in rows).encode("utf-8")
    blob = gzip.compress(payload, 9)
    print(f"\n  index: {len(payload) / 1e6:.1f} MB raw -> {len(blob) / 1e6:.1f} MB gzipped")

    if args.dry_run:
        print("  --dry-run: nothing written\n")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(blob)
    print(f"  wrote {args.out}")
    print("  Update the counts quoted in intel/README.md, intel/SCHEMA.md and")
    print("  skills/zp-corpus/SKILL.md if they moved.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
