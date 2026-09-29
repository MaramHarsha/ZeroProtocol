#!/usr/bin/env python3
"""Rebuild intel/class-priors.csv from a local corpus of disclosed-report metadata.

This is the pack's calibration layer. A class weight in the router encodes IMPACT - what a bug
is worth if it is there. It says nothing about LIKELIHOOD - whether the field is still finding
and getting paid for that class. This script measures the second one from the public disclosure
record, so the queue and the kill gate rank on evidence instead of habit.

    python3 scripts/build_class_priors.py --corpus /path/to/writeups
    python3 scripts/build_class_priors.py --corpus DIR --min-reports 15 --dry-run

INPUT: a directory of newline-delimited JSON, one record per line, any number of files. Only
these fields are read, and only ones that exist are used:

    canonical_url / url   used to recover the report id, for dedup across overlapping sources
    native_id             fallback id
    weakness              the class label (e.g. "Insecure Direct Object Reference (IDOR)")
    bounty                truthy when a bounty was publicly disclosed
    disclosed_at          ISO date; reported_at is the fallback
    program               used only for the program count in the header

SEVERITY IS DELIBERATELY NOT AGGREGATED, and that is the most important thing in this file.
Measured across the sources of one corpus, severity labels are not comparable: one source
labelled 5,313 of 12,618 reports "critical" and only 66 "high", while every other source of the
same reports showed the usual pyramid (medium > low > high > critical), and a Bugcrowd source
used P1-P5 instead. Merging them produces a number that changes depending on which file the
merge happens to read first - which is an artifact, not a measurement. A "critical count" column
built that way looked plausible and was meaningless. If you add a severity column later, first
prove the sources agree on the same report ids.

Report BODIES are never read and never written. The output is counts, which is what makes the
file safe to ship: nobody's report text is redistributed. See intel/README.md.

Re-run it whenever the corpus grows. The numbers move slowly; the trend columns move slowest,
because they are shares of two multi-year windows.

Stdlib only.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "intel" / "class-priors.csv"

# Windows compared by the trend column. Chosen to be wide enough that one busy year on one
# program cannot swing a class, and to leave a gap so a single transition year is not counted
# on both sides.
OLD = (2014, 2020)
NEW = (2023, 2026)

REPORT_ID = re.compile(r"hackerone\.com/reports/(\d+)")

# Which zp-* skill owns which weakness family. Longest matching prefix wins, so a specific
# label beats a generic one. "NONE-gap" is deliberate and load-bearing: it marks a family the
# pack does not cover, so `zp-intel priors --gaps` can state the gap instead of implying
# coverage that is not there.
OWNER: list[tuple[str, str]] = [
    ("Cross-site Scripting", "zp-xss"),
    ("Improper Neutralization of Script-Related", "zp-xss"),
    ("SQL Injection", "zp-sqli"),
    ("Server-Side Request Forgery", "zp-ssrf"),
    ("Resource Injection", "zp-ssrf"),
    ("Insecure Direct Object Reference", "zp-idor"),
    ("Improper Access Control", "zp-authz"),
    ("Improper Authorization", "zp-authz"),
    ("Incorrect Authorization", "zp-authz"),
    ("Privilege Escalation", "zp-authz"),
    ("Client-Side Enforcement of Server-Side", "zp-authz"),
    ("Improper Authentication", "zp-jwt-oauth"),
    ("Authentication Bypass", "zp-jwt-oauth"),
    ("Cross-Site Request Forgery", "zp-csrf"),
    ("UI Redressing", "zp-csrf"),
    ("Information Disclosure", "zp-info-disclosure"),
    ("Information Exposure", "zp-info-disclosure"),
    ("Cleartext Storage", "zp-info-disclosure"),
    ("Insecure Storage", "zp-info-disclosure"),
    ("Insufficiently Protected Credentials", "zp-info-disclosure"),
    ("Misconfiguration", "zp-info-disclosure"),
    ("Privacy Violation", "zp-info-disclosure"),
    ("Insufficient Logging", "zp-info-disclosure"),
    ("Business Logic Errors", "zp-business-logic"),
    ("Violation of Secure Design", "zp-business-logic"),
    ("Open Redirect", "zp-open-redirect"),
    ("Phishing", "zp-open-redirect"),
    ("Code Injection", "zp-rce-ssti"),
    ("Command Injection", "zp-rce-ssti"),
    ("OS Command Injection", "zp-rce-ssti"),
    ("Deserialization of Untrusted Data", "zp-rce-ssti"),
    ("Path Traversal", "zp-xxe-lfi"),
    ("XML External Entities", "zp-xxe-lfi"),
    ("Remote File Inclusion", "zp-xxe-lfi"),
    ("Unrestricted Upload", "zp-upload"),
    ("HTTP Request Smuggling", "zp-smuggling"),
    ("HTTP Response Splitting", "zp-smuggling"),
    ("CRLF Injection", "zp-semantic-confusion"),
    ("Uncontrolled Resource Consumption", "zp-rate-limit"),
    ("Allocation of Resources", "zp-rate-limit"),
    ("Improper Restriction of Authentication", "zp-rate-limit"),
    ("Cryptographic Issues", "zp-tls"),
    ("Improper Certificate Validation", "zp-tls"),
    ("Cleartext Transmission", "zp-tls"),
    ("Man-in-the-Middle", "zp-tls"),
    ("Insufficient Session Expiration", "zp-session"),
    ("Session", "zp-session"),
    ("Time-of-check", "zp-race"),
    ("Race Condition", "zp-race"),
    ("Concurrent Execution using Shared", "zp-race"),
    ("Improper Input Validation", "zp-exceptional"),
    ("Modification of Assumed-Immutable", "zp-proto-pollution"),
    # Memory safety on native code: measured, and deliberately uncovered. Those reports come
    # from open-source C/C++ programs and the work is fuzzing and crash triage, not a web
    # pipeline. Recording it as a gap is the honest option.
    ("Memory Corruption", "NONE-gap"),
    ("Use After Free", "NONE-gap"),
    ("Buffer Over", "NONE-gap"),
    ("Classic Buffer", "NONE-gap"),
    ("Heap Overflow", "NONE-gap"),
    ("Out-of-bounds", "NONE-gap"),
    ("Stack Overflow", "NONE-gap"),
    ("NULL Pointer", "NONE-gap"),
    ("Integer Overflow", "NONE-gap"),
    ("Type Confusion", "NONE-gap"),
    ("Double Free", "NONE-gap"),
    ("Array Index", "NONE-gap"),
]


def owner(weakness: str) -> str:
    best, found = "", "NONE-gap"
    for prefix, skill in OWNER:
        if weakness.startswith(prefix) and len(prefix) > len(best):
            best, found = prefix, skill
    return found


def report_key(rec: dict) -> str | None:
    """A stable id, so the same report seen in several sources is counted once."""
    m = REPORT_ID.search(rec.get("canonical_url") or rec.get("url") or "")
    if m:
        return m.group(1)
    nid = rec.get("native_id")
    return str(nid) if nid else None


def year(rec: dict) -> int:
    d = str(rec.get("disclosed_at") or rec.get("reported_at") or "")[:4]
    return int(d) if d.isdigit() else 0


def collect(corpus: Path) -> dict[str, dict]:
    files = sorted(corpus.rglob("*.jsonl"))
    if not files:
        sys.exit(f"build_class_priors: no .jsonl files under {corpus}")
    merged: dict[str, dict] = {}
    seen = skipped = 0
    for path in files:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                seen += 1
                key = report_key(rec)
                if not key:
                    continue
                cur = merged.setdefault(key, {})
                # First non-empty value wins, so a source with richer metadata fills the gaps
                # a thinner one left. `bounty` is the exception: any source saying a bounty was
                # disclosed is enough, which makes it order-independent.
                for field in ("weakness", "disclosed_at", "reported_at", "program"):
                    if not cur.get(field) and rec.get(field):
                        cur[field] = rec[field]
                if rec.get("bounty"):
                    cur["bounty"] = True
    print(f"  read {seen:,} records from {len(files)} file(s)"
          f"{f', {skipped:,} unparseable lines skipped' if skipped else ''}")
    print(f"  {len(merged):,} unique reports after dedup by report id")
    return merged


def build(merged: dict[str, dict], min_reports: int) -> tuple[list[dict], dict]:
    agg: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    old_total = new_total = 0
    labelled = 0
    programs, programs_new = set(), set()

    for rec in merged.values():
        y = year(rec)
        weakness = str(rec.get("weakness") or "").strip()
        if not weakness:
            continue
        # Only labelled reports back the table, so only they count toward the denominators
        # quoted in the docs. Counting every deduplicated record would inflate the basis with
        # advisories and PoC entries that carry no class label at all.
        labelled += 1
        if rec.get("program"):
            programs.add(rec["program"])
            if NEW[0] <= y <= NEW[1]:
                programs_new.add(rec["program"])
        a = agg[weakness]
        a["n"] += 1
        if rec.get("bounty"):
            a["bounty"] += 1
        if OLD[0] <= y <= OLD[1]:
            a["old"] += 1
            old_total += 1
        elif NEW[0] <= y <= NEW[1]:
            a["new"] += 1
            new_total += 1

    if not old_total or not new_total:
        sys.exit("build_class_priors: one of the trend windows is empty - "
                 "the corpus does not span enough years to measure a trend")

    rows = []
    for weakness, a in agg.items():
        if a["n"] < min_reports:
            continue
        old_share = 100 * a["old"] / old_total
        new_share = 100 * a["new"] / new_total
        rows.append({
            "weakness": weakness,
            "zp_skill": owner(weakness),
            "reports": a["n"],
            "disclosed_bounty": a["bounty"],
            "bounty_pct": round(100 * a["bounty"] / a["n"]),
            "share_2014_2020_pct": round(old_share, 2),
            "share_2023_2026_pct": round(new_share, 2),
            "trend_pts": round(new_share - old_share, 2),
        })
    rows.sort(key=lambda r: -r["reports"])
    meta = {"unique": len(merged), "labelled": labelled, "programs": len(programs),
            "programs_recent": len(programs_new),
            "old_total": old_total, "new_total": new_total}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True, type=Path,
                    help="directory of .jsonl disclosed-report metadata (searched recursively)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--min-reports", type=int, default=15,
                    help="drop classes thinner than this - a rate over 5 reports is noise")
    ap.add_argument("--dry-run", action="store_true", help="print the summary, write nothing")
    args = ap.parse_args()

    if not args.corpus.is_dir():
        sys.exit(f"build_class_priors: no such directory: {args.corpus}")

    print(f"\n  corpus: {args.corpus}")
    merged = collect(args.corpus)
    rows, meta = build(merged, args.min_reports)

    print(f"  {meta['labelled']:,} of those carry a weakness label - THAT is the basis of the "
          f"table")
    print(f"  {meta['programs']:,} programs among the labelled reports "
          f"({meta['programs_recent']:,} with a {NEW[0]}+ disclosure)")
    print(f"  trend windows: {OLD[0]}-{OLD[1]} n={meta['old_total']:,}  "
          f"{NEW[0]}-{NEW[1]} n={meta['new_total']:,}")
    print(f"  {len(rows)} classes at >= {args.min_reports} reports")

    gaps = [r for r in rows if r["zp_skill"] == "NONE-gap"]
    if gaps:
        print(f"\n  {sum(r['reports'] for r in gaps):,} reports in {len(gaps)} families no "
              f"zp-* skill owns:")
        for r in sorted(gaps, key=lambda r: -r["reports"])[:12]:
            print(f"    {r['weakness'][:46]:46} n={r['reports']:>4} paid={r['bounty_pct']:>3}%")
        print("  Either the pack should grow a skill, or intel/README.md should say why not.")

    if args.dry_run:
        print("\n  --dry-run: nothing written\n")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"\n  wrote {args.out}")
    print("  Update the headline figures quoted in intel/README.md, skills/zp-intel/SKILL.md,")
    print("  skills/zp-triage/SKILL.md and skills/zeroprotocol/SKILL.md if they moved.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
