# reports/ — exploits, CVE intelligence and disclosed reports

Local corpus for `zp-reports`. Most of this directory is **fetched on your machine, not
committed** — see *What is committed* below for why.

```bash
zp-reports status                 what is synced, and how big
zp-reports sync all               fetch everything (~2.5 GB)
zp-reports cve CVE-2021-44228     KEV status + PoCs + nuclei template + exploits
zp-reports find log4j             free text across every synced corpus
zp-reports read 160047            fetch one disclosed HackerOne report to read
```

## Sources

| Directory | Source | Licence | Size | What it gives you |
|---|---|---|---|---|
| `kev/` | CISA Known Exploited Vulnerabilities | **public domain** (US gov) | ~2 MB | 1,700+ CVEs confirmed exploited in the wild, with ransomware flags |
| `nuclei-templates/` | projectdiscovery/nuclei-templates | **MIT** | ~735 MB | detection templates — the fastest check for a known CVE |
| `exploitdb/` | exploit-database/exploitdb | **GPL-2.0** | ~1 GB | the Exploit-DB archive, with `searchsploit` |
| `poc-in-github/` | nomi-sec/PoC-in-GitHub | **CC0-1.0** | ~960 MB | CVE → public PoC repository index |
| `trickest-cve/` | trickest/cve | **MIT** | ~880 MB | a second CVE → PoC index, different coverage |
| `hackerone/` | hackerone.com, one report at a time | per-author | grows | reports you chose to cache and read |

Every exploit corpus above is published under a licence that permits redistribution, and all four
are standard, widely-installed security tooling — `nuclei-templates` ships with `nuclei`, which
`zp-doctor` already expects.

## What is committed, and what is not

**Committed:** `kev/known_exploited_vulnerabilities.json` only. It is public-domain US government
data, ~2 MB, and it is the single highest-value file here — it tells you whether a CVE is actually
being exploited rather than merely published.

**Not committed** (`.gitignore`d, fetched by `zp-reports sync`):

- The four exploit corpora, for a practical reason: **~2.5 GB**. Vendoring them would make this
  repository unclonable for the sake of mirroring four repositories that are one `git clone` away
  and better kept current by their own maintainers. `zp-reports sync` pulls them shallow and
  `zp-reports sync <name>` updates them in place.

- **HackerOne report bodies**, for a different reason. Report text, screenshots and PoC write-ups
  are the copyrighted work of the individual researchers who wrote them. HackerOne disclosing a
  report makes it publicly *readable*; it does not license anyone to re-host thousands of other
  people's writing. So `zp-reports read <id>` fetches a single report to your own machine for you
  to read — ordinary personal use — and nothing bulk-scrapes them or ships them onward.

  The searchable metadata you need for dedup and prior art is already in the repository at
  `intel/hackerone-reports.csv` (program, title, link, bounty, weakness — 14,972 reports), and
  `zp-intel` queries it offline. That covers the *find it* half; `zp-reports read` covers the
  *read it* half, one at a time, without redistribution.

If you want a local full-text archive for yourself, `zp-reports read` builds one as you go, in
`reports/hackerone/`, and it stays on your machine.

## Using this while hunting

The pipeline this is built for:

```bash
zp-recon-active → a version banner or a technology fingerprint
zp-reports cve CVE-2024-XXXXX        # is it real, is it exploited, is there a template
nuclei -t reports/nuclei-templates/http/cves/ -u https://target   # scope-gated, rate-limited
```

`zp-cve` owns the methodology for turning a version number into a confirmed finding, including the
rule that matters most here: **a version banner is not a vulnerability**. Confirm the behaviour,
not the version string — banners are wrong, back-ported patches are invisible, and a CVE report
based on a banner alone is the most common false positive in this whole class.

Everything in `zp-scope` still applies. A nuclei run is thousands of requests; it needs exit 0 and
the program's rate limit, exactly like any other active phase.
