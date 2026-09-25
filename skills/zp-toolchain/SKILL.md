---
name: zp-toolchain
description: ZeroProtocol phase 1b - survey what security tooling this machine actually has, pick the fallback for everything missing, and set up wordlists, API keys and an out-of-band callback listener. Use whenever ZeroProtocol starts on a new machine, when a skill needs a tool that is not installed, when a command fails with "not found", when asked what tools are needed or how to install them, or when deciding whether a capability is available or must run degraded. Never installs anything without being asked; emits a script for the user to read instead.
---

# zp-toolchain - what this box can actually do

**Phase:** 1b | **Gate:** none. Surveying your own machine touches no target.

ZeroProtocol is built to degrade, never to fail. Every tool it likes has a documented
`curl`/`dig`/`python3` fallback, so a bare machine still hunts - slower, narrower, and
correct. What it must never do is *pretend*: a hallucinated `subfinder` invocation that
silently produced nothing is worse than an honest crt.sh loop.

---

## Procedure

**1. Survey first, plan second.**

```bash
zp-doctor                 # human report: per-phase inventory + capability verdict
zp-doctor --json          # machine-readable - branch on this, do not guess
zp-doctor --missing       # bare names, one per line
```

Exit 0 means every **core** tool (`python3 curl dig git openssl`) is present. Exit 1 means a
core tool is missing - fix that before hunting; there is no fallback for `curl`.

`jq` is tier *strong*, not core, so exit 0 does **not** guarantee it. Every `jq` pipeline in
this pack therefore needs its stdlib fallback when `zp-doctor --missing` lists it:
`python3 -c 'import json,sys; ...'`.

**2. Read the capability verdict, not the tool list.** What matters is whether a
*capability* is available, not which binary provides it:

```bash
zp-doctor --json | jq -r '.capabilities | to_entries[] | select(.value.available==false) | .key'
```

**3. Record the degraded set in `notes.md`.** Every later phase must know it is running on
fallbacks, because it changes what "exhausted" means. A class you could not test properly
is `not-applicable: no tooling` with the gap named - never silently skipped.

**4. Offer to close the gaps. Never close them unasked.**

```bash
zp-doctor --install-script > /tmp/zp-setup.sh    # emits, does not run
```

Show the user the script. Installing software on their machine is their decision, and
`go install` from a URL is exactly the kind of thing a person should read first.

---

## The fallback table

The substitutions ZeroProtocol uses when a tool is absent. `zp-doctor` prints these
per-tool; this is the shape of the reasoning.

| Missing | Fallback | What you lose |
|---|---|---|
| `subfinder` | crt.sh + Anubis + HackerTarget over `curl` | ~30 sources down to 3; no API-key sources |
| `gau` / `waybackurls` | Wayback CDX API over `curl` | CommonCrawl and URLScan history |
| `httpx` | `curl -sk -o /dev/null -w` in a bounded loop | tech detection, CDN/CNAME columns, speed |
| `dnsx` | `dig +short` in a loop | wildcard detection, throughput |
| `naabu` | `nmap`, or a python `socket.connect_ex` sweep | speed; the python sweep is top-ports only |
| `nuclei` | nothing honest | **say so.** Known-CVE coverage is gone; hand-check a shortlist |
| `ffuf` | `feroxbuster`/`gobuster`, or a rate-limited curl loop | auto-calibration - so calibrate soft-404 by hand |
| `katana` | `hakrawler`, or `curl` + a link regex | JS-rendered routes, which is most of a modern SPA |
| `arjun` / `x8` | `ffuf` against a param list with a reflection oracle | the diff oracle; more false negatives |
| `interactsh-client` | a DNS/HTTP collector **you control** | never a third-party pastebin - that leaks the target |
| `subzy` | `dig CNAME` + fetch + match the vendor claim page | 70+ curated fingerprints |
| `trufflehog` | `gitleaks`, or a regex sweep | verification, so every hit needs manual triage |
| `sqlmap` | hand-built boolean/time oracles | breadth; you gain precision about real impact |
| `jadx` | `apktool` (smali only) | readable Java |
| `forge` | read-only static review | an executable PoC, which most programs require |

**The rule for `nuclei` generalises:** when a capability has no honest fallback, say the
capability is unavailable. Do not substitute a weaker check and report it as coverage.

---

## Wordlists

Discovery quality is wordlist quality. Without one, content discovery is theatre.

```bash
# SecLists - the standard corpus (~1 GB, shallow clone)
git clone --depth 1 https://github.com/danielmiessler/SecLists ~/.local/share/seclists

# the four that earn their place
~/.local/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
~/.local/share/seclists/Discovery/Web-Content/raft-medium-files.txt
~/.local/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
~/.local/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

**A target-derived wordlist beats a generic one.** Build it from the crawl before you
reach for raft:

```bash
cat surface/urls.txt \
  | grep -oE '[A-Za-z0-9_-]{3,}' \
  | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn | awk '$1>1{print $2}' > surface/wordlist-target.txt
```

---

## API keys

Each one unlocks a capability; none is required. Store them in the environment, never in
the repo, and never in a report.

| Key | Unlocks | Without it |
|---|---|---|
| `GITHUB_TOKEN` | code search for subdomains and leaked secrets | unauthenticated search: near-useless rate limit |
| `SHODAN_API_KEY` | host/service/favicon pivots, origin-IP discovery | crt.sh SAN pivots only |
| `CENSYS_API_ID/SECRET` | certificate and host search | crt.sh only |
| `H1_USER` + `H1_TOKEN` | authoritative scope with per-asset flags | the public bounty-targets dump |
| `CHAOS_KEY` | ProjectDiscovery's passive DNS dataset | other passive sources |

```bash
zp-doctor --json | jq -r '.tools[] | select(.present) | .tool' | tr '\n' ' '   # what you have
env | grep -oE '^(GITHUB_TOKEN|SHODAN_API_KEY|CENSYS_API_ID|H1_USER|CHAOS_KEY)' | sort
```

---

## Out-of-band callbacks

Blind SSRF, blind XXE, blind RCE and OOB SQLi all need a collector. This is the one piece
of infrastructure worth setting up before hunting, because without it those classes are
untestable rather than merely harder.

```bash
interactsh-client -v          # prints a domain; every DNS/HTTP hit is shown live
```

Without it, use a domain **you control** with query logging, and tag each sink so a hit
tells you which injection point fired:

```
ssrf-import.<your-collector>     xxe-doc.<your-collector>     rce-ping.<your-collector>
```

**Never use a third-party request-bin, webhook-tester or pastebin for this.** The callback
carries the target's hostnames, internal IPs, and sometimes its credentials, to a service
you do not control and cannot delete from. That is a data leak you caused.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| `zp-doctor` exits 1 | stop. Install the core tool; there is no fallback for `curl` |
| a capability is degraded and the class is P1 | run the fallback, and record the degradation |
| a capability has no honest fallback (`nuclei`) | mark the class `not-applicable: no tooling` |
| no wordlist present | build the target-derived list first; do not fake discovery |
| no OOB collector | blind classes are untestable - say so, do not claim they are clean |
| a tool exists but errors out | treat as missing, use the fallback, note the error |

---

## Pitfalls

- **Inventing flags.** If unsure of a flag, run `<tool> -h`. A wrong flag often means "scanned nothing" with exit 0.
- **Claiming coverage a fallback did not give.** The curl loop did not do tech detection. Say what you actually ran.
- **Installing without asking.** `curl | bash` on someone else's machine is not yours to decide.
- **Go tools missing from PATH.** They land in `~/go/bin`; `zp-doctor` looks there, your shell may not.
- **Third-party OOB services.** See above. This is the single worst tooling mistake in this pack.
- **Treating SecLists as a substitute for the target's own vocabulary.** The target-derived list finds the endpoints that generic lists never contain.

---

## Hand off to

Survey done -> `zp-recon-passive` (needs no target traffic, so it can start while scope is
still being confirmed). Degraded set recorded in `notes.md` for every later phase.
