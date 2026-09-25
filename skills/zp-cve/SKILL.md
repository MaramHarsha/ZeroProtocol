---
name: zp-cve
description: ZeroProtocol hunter for known published vulnerabilities on a target - turning a version fingerprint into a confirmed, reportable finding. Use when a banner, header, changelog or dependency file reveals a version, when checking whether a host is affected by a published CVE, when running nuclei templates, or when asked whether something is exploited in the wild. Backed by the local corpus in reports/ - CISA KEV, nuclei-templates, Exploit-DB and two CVE-to-PoC indexes. Treats a version string as a lead and never as a finding.
---

# zp-cve - a version number is not a vulnerability

**Phase:** 5 (known-CVE sweep) | **Gate:** **active.** `zp-scope check <target>` must exit 0
before any request. Exit 1 refuse · 3 stop · 4 stop. A nuclei run is thousands of requests, so it
needs the program's rate limit as much as any other active phase.

**The rule this whole skill exists to enforce:** a banner saying `nginx/1.18.0` is a *lead*.
Banners are edited, back-ported patches are invisible to them, and vendors ship fixes without
bumping the version. A report that says "you run version X, which has CVE-Y" and shows nothing
else is the single most common junk submission in bug bounty, and it will be closed as
**informative** or **N/A**.

Confirm the **behaviour**, not the version.

---

## 1. Fingerprint, then generate candidates

The surface comes from `zp-recon-active` (headers, `Server`, `X-Powered-By`, cookies, favicon),
`zp-js-secrets` (bundle versions), and `zp-code-audit` (lockfiles, `requirements.txt`,
`pom.xml`, `composer.lock`) when source is in hand.

```bash
curl -skI "https://$H/" | grep -iE 'server|x-powered-by|x-generator|x-drupal|x-aspnet-version'
zp-reports find "<product> <version>"
```

Dependency manifests are far more reliable than banners, because they are what actually shipped.

## 2. Triage the candidates - KEV first

```bash
zp-reports cve CVE-2021-44228      # KEV status + nuclei template + PoC repos + Exploit-DB
```

Prioritise in this order, because it matches what a program will actually pay for:

| Priority | Signal |
|---|---|
| 1 | **listed in CISA KEV** - confirmed exploited in the wild, and the operator needs to know today |
| 2 | pre-auth RCE or auth bypass with a public PoC |
| 3 | authenticated RCE, or an SSRF/deserialization chain |
| 4 | anything requiring a precondition you cannot meet |
| 5 | DoS-class CVEs - **do not test them**, they are excluded by essentially every program |

`zp-reports status` shows what is synced locally; `zp-reports sync all` pulls the corpora.

## 3. Confirm the behaviour

```bash
# scope-gated, rate-limited, targeted at the specific candidate - not a blanket scan
RPS=$(zp-scope show --json | jq -r '.rate_limit_rps // 5')
nuclei -u "https://$H" -t reports/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml \
       -rate-limit "$RPS" -no-interactsh
```

Read the template before you run it. You are looking for one thing: **does it confirm by observed
behaviour, or does it match on a version string?** A template whose matcher is a banner regex
proves nothing your own `curl -I` did not, and a finding built on it is a version report wearing a
scanner's clothes.

For blind classes (Log4Shell, blind SSRF, OOB deserialization) you need a collector **you
control** — see `zp-toolchain`. Never use a third-party interactsh instance for a real target;
the callback carries their hostnames and sometimes their data.

**Stop at proof.** The same stop points as every other ZeroProtocol class: `id`-equivalent output
for RCE, a version string for SQLi, the role name for metadata SSRF. A public exploit that pops a
shell is still an exploit — run the detection half, not the payload half. Where a PoC has no safe
mode, reproduce its *detection* step by hand rather than running someone's weaponised script at a
live target.

## 4. Rule out the four false positives

| Looks like a hit | Actually |
|---|---|
| version in range, no behavioural confirmation | **unconfirmed.** Back-ported patches are the norm on distro packages |
| nuclei matched on a banner regex | the template proved the banner, not the bug |
| WAF returns a block page for the payload | virtual patching, or the WAF answering — not the app being vulnerable |
| the endpoint 404s | the component is present but this path is not the vulnerable one |
| vendor advisory says "affected" but config is required | check the config; most CVEs need a non-default one |

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| behavioural confirmation of the CVE, reproduced twice | **confirmed.** Severity from the CVE and the reachable impact |
| KEV-listed and behaviourally confirmed | **confirmed, report the same hour** - it is being exploited now |
| version in range only | **not a finding.** Report it only if the program explicitly accepts version-based submissions |
| nuclei hit whose matcher is a version string | killed until you confirm behaviour by hand |
| public PoC works, but only against a non-default configuration the target does not run | killed |
| the CVE is in a dependency that is present but unreachable | **not reachable, not a finding** - see `zp-code-audit` |
| DoS-class CVE | do not test. Out of scope essentially everywhere |
| the program's policy lists known-CVE/version findings as out of scope | killed before you start — read the policy first |
| already-patched host, CVE just published | fine. Move on and say the sweep was clean |

**Bug bounty reality worth stating plainly:** most confirmed known-CVE findings on a mature
program come back as *informative* or *duplicate*, because the defenders read the same advisories
you do. The exceptions are worth hunting: a **forgotten host** the patch cycle missed, a
**non-default configuration** the vendor advisory undersells, and a **CVE in a dependency** that
the main product exposes in an unexpected path. That is where this class actually pays.

---

## High-value patterns

- **A KEV-listed CVE on a forgotten subdomain** — the single best outcome here, and usually a staging or acquisition host from `zp-recon-passive`.
- **An edge appliance** — VPN, file transfer, mail gateway, ADC. Pre-auth, internet-facing, and historically the source of the worst incidents.
- **A dependency CVE reachable through an unusual route** in the main app.
- **A CVE the vendor patched silently** with no version bump, which only behaviour reveals.
- **An admin panel or dev tool** exposed on a non-standard port — `zp-recon-active` finds these.
- **A CVE in something the target self-hosts** (CI server, wiki, object store) rather than in their own code.

---

## Pitfalls

- **Reporting a version banner.** The defining mistake of this class.
- **Running a weaponised public exploit** at a live target. Detection half only.
- **Blanket-scanning with every nuclei template** at full speed — that is a scan, not a hunt, and it will trip the WAF and the program's patience.
- **Using a shared or third-party OOB collector**, leaking the target's internals.
- **Testing DoS CVEs.**
- **Trusting a template's matcher** without reading it.
- **Ignoring the program policy**, which very often excludes version-based and known-CVE findings.
- **Assuming distro packages track upstream versions.** They back-port; the banner lies.
- **Leaving exploit artifacts** — files, users, callbacks — behind. Clean up and say so.

---

## Hand off to

Specific published-CVE skills where ZeroProtocol has one: `zp-cve-2026-41940` (cPanel/WHM
pre-auth bypass), `zp-cve-lightrag` (three LightRAG advisories).
Confirmation of the underlying class -> `zp-rce-ssti`, `zp-sqli`, `zp-ssrf`, `zp-xxe-lfi`,
`zp-jwt-oauth`. Dependency reachability -> `zp-code-audit`.
Self-hosted infrastructure -> `zp-cloud`. Confirmed -> `zp-triage`, `zp-report`.

Corpus: `reports/` — CISA KEV (public domain), nuclei-templates (MIT), Exploit-DB (GPL-2.0),
PoC-in-GitHub (CC0), trickest/cve (MIT). See `reports/README.md`.
