---
name: zp-recon-passive
description: ZeroProtocol phase 2 - build the attack surface from third-party sources without sending a single packet to the target. Use when starting recon on a new domain or wildcard, when asked to enumerate subdomains, find an attack surface, do OSINT on a company, mine historical URLs, search certificate transparency, hunt GitHub leaks, or find an origin IP behind a CDN. Runs before the scope is confirmed, because it queries CT logs, archives and search engines rather than the target itself.
---

# zp-recon-passive - surface without contact

**Phase:** 2 | **Gate:** a scope file must exist. Confirmation is **not** required - every
source here is a third party, so no packet reaches the target.

The distinction that makes this phase legal before confirmation: you are reading public
records *about* the target, not touching it. The moment you resolve-and-probe, you are in
`zp-recon-active` and you need `zp-scope` exit 0.

---

## Procedure

**1. Seed from the scope, not from imagination.** Every root in `in_scope` becomes a seed.
Wildcards are seeds; apexes are seeds; a CIDR is a seed for reverse DNS.

```bash
zp-scope show --json | jq -r '.in_scope[]' | sed 's/^\*\.//' | sort -u > surface/seeds.txt
```

**2. Certificate transparency first.** CT is the highest-yield keyless source in existence:
every TLS cert ever issued for the domain, including the internal hostnames someone
accidentally put in a SAN.

```bash
while read -r d; do
  curl -sS --max-time 60 "https://crt.sh/?q=%25.$d&output=json" \
    | jq -r '.[].name_value' | tr 'A-Z' 'a-z' | sed 's/^\*\.//'
done < surface/seeds.txt | sort -u | grep -E '^[a-z0-9.-]+$' >> surface/hosts.txt
```

**3. Stack the other keyless sources.** Each finds hosts the others miss, so union them.

```bash
D=target.com
curl -sS "https://jldc.me/anubis/subdomains/$D"            | jq -r '.[]?'
curl -sS "https://api.hackertarget.com/hostsearch/?q=$D"    | cut -d, -f1
curl -sS "https://rapiddns.io/subdomain/$D?full=1"          | grep -oE "[a-z0-9.-]+\.$D"
curl -sS "https://otx.alienvault.com/api/v1/indicators/domain/$D/passive_dns" \
  | jq -r '.passive_dns[].hostname'
# `domain:$D` matches any scan that merely *contacted* the target, and `page.domain` is the
# site that was scanned - often an unrelated third party - so filter to the target like the
# rapiddns line above, and page with `search_after` instead of asking for one huge page
curl -sS "https://urlscan.io/api/v1/search/?q=domain:$D&size=100" \
  | jq -r '.results[] | .page.domain, .task.domain' | grep -E "(^|\.)${D//./\\.}$"
```

With tooling, the same work in one line each:

```bash
subfinder -d "$D" -all -silent | anew surface/hosts.txt
assetfinder --subs-only "$D"   | anew surface/hosts.txt
amass enum -passive -d "$D"    | anew surface/hosts.txt
```

**4. Mine the archives for endpoints nobody links to any more.** Historical URLs are where
deprecated-but-live admin routes and forgotten API versions come from.

```bash
curl -sS --max-time 180 \
  "http://web.archive.org/cdx/search/cdx?url=*.$D/*&output=text&fl=original&collapse=urlkey" \
  >> surface/urls.txt
# with tooling:
gau --subs "$D" | anew surface/urls.txt
echo "$D" | waybackurls | anew surface/urls.txt
```

Historical URLs are **discovery, not proof of reachability**. Every one needs a live check
in `zp-recon-active` before it means anything.

**5. Triage the URL corpus into leads immediately** - a 200k-line url file you never sort
is not recon.

```bash
grep -Ei '/api/|/graphql|/v[0-9]+/|swagger|openapi|\.json$'        surface/urls.txt | sort -u > surface/api-candidates.txt
grep -Ei 'login|logout|register|reset|forgot|oauth|saml|sso|callback|token|session' surface/urls.txt | sort -u > surface/auth-candidates.txt
grep -Ei '\.(js|mjs|map)([?#]|$)'                                  surface/urls.txt | sort -u > surface/js.txt
grep -Ei '\.(bak|old|sql|zip|tar\.gz|env|log|conf|ya?ml|git)([?#]|$)' surface/urls.txt | sort -u > surface/interesting-files.txt
grep -oE '\?[^ ]+' surface/urls.txt | tr '&' '\n' | cut -d= -f1 | tr -d '?' | sort -u > surface/params.txt
```

**6. Search code hosts for leaks.** This finds credentials and internal hostnames that no
amount of scanning would.

```bash
# needs GITHUB_TOKEN; unauthenticated search is rate-limited into uselessness
for q in "$D password" "$D api_key" "$D secret" "$D BEGIN RSA" "$D internal" "$D.s3.amazonaws.com"; do
  gh api -X GET search/code --raw-field "q=$q" --jq '.items[]?.html_url' 2>/dev/null
done | sort -u
github-subdomains -d "$D" -t "$GITHUB_TOKEN" | anew surface/hosts.txt
```

Also check what is already public and indexed: `site:$D -www`, `site:$D inurl:api`,
`site:$D ext:log|ext:sql|ext:bak`, `site:pastebin.com "$D"`,
`site:trello.com "$D"`, `site:s3.amazonaws.com "$D"`.

**7. ASN and netblock pivot** - for wide scopes, the IP ranges are the real surface.

```bash
curl -sS "https://api.bgpview.io/search?query_term=$ORGNAME" | jq -r '.data.ipv4_prefixes[]?.prefix'
whois -h whois.radb.net -- "-i origin AS$ASN" | awk '/^route:/{print $2}' | sort -u
```

Every derived prefix needs an **ownership decision** from `zp-scope` before it is probed.
An ASN that merely mentions the brand is not authorization.

**8. Origin IP behind a CDN** - still passive, still high value. Old certs and historical
DNS remember where the origin used to live.

```bash
curl -sS "https://crt.sh/?q=$D&output=json" | jq -r '.[].name_value' | sort -u   # forgotten SANs
curl -sS "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=ssl.cert.subject.CN:$D" \
  | jq -r '.matches[].ip_str'
```

**9. Dedupe, then hand over.** `zp-scope filter` refuses while the scope is unconfirmed (exit 3) and writes an **empty** file, so check it landed rather than trusting the redirect.

```bash
sort -u surface/hosts.txt -o surface/hosts.txt
wc -l surface/hosts.txt surface/urls.txt surface/js.txt surface/params.txt
# THE funnel before any active phase - note it needs a CONFIRMED scope, so it belongs at
# the handoff into zp-recon-active, not here. Run it once the user has confirmed:
cat surface/hosts.txt | zp-scope filter > surface/in-scope.txt
```

---

## Confirm or kill

| Observation | Meaning |
|---|---|
| host appears in CT only, never resolves | almost certainly dead or internal - park it, do not claim it |
| host resolves to `127.0.0.1` / RFC1918 | internal-only; interesting as an intel leak, not a target |
| host in CT with a non-prod label | check it against `out_of_scope` before it enters any list |
| archived URL returns 404 now | historical, not a finding. Note the path pattern, drop the URL |
| a secret found in GitHub code search | **do not use it.** Finding it is the bug. Validate scope and report |
| ASN matches the brand name only | not ownership. Send it to `zp-scope` step 7 |
| 10k+ hosts from a wildcard | expected. Rank in phase 4; do not probe them all |

**The false positive that wastes the most time here** is treating a CT-log hostname as a
live host. CT records what was *issued*, not what exists. Nothing from this phase is real
until `zp-recon-active` resolves and probes it.

---

## High-value patterns

- **Non-prod that is in scope.** `dev.`, `staging.`, `uat.` with production data and no WAF. Check the scope first - often excluded, sometimes explicitly included and barely defended.
- **Forgotten API versions.** `/api/v1/` still live after `/api/v3/` shipped, with the old authorization model.
- **Acquisition estates.** Recently acquired brands run on unmigrated infrastructure. CT for the parent often reveals the child.
- **Internal hostnames in SANs.** `*.internal.target.com` in a public cert names the internal estate for free.
- **A leaked key in a JS bundle or a public repo.** Highest-severity single artifact this phase produces, and the `+55` score in the ranking exists for it.

---

## Pitfalls

- **Probing during "passive" recon.** `httpx`, `nmap`, `ffuf` are not passive. They belong to the next skill and they need scope exit 0.
- **Using a found credential.** Report it; never authenticate with it.
- **Treating a brand-name substring as ownership.** Squatters and shared hosts look identical to real assets.
- **Never deduping.** The same host arrives from six sources; unsorted files make every later count a lie.
- **Ignoring the sibling TLDs the program lists.** Recon on the flagship `.com` alone and calling it exhausted misses whole estates.
- **Dumping 200k URLs with no triage.** The grep pass in step 5 is where the value is.
- **Leaking the target.** Do not paste target hostnames into third-party "analysis" web services.

---

## Hand off to

`zp-recon-active` to find out what is actually alive - **needs `zp-scope` exit 0**.
Secrets found -> `zp-js-secrets` for validation and reporting.
Dangling CNAMEs spotted in CT -> `zp-takeover`.
Derived netblocks or unlisted hosts -> back to `zp-scope` for an ownership decision.
