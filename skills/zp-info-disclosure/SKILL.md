---
name: zp-info-disclosure
description: ZeroProtocol hunter for information disclosure - verbose errors and stack traces, debug and actuator endpoints, directory listing, version banners, internal hostnames and IPs, user enumeration, file metadata (EXIF, PDF authors), API fields the UI never shows, and timing or response-shape oracles. Use when a 500 page leaks a filesystem path, when /actuator answers, or when login replies differ for real and fake accounts. Most of this class is Low or N/A - this skill decides which instance is not.
---

# zp-info-disclosure - a leak is not yet a finding

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

This is the highest-volume class in bug bounty and the one with the worst signal-to-noise. A
stack trace, a `Server:` banner, an internal `10.x` address and a `/health` page are, by
themselves, **not vulnerabilities** - and filing them burns your reputation on the program.

Apply the three-question bar to every leak **before** you write anything:

1. **Does it contain a secret?** A live credential, token, key, session, connection string.
2. **Does it contain data a person owns?** PII, another tenant's records, private content.
3. **Does it unlock a specific second bug you can then demonstrate?** Not "aids an attacker" -
   an actual next request you make and show working.

One "yes" and you have a finding whose severity is the *consequence*, not the leak. Three
"no"s and it is informational. Say so and move on; `zp-triage` will kill it anyway.

---

## Procedure

**1. Elicit the error surface.** Break each endpoint in the five ways frameworks handle badly.

```bash
EP="https://$H/api/items"
curl -sk "$EP?id=%27"                                         -o - | head -c 600; echo
curl -sk "$EP/null" -o - | head -c 600; echo
curl -sk -X POST "$EP" -H 'Content-Type: application/json' -d 'not-json'   | head -c 600; echo
curl -sk -X POST "$EP" -H 'Content-Type: application/xml'  -d '<x/>'       | head -c 600; echo
curl -sk -X POST "$EP" -H 'Content-Type: application/json' -d '{"id":{"a":1}}' | head -c 600; echo
```

Type confusion (`{}` or an array where a scalar is expected) produces the most verbose traces.

**2. Read the trace for the four things that matter**, and ignore the rest.

| In the trace | Worth | Next step |
|---|---|---|
| a DB error naming tables, columns or the dialect | the SQLi it proves | `zp-sqli` - the trace is evidence, not the report |
| an absolute path (`/var/www/app/...`, `C:\inetpub\...`) | a working LFI/traversal target | `zp-xxe-lfi`; the path alone is informational |
| an internal hostname or private IP (`db.internal.corp`, `10.0.3.11`) | an SSRF destination | `zp-ssrf`; add the name to `zp-scope` before touching it |
| framework + exact version | a CVE **you confirm is reachable** | `zp-intel` for prior art, then reproduce the CVE |
| a template-engine error from `{{7*7}}` / `${7*7}` | SSTI | `zp-rce-ssti` |
| "An unexpected error occurred", no detail | nothing | killed |

**3. Debug, management and observability surfaces.** These are where the class actually pays.

```bash
for p in actuator actuator/env actuator/configprops actuator/heapdump actuator/threaddump \
         actuator/mappings actuator/gateway/routes debug/pprof debug/pprof/cmdline \
         debug/vars metrics prometheus server-status server-info phpinfo.php info.php \
         _profiler _debugbar __debug__ telescope horizon api/info build-info version; do
  printf '%-28s %s\n' "$p" "$(curl -sk -o /dev/null -w '%{http_code} %{size_download}b' \
    --max-time 10 "https://$H/$p")"
done
```

`nuclei -u "https://$H" -tags exposure -silent` covers the same ground with maintained
fingerprints if it is installed; the loop above is the fallback and needs nothing but curl.

| Endpoint | Honest severity |
|---|---|
| `/actuator/heapdump`, `/debug/pprof/heap`, any core dump | **Critical-class.** Process memory - `strings` it for keys; a live key is the finding |
| `/actuator/env`, `/actuator/configprops`, `/debug/pprof/cmdline` | **High.** Env vars and process args routinely carry credentials |
| `/server-status`, `/metrics` with request URLs, IPs, process args | Medium - it leaks other users' request paths, which is real traffic data |
| `phpinfo()` | Medium - paths, modules, sometimes env; and it pins the exact version |
| `/actuator/health`, `/api/info`, `/version` returning a version string | **Low or N/A.** This is the one everybody files. Do not |
| a debug endpoint that also *writes* (`/loggers`, `/gateway/routes`, `/shutdown`) | no longer disclosure - that is `zp-authz` and much higher |

**Stop point for memory dumps.** Download, `strings | grep` for a key pattern, validate that
one key is live with a single identity call, and **stop**. Never enumerate the account it opens.

**4. Directory listing.** A real listing (not an SPA catch-all) shows the server's own index.

```bash
for d in / /static/ /assets/ /uploads/ /files/ /backup/ /logs/ /.well-known/ /img/; do
  printf '%-16s ' "$d"
  curl -sk --max-time 10 "https://$H$d" \
    | grep -oiE 'index of|<title>Directory listing|autoindex|Parent Directory' | head -1
  echo
done
```

Reportable only by **what is in it**. A listing of public CSS is noise; a listing of `/uploads/`
that hands you other users' documents, or `/backup/` with an archive, is the finding.

**5. Banners, internal names and IPs.** Collect, do not report.

```bash
curl -skI "https://$H/" | grep -iE 'server|x-powered-by|x-aspnet|x-generator|via|x-.*version'
curl -skI "https://$H/" | grep -iE 'x-request-id|traceparent|server-timing|x-.*-host|x-backend'
dig +short TXT "$D" | tr ' ' '\n' | grep -iE 'include:|internal|corp|vpn'
```

Version and banner disclosure is **N/A on its own** on essentially every program. It becomes a
finding only through step 2's CVE path, or when a header names a host that resolves privately -
then it is SSRF reconnaissance, and the SSRF is the report.

**6. API over-exposure - diff the JSON against the screen.** Enumerate every leaf the API
returns and ask which of them the interface ever shows.

```bash
curl -sk "https://$H/api/me" -H "Cookie: session=$TOK_A" \
  | jq -r '[paths(scalars) | join(".")] | sort | unique | .[]'
# no jq - same leaf list from the stdlib:
curl -sk "https://$H/api/me" -H "Cookie: session=$TOK_A" | python3 -c 'import json,sys
def w(o,p=""):
 if isinstance(o,dict):
  for k,v in o.items(): w(v,p+"."+k)
 elif isinstance(o,list): [w(v,p+"[]") for v in o[:1]]
 else: print(p.lstrip("."))
w(json.load(sys.stdin))'
```

Fields worth the report - `password_hash`, `mfa_secret`, `recovery_codes`, `api_key`,
`internal_notes`, `risk_score`, `kyc_*`, `*_token`. A field on **your own** record is a
hardening issue at best; the same field on **another user's** record is `zp-idor` and a real
severity. Run the diff on a list endpoint too - `/api/users?limit=1` often returns the full
row for everyone.

**7. User enumeration - three channels, and rate discipline.** Use **two accounts you own**
plus one address you control that is definitely not registered. Never a stranger's address.

```bash
KNOWN="you+zp@example.com"; UNKNOWN="zp-nonexistent-91234@example.com"
for e in "$KNOWN" "$UNKNOWN"; do
  for route in /api/login /api/password-reset /api/signup; do
    printf '%-22s %-24s ' "$route" "$e"
    curl -sk -o /tmp/zp.body -w '%{http_code} %{size_download}b %{time_total}s' \
      -X POST "https://$H$route" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$e\",\"password\":\"zp-wrong-91234\"}"
    echo "  $(head -c 120 /tmp/zp.body | tr -d '\n')"
  done
done
```

A differential in **status, body, size or time** is enumeration. Timing needs 10 samples per
side and non-overlapping spreads before you claim it - a bcrypt compare on a real account is
usually 80-300 ms slower than an early return, but network jitter mimics it.

**Never turn the oracle into a harvest.** Proving the differential on two addresses you own is
the whole proof. No wordlist of real emails, and never a password guess against any of them.

**8. File metadata.** Fetch documents the app publishes or generates, then read the fields.

```bash
curl -skO "https://$H/uploads/invoice.pdf"
exiftool -a -u -g1 invoice.pdf                   # if installed
strings invoice.pdf | grep -aE '/(Author|Creator|Producer|Title|ModDate)' | head
unzip -p report.docx docProps/core.xml           # Office - authors, org, revision
strings photo.jpg  | grep -aiE 'GPS|Nikon|Canon|Adobe|[A-Z]:\\\\|/Users/|/home/'
```

| Leaked | Verdict |
|---|---|
| GPS coordinates surviving on a **user-uploaded** photo the app republishes | real privacy finding - the platform fails to strip EXIF. Prove it on **your own** upload |
| internal usernames, `Author`, domain\\user in generated PDFs | Low, and useful input to step 7 |
| absolute build paths, internal software versions | informational; feeds step 2 |
| camera model, page count, timestamps | killed |

**9. Response-shape oracles for existence.** When a body is identical, the envelope may not be.

```bash
for id in 1 2 3 999999; do          # yours, a neighbour's, a stranger's, an absent one
  printf '%-8s ' "$id"
  curl -skI "https://$H/api/orders/$id" -H "Cookie: session=$TOK_A" \
    | grep -iE 'etag|last-modified|content-length|x-cache' | tr '\n' ' '; echo
done
```

A distinct `ETag`/`Content-Length` for existing-but-forbidden objects, or `403` versus `404`,
confirms existence across a boundary. That is a resource oracle - worth Low alone, and the
entry point to `zp-idor`. A cached private response instead means `zp-cache-poison`.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| debug endpoint returning a **live** credential, validated with one identity call | **confirmed, Critical/High.** The consequence is the severity |
| `.env` / config body with a credential you confirm is live | confirmed High. Stop at confirmation, never pivot |
| API field exposing **another user's** PII or secret | confirmed - file as `zp-idor`, not as disclosure |
| a private field on your own record only | hardening note. Usually **killed** |
| `/uploads/` listing serving other users' documents | confirmed Medium/High by data sensitivity |
| directory listing of public static assets | **killed.** The single most-filed junk report in this class |
| stack trace with a DB query | evidence for `zp-sqli`; on its own **Low at best** |
| stack trace with an absolute path and nothing else | informational. Killed unless you land the LFI |
| framework version, `Server:`, `X-Powered-By` | **N/A.** Killed. No exceptions without a reproduced CVE |
| internal hostname or private IP in a header or trace | **N/A alone.** Becomes the SSRF report or nothing |
| `/actuator/health`, `/api/version`, `/robots.txt`, `security.txt` | intended. Killed |
| GraphQL introspection enabled | configuration note, routinely N/A - the *hidden operation it reveals* is the finding. `zp-graphql` |
| Swagger/OpenAPI reachable in production | usually N/A by itself; its value is coverage for `zp-api` |
| source map in production with no secret in it | **killed.** With a secret or non-public source - `zp-js-secrets` |
| login/reset differential on two addresses you own | confirmed enumeration. Low, or Medium where the account list is itself sensitive (health, dating, finance, defence) |
| timing differential with overlapping distributions | not proven. Killed until 10 clean samples per side |
| leak only reachable with your own valid session, showing your own data | **not a disclosure.** Killed |
| a leak you found but cannot tie to a secret, PII or a demonstrated second bug | informational. Say it plainly and do not file |

---

## High-value patterns

- **`/actuator/heapdump` or `/debug/pprof/cmdline` on a forgotten subdomain** - process memory and process args carry cloud keys. Blast radius goes to `zp-cloud`.
- **`/actuator/env` and `/actuator/configprops`** - the fastest path from "a Spring host exists" to a live connection string.
- **`/server-status` and unauthenticated `/metrics`** - other users' request URLs, including tokens passed in query strings.
- **A list endpoint returning full rows** (`/api/users?limit=1`) where the UI shows three columns - the widest PII surface in most apps.
- **Verbose errors on the *staging* twin** of a hardened production host - same code, `DEBUG=true`.
- **Password-reset differential plus a leaked employee name list** from PDF metadata - steps 7 and 8 compose.
- **An error body that mirrors a header you control** - stop and check `zp-cache-poison`; a cached error page is a stored leak.
- **`403` versus `404` across tenants** on an object API - a clean resource oracle straight into `zp-idor`.

---

## Pitfalls

- **Filing a version banner, a `/health` page or a public-asset directory listing.** This is what makes triagers distrust the whole class.
- **Calling a leak "Medium because it aids an attacker".** CVSS confidentiality needs actual access to restricted data. Either land the second bug or leave it informational.
- **Reporting the leak when the leak is only the evidence.** A DB error is a SQLi report; a path is an LFI report; an internal IP is an SSRF report. File the consequence.
- **Enumerating real users' emails** to "show impact". Two addresses you own is the proof; a harvest is an attack on the users.
- **Guessing a password** after finding an enumeration oracle. Never. That is credential attack, out of scope, and ZeroProtocol stops at the differential.
- **Using a credential you extracted** beyond one read-only identity call to confirm it is live. No listing, no data pull, no lateral movement.
- **Dumping an exposed repository or an entire bucket.** Confirm it reads as real, capture a page of proof, stop - `zp-content-discovery`, `zp-cloud`.
- **Mass-probing every path on every subdomain** at full speed. Respect the program rate limit; this class tempts you into scanning.
- **Reading someone else's EXIF** to prove stripping is missing. Upload your own file and fetch it back.
- **Trusting one timing sample.** Jitter looks exactly like bcrypt.
- **Forgetting a new hostname needs its own scope check** before you send it a packet.
- **Testing only the JSON API.** SSR HTML, GraphQL, WebSocket and mobile endpoints are frequently hardened inconsistently - the mirror channel is where the extra fields survive.

---

## Hand off to

Path and backup-file fuzzing (`.git`, `.env`, archives) -> `zp-content-discovery`. Bundles and
source maps -> `zp-js-secrets`. Keys, buckets and blast radius -> `zp-cloud`. Endpoint coverage
from a spec -> `zp-api`; introspection -> `zp-graphql`. Another user's data -> `zp-idor`,
`zp-authz`. Traces that prove injection -> `zp-sqli`, `zp-rce-ssti`, `zp-xxe-lfi`. Internal
names and IPs -> `zp-ssrf`, and new hostnames -> `zp-scope`. Leaked tokens -> `zp-jwt-oauth`.
Cached private responses -> `zp-cache-poison`; cross-origin readability -> `zp-cors`. Recovered
source -> `zp-code-audit`. JS-only surfaces and screenshot proof -> `zp-browser`. Prior art and
duplicate check -> `zp-intel`, then `zp-triage` and `zp-report`.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `information_disclosure`.
