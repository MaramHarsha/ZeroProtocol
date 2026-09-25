---
name: zp-csrf
description: ZeroProtocol hunter for cross-site request forgery in the SameSite era - the narrow set of conditions under which CSRF is still real. Use when a state-changing POST or DELETE carries no token, when a token is present but never validated or not bound to the session, when a session cookie is SameSite=None or carries no attribute, when a GET changes state, when a JSON route also accepts text/plain, or when a method override is honoured. Supersedes the CSRF section of zp-cors.
---

# zp-csrf - the browser still sends the cookie

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Chromium's `SameSite=Lax` default killed the classic form-POST CSRF, and most reports in this class
die on that one line. What survives is short and checkable - a `SameSite=None` cookie, a `GET` that
changes state, a same-site staging point, a token that is never checked. A real finding names the
**cookie attribute that let the request cross**, the **state that changed**, and the **victim's
loss**. Read `Set-Cookie` before you write a single payload.

---

## Procedure

**1. Read the cookie jar first. This step decides whether the class is live at all.**

```bash
H=target.tld
curl -sk -D - -o /dev/null "https://$H/" | grep -i '^set-cookie:' | tr -d '\r'
# again after logging in - the session cookie is usually only set on the auth response
curl -sk -D - -o /dev/null -b cookies.txt -c cookies.txt "https://$H/dashboard" | grep -i '^set-cookie:'
```

| Session cookie | What can cross | Verdict |
|---|---|---|
| `SameSite=None; Secure` | everything - form POST, `fetch`, iframe | classic CSRF is **live**; go to step 2 |
| no `SameSite` attribute | Chromium treats it as Lax; Firefox and some WebViews still send it cross-site | live **only** in a browser you name in the report |
| `SameSite=Lax` | top-level `GET` navigation only | needs a `GET` state change (step 5) or a same-site stage (step 7) |
| `SameSite=Strict` | nothing cross-site | needs a same-site stage - subdomain XSS or takeover - or it is killed |
| `Authorization` header, no cookie | nothing is ambient | **killed.** The browser never attaches it |
| `__Host-` prefixed | host-only, no `Domain` sharing | cookie-tossing bypasses (step 6) are closed |

Chrome's old two-minute "Lax+POST" exemption was removed years ago - never build a report on it.

**2. Inventory the state changes worth forging** from the `zp-proxy` corpus or the surface map. The
endpoint matters far more than the payload.

```bash
grep -rhoE '<form[^>]+method=["'\'']?[Pp][Oo][Ss][Tt][^>]*action=["'\'']?[^"'\'' >]+' pages/ 2>/dev/null | sort -u
grep -rhoE '(csrf[-_]?token|authenticity_token|_token|csrfmiddlewaretoken|__RequestVerificationToken)' pages/ js/*.js 2>/dev/null | sort | uniq -c
```

Rank: email or password change, MFA disable, API/SSH key add, OAuth or social account link, role
grant, payout destination, webhook URL. Below that tier the report is not worth writing.

**3. Run the token ladder on one endpoint with two accounts you own.** Capture a known-good request
first, then remove exactly one thing per request.

```bash
EP="https://$H/settings/email"; A="session=$TOK_A"
send(){ curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$EP" -H "Cookie: $A" \
         -H "Content-Type: application/x-www-form-urlencoded" -d "$1"; }
send "email=zp+a@example.com&csrf_token=$TOK_CSRF_A"   # baseline - must succeed
send "email=zp+a@example.com"                          # field removed entirely
send "email=zp+a@example.com&csrf_token="              # present but empty
send "email=zp+a@example.com&csrf_token=$TOK_CSRF_B"   # your second account's token
send "email=zp+a@example.com&csrf_token=0000000000000000000000000000000000000000"
# a 200 proves nothing - re-read the resource and confirm the value actually changed
curl -sk "https://$H/api/me" -H "Cookie: $A" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("email"))'
```

Removed-and-succeeded is the strongest result. Another account's token accepted means the token is
not session-bound - equally reportable, and much more often missed.

**4. Content-Type ladder - a JSON endpoint is not automatically safe.** Only
`application/x-www-form-urlencoded`, `multipart/form-data` and `text/plain` are CORS "simple" bodies
a cross-site form can send with no preflight.

```bash
for ct in "application/x-www-form-urlencoded:email=zp@example.com" \
          "text/plain:{\"email\":\"zp@example.com\"}" \
          "application/json:{\"email\":\"zp@example.com\"}"; do
  printf '%-42s ' "${ct%%:*}"
  curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$EP" -H "Cookie: $A" \
    -H "Content-Type: ${ct%%:*}" --data-raw "${ct#*:}"
done
```

`text/plain` accepted on a JSON route is deliverable from a plain form using `enctype="text/plain"`
and the padding trick below. `application/json` alone is **not** form-deliverable - say so rather
than implying a form can send it.

**5. Method and override.** `SameSite=Lax` still sends the cookie on a top-level `GET`.

```bash
curl -sk -o /dev/null -w 'GET %{http_code}\n' "$EP?email=zp@example.com" -H "Cookie: $A"
curl -sk -o /dev/null -w '_method %{http_code}\n' -X POST "$EP" -H "Cookie: $A" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d '_method=DELETE&id=<your-own-object>'
for h in X-HTTP-Method-Override X-HTTP-Method X-Method-Override; do
  printf '%-24s ' "$h"
  curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$EP" -H "Cookie: $A" -H "$h: PUT" \
    -H 'Content-Type: application/x-www-form-urlencoded' -d 'email=zp@example.com'
done
```

A framework that reads `_method` from a form body turns every `DELETE`/`PUT` route into a
form-reachable one. Where the override makes two components read one request differently, that is
also `zp-semantic-confusion`.

**6. Header checks and cookie writes - where the remaining bypasses live.**

```bash
for o in OMIT null https://evil.tld "https://$H.evil.tld" "https://sub.$H"; do
  [ "$o" = OMIT ] && HDR=() || HDR=(-H "Origin: $o")
  printf '%-30s ' "$o"
  curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$EP" -H "Cookie: $A" "${HDR[@]}" \
    -H 'Content-Type: application/x-www-form-urlencoded' -d 'email=zp@example.com'
done
```

`curl` sets any `Origin` it likes; a browser cannot. A spoofed-header success proves the check is a
string comparison, **not** an exploit - you still owe a delivery path: an omitted `Origin` (some
navigations and downgrades genuinely omit it), `null` from a sandboxed iframe, or an origin you
control (`zp-takeover`, `zp-xss`). Double-submit is the same - it breaks only if you can write a
cookie on the parent domain, which needs a sibling host you hold and no `__Host-` prefix.

**7. Prove it in a real browser.** `zp-browser` drives the engine; SameSite is browser behaviour, so
the browser is the witness. Host the PoC on your own origin, log in as **your second account**, load
the page, then confirm the change in that account's own settings. Screenshot your hostname in the
address bar beside the changed state.

**8. Stop point for this class.** You stop at a state change in **an account you own**, delivered
from **your own page**. You do not send the link to another user, forge a request into a real user's
session, alter a payout destination on anything but your own test object, or chain onward into the
data the forged request unlocks - that is a separate report through `zp-triage`.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| token field deleted, or `csrf_token=` left empty | validation only when present, or format-only checks | baseline status code, state changed |
| token from your second account | tokens not bound to the session | same - file as "token not session-bound" |
| `Origin` omitted, or `null` from `<iframe sandbox="allow-forms allow-scripts">` | presence-only origin checks | accepted - now find the real delivery path |
| `<form enctype="text/plain">` with `name='{"email":"a@b.c","x":"' value='"}'` | Content-Type not enforced on a JSON route | valid JSON reaches the handler from a form |
| `<img src="https://$H/api/x?...">`, or `_method=DELETE` / `X-HTTP-Method-Override: PUT` in a form POST | `GET` state change with a Lax cookie; method-based routing or verb-scoped middleware | state changed with no script; a protected verb reached from a form |
| `/setup/api/start/..%2f..%2fadmin%2fusers` | token middleware scoped by the pre-normalisation path | protected route executes, no token sent |
| GraphQL `?query=mutation{...}` over `GET` | CSRF check skipped for `GET`, mutations allowed anyway | mutation executes - `zp-graphql` |
| `new WebSocket("wss://$H/hubs/x")` from a foreign page | the upgrade cannot carry a custom header, so the check was dropped | `101` plus a state-changing frame - `zp-websocket` |
| OAuth callback replayed with a fixed or absent `state` | `state` is structurally the CSRF token of the link flow | your identity attached to another account - `zp-jwt-oauth` |

No-tool fallback is `curl` plus `python3` (`http.cookies.SimpleCookie` parses `Set-Cookie` exactly);
only the browser step needs an engine. `nuclei`'s CSRF templates check token *presence*, never
validation - they produce the first rows of the next table.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| token removed, request succeeds, cookie is `SameSite=None`, state changed | **confirmed CSRF.** Severity from the action - email, password or MFA is ATO-grade |
| another account's token accepted on your session | confirmed - token not session-bound. Same ceiling |
| `GET` changes state and the cookie is Lax or `None` | confirmed, and the cheapest PoC in the class (`<img>`) |
| JSON route also accepts `text/plain` with no token | confirmed - show the `enctype="text/plain"` form working in a browser |
| `_method`/override reaches `DELETE` from a form POST, or a path traversal slips past the token middleware | confirmed - the second is usually higher, it is a middleware-scoping bug |
| cookie is `SameSite=Lax`, endpoint is POST-only, JSON-only and token-validated | **killed.** The majority case today |
| succeeded only with an `Origin` you set by hand in `curl` | **not exploitable yet.** No browser sends that. Killed until you own the origin |
| works only from a subdomain you do not control, or needs an XSS you have not found | killed as CSRF; a lead for `zp-takeover` or `zp-xss`. Find it, then file the chain |
| the request needs a value only the victim knows (current password, a fresh OTP) | killed - re-auth is the control working |
| logout, login, read-only `GET`, cart add, theme toggle, newsletter opt-in | no meaningful loss. Killed or informative on nearly every program |
| `200` returned but the value never changed | killed - you proved nothing. Re-read the resource |
| double-submit "bypass" assuming you can set a parent-domain cookie | killed until you show the cookie-write primitive |

"A CSRF token is missing" is not impact. "Any page can change a logged-in user's email address, and
the reset flow then delivers the token there" is.

---

## High-value patterns

- **Email change then password reset**, and **MFA disable or recovery-code regeneration** - the canonical ATO chains, and the reason this class still pays; security settings are guarded less often than payments.
- **OAuth and social account-linking callbacks** with a reused, predictable or absent `state` - attaches your identity as a permanent login path.
- **GraphQL over `GET`** - one endpoint, every mutation, and the token check frequently keyed to the method.
- **A `SameSite=None` cookie set for an embed or legacy iframe integration** - one attribute re-opens the whole app; likewise **sibling-subdomain staging**, where a marketing, status or legacy host under the same parent makes a Lax cookie same-site.
- **`/api/*` routes with CSRF middleware excluded** because "API clients do not need it", while the SPA is a browser client - and **self-hosted dashboards on subdomains** (Grafana, Kibana, CI) with weak defaults; version-check those via `zp-cve`.
- **Mobile deep links** performing a state change on the app's ambient session - a link or QR code is the delivery. `zp-mobile`.

---

## Pitfalls

- **Writing the report before reading `Set-Cookie`.** Lax makes most of this class impossible.
- **Claiming a form can send `application/json`.** It cannot. `text/plain` or nothing.
- **Treating a `curl`-set `Origin` as an exploit,** or relying on Chrome's removed Lax+POST window or a browser default you never verified.
- **Filing logout, login or cart CSRF,** or a `200` you never confirmed by re-reading the resource.
- **Forging a request into a real user's session.** Two accounts you own, always - anything else is unauthorized access, not testing.
- **Testing shared or production objects** - payout destinations, org-wide settings, another tenant's webhook. Use your own, and take the hosted PoC down afterwards.
- **Looping the ladder over every endpoint.** It is ~10 requests per endpoint; pick the four that end in ATO or money, and keep the program's rate limit.
- **Stopping at "the request executed".** Name what the victim loses, or `zp-triage` will kill it for you.

---

## Hand off to

New origin or subdomain -> `zp-scope` first. Browser proof -> `zp-browser`; captured requests ->
`zp-proxy`. Cross-origin **reads**, `Access-Control-Allow-*` and `postMessage` -> `zp-cors` (this
skill replaces its CSRF section). `state`/`RelayState`, account linking and reset flows ->
`zp-jwt-oauth`. Same-site staging -> `zp-xss`, `zp-takeover`. Mutations over `GET` -> `zp-graphql`;
upgrade-time checks -> `zp-websocket`; `/api/*` middleware gaps -> `zp-api`, `zp-authz`. Override and
path-normalisation differentials -> `zp-semantic-confusion`. Skipped workflow rules ->
`zp-business-logic`; one-time-token abuse -> `zp-race`. Tokens in bundles -> `zp-js-secrets`.
Dashboard versions -> `zp-cve`. Deep links -> `zp-mobile`. Dedup -> `zp-intel`, then `zp-triage` and `zp-report`.
