---
name: zp-sharepoint
description: ZeroProtocol hunter for SharePoint Server and SharePoint Online - anonymous build fingerprinting, the recurring pre-auth ViewState and deserialization CVE families, _vti_bin and _api and _layouts enumeration, anonymous state-change preconditions, guest-link oversharing, tenant-wide search exposure, and workflow, BCS and add-in-principal abuse. Use when SPRequestGuid or X-SharePointHealthScore appears, when a path begins /_layouts/ or /_vti_bin/, or when a sharepoint.com tenant is in scope.
---

# zp-sharepoint - the farm answers before it authenticates

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

SharePoint is ASP.NET Webforms with twenty years of compatibility endpoints bolted on, and two things
pay - **an endpoint that answers anonymously when the branded UI says it cannot**, and **content the
tenant indexed for everyone without meaning to**. A build number is a lead, never a finding. The bar is
a named endpoint, an observed response, and either data your role should not reach or a state change
the farm accepted with no session.

---

## Procedure

**1. Confirm the product, and which side of it you are on.** On-prem and Online share paths and have
almost no findings in common.

```bash
H=sp.target.tld
curl -sk -D - -o /dev/null "https://$H/" | tr -d '\r' | grep -iE \
 '^(server|sprequestguid|spiislatency|x-sharepointhealthscore|microsoftsharepointteamservices|x-forms_based_auth_required|dav|set-cookie):'
```

| Signal | Read it as |
|---|---|
| `SPRequestGuid`, `X-SharePointHealthScore`, `SPIisLatency` | SharePoint, any edition - present on anonymous responses |
| `MicrosoftSharePointTeamServices: 15.0.0.0` / `16.0.0.0` | on-prem. `15.x` is SP2013, `16.x` is 2016/2019/SE |
| host `*.sharepoint.com`, cookies `FedAuth` + `rtFa` | Online. Skip the CVE arm entirely and go to steps 6-8 |
| `X-Forms_Based_Auth_Required`, or `/_layouts/14/` resolves | a Forms-auth zone (step 5), or SP2010 far past support |
| `WWW-Authenticate: NTLM` on an anonymous 401 | dual-auth binding, AD topology leak - `zp-aspnet` |

**2. Pin the exact build from the target's own body, not a header an edge can strip.**

```bash
curl -sk "https://$H/_vti_inf.html" | grep -i fpversion
curl -sk -X POST "https://$H/_api/contextinfo" -H 'Accept: application/json;odata=verbose' | python3 -c \
 'import sys,json;d=json.load(sys.stdin)["d"]["GetContextWebInformation"];print(d.get("LibraryVersion"),len(d.get("FormDigestValue","")))'
curl -sk "https://$H/_layouts/15/start.aspx" | grep -oE '1[56](\.[0-9]+){3}' | sort -u | head
```

Hand the build to `zp-cve` and the ViewState question to `zp-aspnet`. This product ships two classes on
a cycle - **pre-auth deserialization** through a `_layouts` or `_vti_bin` handler, and **ViewState
signed rather than encrypted**, so a leaked `machineKey` becomes execution. Never restate an advisory.

**3. Sweep the anonymous surface in one bounded pass**, one request per path, at the program's rate.

```bash
RPS=$(zp-scope show --json | python3 -c 'import sys,json;print(json.load(sys.stdin).get("rate_limit_rps",5))')
for p in _vti_inf.html _vti_bin/spsdisco.aspx _vti_bin/Authentication.asmx?WSDL _vti_bin/SharedAccess.asmx \
         _vti_bin/lists.asmx _vti_bin/client.svc '_api/$metadata' _api/web _api/web/CurrentUser _api/site \
         _layouts/15/start.aspx '_layouts/15/ToolPane.aspx?DisplayMode=Edit' _layouts/15/Picker.aspx \
         _layouts/15/people.aspx _layouts/15/AppPrincipals.aspx; do
  printf '%-52s ' "$p"; curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H/$p"
  sleep "$(python3 -c "print(1/$RPS)")"
done
```

**4. Test for anonymous state-change preconditions** - the highest-value on-prem shape, and provable
without ever sending a payload.

```bash
curl -sk "https://$H/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  | grep -oE '__(REQUESTDIGEST|VIEWSTATEENCRYPTED|VIEWSTATEGENERATOR)" [^>]*value="[^"]{0,24}'
```

Three questions. Does an **anonymous** request receive a `__REQUESTDIGEST`? Did `/_api/contextinfo`
mint a digest with no session (step 2 printed its length)? Is `__VIEWSTATEENCRYPTED`
**absent**, meaning ViewState is MAC-only? (The field is emitted only when ViewState is
encrypted and its value is always empty, so absence - not emptiness - is the MAC-only signal;
SharePoint pages are commonly MAC-only with no such field at all.) All three on an
out-of-support build is critical by itself. **Stop there.**

**5. Legacy Forms-auth endpoints, and the absence of the control that guards them.** The branded login
page's lockout, CAPTCHA and MFA live in the branded login page. `Authentication.asmx` is a different
code path with its own ACL.

```bash
curl -sk -X POST "https://$H/_vti_bin/Authentication.asmx" -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Mode' --data-raw \
  '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Mode xmlns="http://schemas.microsoft.com/sharepoint/soap/"/></soap:Body></soap:Envelope>' \
  | grep -oE '<ModeResult>[^<]+</ModeResult>'
```

`Windows` means this vector is N/A - say so and move on. `Forms` means the endpoint validates credentials.
To show the throttle is **absent**, send **five** `Login` calls for one synthetic account that cannot
exist (`zpcanary-0000@invalid.example`) with five random strings, recording status, byte length and
latency. Five identical rows with flat timing proves there is no control, and **that is the finding and
the stop point.** Never send a wordlist, a real or harvested username, an account list, or a credential
you were not issued - the defect is unbounded credential validation, not a cracked password.

**6. Work the authenticated surface with the lowest-privileged account you were issued** - Online and
on-prem both. The finding is what that account reaches that its role does not justify.

```bash
A=(-H 'Accept: application/json;odata=nometadata' -H "Cookie: $SP_COOKIE")
curl -sk "${A[@]}" "https://$H/_api/web/roleassignments?\$expand=Member" | python3 -c \
 'import sys,json;[print(r["Member"]["LoginName"],"|",[b["Name"] for b in r["RoleDefinitionBindings"]]) for r in json.load(sys.stdin)["value"]]'
curl -sk "${A[@]}" "https://$H/_api/web/lists?\$select=Title,Hidden,ItemCount"
```

`Everyone`, `Everyone except external users`, `All Authenticated Users` or `NT AUTHORITY\authenticated
users` holding anything above *Read* over regulated content is the oversharing finding, and on Online
it is the most common real bug in the product.

**7. Search is the exposure oracle - query it, do not scrape it.** Search executes as the *caller*, so
every hit is genuinely readable by your account.

```bash
curl -sk "${A[@]}" --get "https://$H/_api/search/query" --data-urlencode "rowlimit=10" \
  --data-urlencode "querytext='secret OR credential OR \"private key\"'" \
  --data-urlencode "selectproperties='Title,Path,Author'"
curl -sk "${A[@]}" --get "https://$H/_api/search/query" --data-urlencode "querytext='*'" \
  --data-urlencode "sourceid='B09A7990-05EA-4AF9-81EF-EDFAB16C4E31'" --data-urlencode "rowlimit=10"
```

Keep `rowlimit` small and the query count in single digits. Report **one document path and the role binding
that should have blocked it**, reduced to a hash and a byte count unless the program asks for more.

**8. Sharing links, external policy, workflows, BCS and add-in principals.** Create the artifact
yourself, on a site you own, and test **its** properties.

| Surface | Probe | The bug |
|---|---|---|
| anonymous link | upload a canary to your own library, mint an "Anyone" link, fetch it with no cookie; do the same with a "Specific people" link | it resolves unauthenticated, never expires, or the scope was enforced only in the UI |
| workflow | `_api/SP.WorkflowServices.WorkflowSubscriptionService.Current/EnumerateSubscriptions` | an authoring role can publish a workflow that fetches a URL - `zp-ssrf` |
| BCS external list | `_layouts/15/bdcadminlist.aspx`, then read one external list | the farm's stored credential reads a backend you never authenticated to |
| add-in principal | `_layouts/15/AppPrincipals.aspx`, `_layouts/15/appinv.aspx` | a site-level role grants an app-only principal tenant-wide Full Control |

**9. Stop point for this class.** You stop at **one response** - a build number, an anonymous digest, an
empty `__VIEWSTATEENCRYPTED`, a flat five-request table, one document path your role should not reach,
or one unauthenticated fetch of your own canary. You do **not** send a deserialization payload, sign a
ViewState, read a colleague's or another tenant's documents, use a key, token or farm credential you
recovered, author a workflow bound to anything but your own list, or pivot into Entra.

---

## Probes and payloads

| Probe | Tests | Positive looks like |
|---|---|---|
| `POST /_api/contextinfo`, no cookie | anonymous form-digest issuance | JSON with a non-empty `FormDigestValue` and a `LibraryVersion` |
| `GET /_layouts/15/ToolPane.aspx?DisplayMode=Edit`, no cookie | pre-auth reach of the web-part editor | 200 carrying `__REQUESTDIGEST` and `__VIEWSTATEENCRYPTED=""` |
| `GET /_layouts/15/Picker.aspx?PickerDialogType=<type>&typeName=System.String` | reflection reach of a named class | *"Only PickerDialog types can be used"* = the type loaded; *"Could not load type"* = absent |
| `SOAPAction: …/soap/Mode` on `Authentication.asmx`, then `GET /_vti_inf.html` | whether the Forms login path is live; version on the oldest handler | `<ModeResult>Forms</ModeResult>`; `FPVersion="15.00.0.000"` anonymously |
| 5 `Login` calls, one synthetic non-existent account | **absence** of throttling and lockout | five identical statuses, sizes and latencies. Then stop |
| `GET /_api/search/query?querytext='…'&rowlimit=10`, and an unauthenticated fetch of your own "Anyone" link | what your role sees tenant-wide; sharing policy versus sharing reality | a path in a site you were never granted; 200 with the canary bytes and no session |
| `openssl s_client -alpn h2,http/1.1 -connect "$H:443" </dev/null 2>&1 \| grep ALPN` | edge protocol, before any smuggling theory | `No ALPN negotiated` closes the h2 families - `zp-smuggling` |

Nothing above needs a tool beyond `curl`, `python3` and `openssl`. `nuclei` belongs to `zp-cve`, and
its SharePoint templates match on version strings far more often than on behaviour.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| anonymous `__REQUESTDIGEST` + anonymous `contextinfo` digest + `__VIEWSTATEENCRYPTED=""` on an out-of-support build | **confirmed critical.** Pre-auth state-change preconditions on code that will never be patched. Ship the three responses, not an exploit |
| the same three on a currently-patched build | **misconfiguration**, High at most - the patch or encrypted ViewState removed the deserialization arm. Name which one saved them |
| `Authentication.asmx` in `Forms` mode, five flat responses | **confirmed** - unbounded credential validation bypassing the branded login's lockout and MFA. Severity from what one valid credential would reach |
| a low-privilege account's search returns a document from a site it was never granted | **confirmed oversharing.** The strongest Online finding. Name the principal and the role binding |
| an "Anyone" link that resolves although the policy says anonymous sharing is disabled | confirmed - the policy is not enforced at the link layer |
| build in range, nothing else | **not a finding.** The defining junk report of this product - route to `zp-cve` and confirm behaviour |
| `download.aspx?SourceUrl=` echoes your external URL in a 500 | **not SSRF.** It resolves internal `SPWeb`/`SPFile` paths and the echo is error formatting. Killed unless a collector you own actually fires - `zp-ssrf` |
| `Picker.aspx` returns *"Only PickerDialog types…"*, or a 401 carries `WWW-Authenticate: NTLM` | **recon, not findings** - the inheritance check is the patch working, and an NTLM challenge is a topology lead for `zp-aspnet` |
| `/_api/$metadata`, `scriptresx.ashx`, an anonymous error page, or an anonymous site the owner published on purpose | product defaults. Judge the content, not the flag - killed on essentially every program |
| you reached data with a credential, key or token the target never issued you | **not filable.** Outside authorization - stop and escalate to a human |

Two honest notes. End-of-support findings are rejected by many programs even when accurate, so lead with the
anonymous behaviour. And on Online you test **the tenant's configuration** - a platform bug belongs to MSRC.

---

## High-value patterns

- **An out-of-support on-prem farm on a forgotten hostname** - a partner, dealer or acquisition portal an integrator built and nobody re-platformed. Every advisory after its support date applies permanently, and its branded login page usually sits in front of a live `Authentication.asmx` whose lockout, CAPTCHA and MFA were implemented only in that page.
- **`Everyone except external users` above Read on HR, legal or finance content** - the most common paid SharePoint Online finding, and one search query finds it, because search runs as the caller and so proves readability instead of guessing it.
- **An add-in or app-only principal holding tenant-wide Full Control** granted from a site-level role - privilege escalation with a paper trail; workflow and BCS are the same story for outbound fetches and stored credentials.
- **A hybrid farm** - the farm account, the sync account and the tenant trust are one identity graph. Prove the exposure, then hand the pivot to a human.

---

## Pitfalls

- **Reporting a build number.** It is a lead; `zp-cve` turns it into a finding or kills it.
- **Sending a deserialization payload or a ViewState you signed.** The precondition chain is the report. A shell is unauthorized access and is in no program's scope.
- **Spraying credentials.** No wordlists, no harvested usernames, no account lists, no "just a few common passwords". Five requests, one synthetic account that cannot exist, to prove a control is missing - and nothing past that.
- **Scraping search,** or reading a colleague's or another tenant's documents because a link resolved. Ten rows prove the exposure; ten thousand is exfiltration. Use a canary you uploaded to a site you own.
- **Calling `download.aspx` SSRF** on an echoed URL, calling the extension blocklist an oracle, or using a `machineKey`, farm credential or connection string you recovered - prove it leaked, then stop.
- **Touching Central Administration, farm settings, site deletion, or a workflow bound to a real list.** Read-only on anything shared.
- **Forgetting the farm is slow.** SharePoint 500s under load, so a fast loop - including a long `Picker.aspx` type list - reads as an availability attack.

---

## Hand off to

ViewState, `machineKey`, `.axd` handlers and IIS normalisation -> `zp-aspnet`. Build to a published
advisory -> `zp-cve`. Unlinked site collections and anonymous zones -> `zp-content-discovery`; branding
bundles and hardcoded endpoints -> `zp-js-secrets`. `FedAuth`/`rtFa`, ADFS and Entra login flows ->
`zp-jwt-oauth`, `zp-session`; `Source=` and `ReturnUrl=` redirectors -> `zp-open-redirect`. Cross-account
document access -> `zp-idor`; a route that ignores its role binding -> `zp-authz`. OData and CSOM breadth
-> `zp-api`. Workflow and BCS outbound fetches -> `zp-ssrf`; upload and extension policy -> `zp-upload`;
XML entities in a SOAP body -> `zp-xxe-lfi`. Edge-versus-IIS parsing -> `zp-smuggling`,
`zp-semantic-confusion`. Error bodies -> `zp-info-disclosure`. AD and hybrid identity ->
`zp-redteam-ad`, `zp-redteam-entra`. Dedup -> `zp-intel`. Confirmed -> `zp-triage`, then `zp-report`.

Class reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
