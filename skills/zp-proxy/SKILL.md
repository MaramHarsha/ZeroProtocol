---
name: zp-proxy
description: ZeroProtocol integration for intercepting proxies - Caido, Burp Suite and mitmproxy. Use when a proxy is running or should be, when a captured traffic corpus exists, when replaying or mutating a saved request, when driving a proxy through its MCP server or API, or when the app is a SPA whose real requests are invisible to curl. A traffic corpus beats guessing: test the requests the app actually makes.
---

# zp-proxy - test the requests the app really makes

**Phase:** 1b / continuous | **Gate:** the proxy itself is local and needs no gate. Every request
you **replay** at the target is active - it inherits `zp-scope check` exit 0, and a proxy makes it
very easy to forget that. Configure the scope in the proxy too, so its own automated features
cannot wander.

A curl-only hunt tests the requests *you* thought of. A proxy corpus tests the requests the
application actually makes - with the right headers, the right content types, the right nested
JSON and the CSRF tokens already in place. For a modern SPA that difference is most of the
attack surface.

---

## Procedure

**1. Pick what is available and set the scope inside it.**

| Tool | Best at | Get the corpus out |
|---|---|---|
| **Caido** | modern UI, HTTPQL filtering, an agent-friendly API and MCP server | HTTPQL query -> export, or the GraphQL API |
| **Burp Suite** | the deepest tooling; Repeater/Intruder/Scanner; MCP extension | project file parse, or the REST API on Pro |
| **mitmproxy** | scriptable, headless, CI-friendly, free | `mitmdump -w flows` then `mitmdump -nr flows` |

Set the target scope in the proxy before browsing. Then your own automated features - passive
scanning, crawling - stay inside it. This is the same discipline as `zp-scope`, applied to the
tool rather than the agent.

**2. Capture a real session.** Browse the app as a normal user, with **your own** test account,
and exercise every feature once: login, profile edit, search, upload, export, settings, a
purchase in test mode, logout. Ten minutes of deliberate clicking produces a better endpoint
inventory than an hour of fuzzing.

```bash
# headless capture with mitmproxy
mitmdump -w flows.mitm --set confdir=~/.mitmproxy
# then mine it
mitmdump -nr flows.mitm -s /dev/stdin <<'PY'
def response(flow):
    r = flow.request
    if any(r.pretty_url.endswith(e) for e in (".png",".jpg",".css",".woff2",".svg",".gif")):
        return
    print(f"{r.method}\t{flow.response.status_code}\t{r.pretty_url}")
PY
```

**3. Turn the corpus into the surface artifacts the pipeline expects.**

```bash
mitmdump -nr flows.mitm -s dump.py > proxy-requests.tsv
cut -f3 proxy-requests.tsv | sort -u >> surface/endpoints.txt
# parameters the app actually sends - far better than a generic wordlist
cut -f3 proxy-requests.tsv | grep -oE '\?.*' | tr '&?' '\n' | cut -d= -f1 | sort -u >> surface/params.txt
```

A parameter list derived from real traffic is the single best input to
`zp-content-discovery` and every injection hunter.

**4. Save requests as files and replay them.** This is the cleanest way to test an endpoint that
needs auth, a CSRF token and a nested JSON body.

```bash
# a saved raw request replays exactly, with every header the app sent
curl -sk --request-target '/api/orders' -X POST "https://$H" \
     -H @headers.txt --data-binary @body.json
# ffuf and sqlmap both take a saved request - this is how you fuzz an authenticated endpoint
ffuf --request req.txt --request-proto https -w wordlist.txt -ac
sqlmap -r req.txt --batch --level 2 --risk 1 --banner
```

`ffuf --request` and `sqlmap -r` are the two highest-value uses of a saved request: they inherit
the session, the content type and the body shape, so the fuzzing is against the real endpoint
rather than a guess at it.

**5. Drive the proxy programmatically when it offers an API or MCP server.**

Caido and Burp both expose interfaces an agent can call: list the sitemap, fetch a request by id,
send a modified request, read the response. When such a tool is available in the session, prefer
it over shelling out - it keeps the traffic inside the proxy's history, which means your evidence
is captured automatically and your scope configuration still applies.

Use it to: pull the full sitemap into `surface/endpoints.txt`, re-send one request with one header
changed (the core loop of `zp-authz` and `zp-idor`), and diff two responses.

**6. Use the proxy's history as the evidence store.** It records the exact request and response,
with timestamps, which is precisely what `zp-report` needs. Export the two or three relevant
entries per finding - and **redact** the session cookie and any other user's data before
attaching anything.

**7. Passive findings are free.** A proxy's passive checks flag missing security headers, cookie
flags, verbose errors and mixed content while you browse. Treat them as *leads*, not findings:
most are informational, and a report consisting of passive-scanner output is the archetype of a
low-signal submission.

**8. Know what the proxy cannot do.** Automated active scanning against a bounty target is
frequently **forbidden by the program policy** - check it in `zp-scope` before enabling any
active scan, and respect the rate limit. A scanner at default concurrency will trip a WAF and get
your IP blocked within a minute.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| a request in the corpus that the UI never exposes | good lead - an internal or debug endpoint |
| an endpoint returning more fields than the UI renders | data over-exposure -> `zp-api`, `zp-idor` |
| a token or key in a response body | check whether it should be there -> `zp-js-secrets` |
| passive scanner: missing security header | informational. Usually not worth reporting alone |
| passive scanner: cookie without `HttpOnly`/`Secure` | Low; matters only as part of an XSS chain |
| passive scanner: "possible XSS" | a lead. Verify manually and in a browser, or drop it |
| active scanner finding | **never report unverified.** Reproduce it by hand first |
| a replayed request succeeds without its auth header | that is a real finding -> `zp-authz` |

**The rule for any scanner output:** if you cannot reproduce it with a hand-built request and
explain why it happens, it does not go in a report.

---

## High-value patterns

- **The SPA's real API calls** - nested JSON bodies and custom headers you would never have guessed.
- **A request the UI makes once, on a rare path** - an export, an admin preview, an onboarding step.
- **Fields the client sends but the UI does not show** - `role`, `tenant_id`, `is_internal` -> `zp-idor` mass assignment.
- **Responses containing more than the UI renders** - the classic over-exposure finding.
- **A saved authenticated request piped into ffuf** - authenticated content discovery, which most hunters skip.
- **The mobile app's traffic** captured through the same proxy -> `zp-mobile`, then `zp-api`.

---

## Pitfalls

- **Running an automated active scan without checking the policy.** Commonly forbidden, and it will get you blocked.
- **Forgetting the proxy has its own scope.** An unscoped crawler will fetch out-of-scope hosts for you.
- **Reporting passive-scanner output as findings.**
- **Attaching an unredacted history entry** with your session cookie in it.
- **Letting the proxy follow redirects out of scope.**
- **Scanner default concurrency** against a rate-limited program.
- **Capturing traffic while logged into a real user's account** - use your own test accounts.
- **Trusting the sitemap as complete.** It only contains what you browsed; combine it with `zp-recon-passive` and `zp-js-secrets`.
- **Leaving an intercepting proxy trusted in your OS store** after the engagement. Remove the CA.

---

## Hand off to

Endpoint inventory -> `zp-api`, `zp-graphql`, `zp-content-discovery`.
Saved authenticated requests -> every injection hunter (`zp-sqli`, `zp-xss`, `zp-ssrf`).
One-header-changed replays -> `zp-idor`, `zp-authz`. Mobile traffic -> `zp-mobile`.
History entries -> `zp-report` as evidence, redacted.
