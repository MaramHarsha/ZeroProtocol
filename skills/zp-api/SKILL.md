---
name: zp-api
description: ZeroProtocol hunter for REST and general API weaknesses mapped to the OWASP API Top 10. Use when an /api/ route, Swagger or OpenAPI spec, versioned endpoint, mobile backend or B2B integration is in scope, when testing BOLA/BFLA/mass assignment on an API, when hunting undocumented or deprecated API versions, or when auditing a directly-exposed backend such as Supabase, Firebase or PostgREST. Builds the endpoint inventory first, because coverage is the finding here.
---

# zp-api - the surface behind the app

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

APIs are where the bugs are, because the browser UI is no longer the only client and the checks
that the UI implied were never written on the server. The work here is mostly **inventory**: the
endpoint the developers forgot is the one that is broken.

---

## Procedure

**1. Get the spec if there is one. This is the single highest-value step.**

```bash
for p in openapi.json openapi.yaml swagger.json swagger.yaml api-docs v2/api-docs \
         swagger/v1/swagger.json api/swagger.json .well-known/openapi.json \
         graphql/schema.json api/schema redoc spec docs/openapi.json \
         actuator/mappings api/v1/openapi.json; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$H/$p")
  [ "$code" = "200" ] && echo "200 /$p"
done
curl -sk "https://$H/openapi.json" | jq -r '
  .paths | to_entries[] | .key as $p | .value | keys[]
  | select(. as $m | ["get","put","post","delete","patch","head","options","trace"] | index($m))
  | "\(.|ascii_upcase) \($p)"'   # the select() filters out sibling keys like "parameters"
```

A spec hands you every route, every parameter, every auth requirement and every schema. Diff it
against what the UI actually uses - the delta is your target list.

**2. Otherwise build the inventory from everything you have.**

```bash
cat surface/urls.txt surface/js-endpoints.txt 2>/dev/null \
  | grep -oE '/(api|v[0-9]+|rest|graphql|gateway)/[A-Za-z0-9/_{}.-]*' \
  | sed 's/[0-9a-f]\{8,\}/{id}/g; s/\/[0-9]\+/\/{id}/g' \
  | sort -u > api-endpoints.txt
wc -l api-endpoints.txt
```

Normalising ids into `{id}` collapses thousands of URLs into the handful of real route patterns.

**3. Version pivot - old versions keep the old authorization model.**

```bash
for p in $(cut -d/ -f1-4 api-endpoints.txt | sort -u); do
  for v in v1 v2 v3 v4 beta alpha internal legacy old test dev; do
    u=$(echo "$p" | sed -E "s#/v[0-9]+/#/$v/#")
    [ "$u" = "$p" ] && continue
    printf '%-52s ' "$u"
    curl -sk -o /dev/null -w '%{http_code}\n' "https://$H$u" -H "Authorization: Bearer $TOK_A"
  done
done | grep -v ' 404$'
```

**4. Run the OWASP API Top 10 as a checklist, because coverage is the point.**

| # | Class | Test | Route to |
|---|---|---|---|
| 1 | BOLA | object id from account B, requested as A | `zp-idor` |
| 2 | Broken auth | no token, expired token, another tenant's token, `alg:none` | `zp-jwt-oauth` |
| 3 | Property-level authz | send `role`/`is_admin`/`credit`; read the object back | `zp-idor` step 6 |
| 4 | Resource consumption | **do not load-test.** Check for a missing `limit` cap and report the absence | - |
| 5 | BFLA | user token against admin functions | `zp-authz` |
| 6 | Sensitive business flows | automate a flow meant to be manual (bulk invite, checkout) | `zp-race` |
| 7 | SSRF | any URL-valued field, webhook, importer | `zp-ssrf` |
| 8 | Misconfiguration | verbose errors, debug routes, permissive CORS, missing TLS | `zp-cors` |
| 9 | Inventory management | undocumented/old versions, staging APIs, decommissioned hosts | this skill |
| 10 | Unsafe API consumption | the target trusting a third-party API's response | `zp-ssrf` |

**5. Content-type and parameter juggling - cheap, and it finds real parser gaps.**

```bash
# does a JSON endpoint also take form or XML? Different code path, different validation.
curl -sk -X POST "https://$H/api/users" -H "Authorization: Bearer $TOK_A" \
     -H 'Content-Type: application/x-www-form-urlencoded' -d 'role=admin&name=zp'
curl -sk -X POST "https://$H/api/users" -H "Authorization: Bearer $TOK_A" \
     -H 'Content-Type: application/xml' --data '<user><role>admin</role></user>'
# parameter pollution: which layer wins?
curl -sk "https://$H/api/items?id=1&id=2" -H "Authorization: Bearer $TOK_A"
# JSON type confusion
curl -sk -X POST "https://$H/api/items" -H 'Content-Type: application/json' \
     -d '{"id":["1","2"],"qty":{"$gt":0},"enabled":"true","price":-1}'
```

**6. Pagination and filter parameters** - where mass data exposure lives.

```bash
for p in "limit=99999" "per_page=99999" "page_size=0" "count=-1" "offset=0&limit=100000" \
         "fields=*" "include=user,payment_method" "expand=all" "sort=id" "filter[role]=admin"; do
  printf '%-34s ' "$p"
  curl -sk "https://$H/api/users?$p" -H "Authorization: Bearer $TOK_A" | wc -c
done
```

An endpoint honouring `limit=99999` and returning every user in the system is a real finding.
**Read one page to prove it, note the total count from the response metadata, and stop** - do not
download the dataset.

`include`/`expand`/`fields` parameters are especially productive: they often pull in related
objects that skip the authorization check applied to the primary object.

**7. Rate limiting and headers.** Check for *presence*, do not stress-test.

```bash
for i in $(seq 1 12); do curl -sk -o /dev/null -w '%{http_code} ' "https://$H/api/items" -H "Authorization: Bearer $TOK_A"; done; echo
curl -skI "https://$H/api/items" -H "Authorization: Bearer $TOK_A" \
  | grep -iE 'x-ratelimit|retry-after|access-control-allow|strict-transport|x-content-type'
```

Twelve requests tells you whether a limit exists. If none appears, report the absence on a
sensitive endpoint (login, reset, OTP) - and do not demonstrate it by actually hammering it.

**8. Directly-exposed backends.** Increasingly the whole API *is* the database.

| Backend | Tell | Check |
|---|---|---|
| **Supabase** | `supabase.co` URL, `apikey` header, `anon` JWT | RLS on every table; `/rest/v1/<table>?select=*` with the anon key; RPC functions; storage buckets; realtime channels |
| **Firebase** | `firebaseio.com`, `firestore.googleapis.com` | `/.json` on the RTDB root; Firestore rules; anonymous auth enabled |
| **PostgREST** | `/rest/v1/`, `Prefer:` headers | table access, `?select=`, embedded resources |
| **Hasura** | `/v1/graphql`, `x-hasura-*` | unauthenticated introspection, permissions per role -> `zp-graphql` |
| **AWS AppSync/API GW** | `execute-api`, `appsync-api` | missing authorizer, IAM vs API-key auth |

```bash
# Supabase anon key found in the bundle: does RLS actually exist?
curl -sk "https://<proj>.supabase.co/rest/v1/users?select=*&limit=1" \
  -H "apikey: $ANON" -H "Authorization: Bearer $ANON"
# Firebase RTDB open rules. `shallow=true` returns top-level KEYS ONLY, never values -
# `limit` is not an RTDB parameter, and an unbounded /.json on an open database dumps the
# entire dataset, which is mass exfiltration rather than proof.
curl -sk "https://<instance>.firebaseio.com/.json?shallow=true"
# modern instances are <proj>-default-rtdb.firebaseio.com or <proj>.<region>.firebasedatabase.app
# - take the exact host from the bundle rather than guessing
```

The anon key is **meant** to be public - it is not the finding. Missing row-level security is.
Retrieve one row to prove readability, then stop.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| undocumented endpoint returning data with a user token | depends what data - triage by sensitivity |
| old version reachable with weaker authz | **confirmed.** Often the cleanest API finding |
| `limit=99999` returns the whole table | confirmed mass data exposure. One page as proof |
| `include=` pulls in an object you cannot fetch directly | confirmed property/relation authz gap |
| form or XML body bypasses JSON validation | confirmed - report the specific bypassed check |
| anon Supabase/Firebase read of user data | **confirmed missing RLS/rules.** High to Critical |
| public anon key found | not a finding by itself. Test the rules |
| verbose stack trace | information disclosure, Low to Medium. Report honestly |
| no rate limit on login/OTP/reset | real finding. Report the absence, do not brute-force |
| no rate limit on a read endpoint | usually Low or N/A |
| `OPTIONS` reveals allowed methods | informational |
| 401 everywhere with a valid token | correctly scoped. Killed |

---

## High-value patterns

- **`/api/internal/`, `/api/admin/`, `/api/v1/` after v3 shipped** - the inventory finding, and it is everywhere.
- **The mobile app's API** - looser than the web API because "only our app calls it". Cross-check with `zp-mobile`.
- **B2B/partner APIs** with API-key auth and no per-object checks.
- **`include`/`expand` parameters** pulling related records past the authorization boundary.
- **Supabase with RLS disabled on one table** - the whole table to anyone with the public key.
- **A bulk or batch endpoint** where the per-item check is missing.
- **Webhook registration** - unauthenticated creation, plus SSRF -> `zp-ssrf`.
- **An API gateway route with no authorizer attached** - one route out of fifty, and it is the bug.

---

## Pitfalls

- **Downloading the dataset** to prove mass exposure. One page plus the total count.
- **Load-testing for "resource consumption"** findings. Report the missing cap instead.
- **Brute-forcing to prove no rate limit.** Twelve requests shows presence or absence.
- **Reporting a public anon key** as a leaked secret.
- **Testing only the documented routes.** The spec is a starting point, not the surface.
- **Ignoring the content-type flip.**
- **Not normalising ids** and drowning in a URL list instead of seeing the route patterns.
- **Missing deprecated versions** because the UI only uses the current one.
- **Reporting a verbose error as High.** It is information disclosure; score it honestly.

---

## Hand off to

Object ids -> `zp-idor`. Admin routes -> `zp-authz`. Tokens -> `zp-jwt-oauth`.
GraphQL -> `zp-graphql`. URL fields -> `zp-ssrf`. CORS headers -> `zp-cors`.
Upload routes -> `zp-upload`. Limit/quota logic -> `zp-race`.
Cloud-hosted backends -> `zp-cloud`. Spec or source in hand -> `zp-code-audit`.
