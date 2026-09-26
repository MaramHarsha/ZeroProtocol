---
name: zp-exceptional
description: ZeroProtocol hunter for exceptional conditions and error-state behaviour - what an application does once it is pushed off the happy path. Use when a field accepts empty, null, negative, zero, oversized or wrong-typed values, when a request can be truncated mid-body, when a workflow can be driven out of order or replayed, and above all when an error path may skip an authorization or validation check and fail OPEN. Resource-shaped inputs are reported, never exercised.
---

# zp-exceptional - the path nobody tested

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Happy-path code is reviewed; error handlers are not. This class hunts the handler that catches an exception
and then **continues** - the `try` that dies after the privileged write, the `except` that returns allow,
the validator that throws and is answered with `200`. A crash is not a finding; the finding is a
**differential** - the malformed request does what the clean request from the same identity is refused.

---

## Procedure

**1. Capture a known-good request and keep it.** Every probe below is one deviation from it.

```bash
H=target.tld; EP="https://$H/api/orders"          # two accounts you own, one unauthenticated
A="Authorization: Bearer $TOK_A"; B="Authorization: Bearer $TOK_B"
send(){ local hdr=(); [ "$1" != - ] && hdr=(-H "$1"); printf '%-42s ' "$(printf %.40s "$2")"
        curl -sk -o /tmp/zp.out -w '%{http_code} %{time_total}s ' --max-time 20 \
          -X POST "$EP" "${hdr[@]}" -H 'Content-Type: application/json' --data-binary "$2"
        head -c 90 /tmp/zp.out | tr -d '\n'; echo; }
send "$A" '{"quantity":1,"coupon":"SPRING","note":"ok"}'   # must succeed. Record the object id
```

**2. Generate the type and boundary matrix, read it, then send it.** One field mutated per request is
the only way a result means anything.

```bash
python3 - <<'PY' > /tmp/zp.bodies
import json
base = {"quantity": 1, "coupon": "SPRING", "note": "ok"}
odd  = [0, -1, -0.0, 2**63, 1e309, "", " ", "0", "null", None, [], {}, [1, 2], True,
        {"$ne": None}, "\u0000", "\r\n", "A"*8192, "\u0661\u0662", "\ud83d\udca5", "%00", "\u202e"]
for k in base:
    for v in odd: print(json.dumps({**base, k: v}))
PY
wc -l /tmp/zp.bodies                      # bounded - about 66 requests. Read it before you send it
while read -r b; do send "$A" "$b"; done < /tmp/zp.bodies
```

`json.dumps(1e309)` emits bare `Infinity`, which strict JSON forbids - that probes the parser, not the
field. Duplicate keys need a raw string, and **which** one the app keeps decides whether two components
can be made to disagree (`zp-semantic-confusion`).

```bash
send "$A" '{"quantity":1,"quantity":9999}'; send "$A" '{"quantity":1,"QUANTITY":9999}'
send "$A" '{"quantity":1,"coupon":"SPRING"'                       # truncated - unterminated object
curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$EP" -H "$A" --data-binary '{"quantity":1}' # no CT
```

**3. Truncate the body on the wire - one connection, then close it.** A `Content-Length` the sender
never satisfies is where framework and application disagree about whether a request happened.

```bash
python3 - <<'PY'
import socket, ssl
host, body = "target.tld", b'{"quantity":1,"coup'          # 19 bytes of a declared 64
req = (b"POST /api/orders HTTP/1.1\r\nHost: " + host.encode() + b"\r\nAuthorization: Bearer TOK_A"
       b"\r\nContent-Type: application/json\r\nContent-Length: 64\r\nConnection: close\r\n\r\n" + body)
s = ssl.create_default_context().wrap_socket(socket.create_connection((host, 443), timeout=10),
                                            server_hostname=host)
s.settimeout(8); s.sendall(req)
try: print(s.recv(4096).decode("utf-8", "replace")[:400])
except socket.timeout: print("no response - the server is waiting for the rest")
finally: s.close()
PY
```

**One socket, one probe, closed immediately.** Several held open in parallel is slow-loris - denial of service, out of scope. Do not loop this.

**4. The fail-open differential - the finding; everything above is setup.** Replay each variant that produced an unusual status under three identities, then **re-read the object**.

```bash
for b in '{"quantity":1}' '{"quantity":{}}' '{"quantity":1,"quantity":9999}' '{"quantity":1' ; do
  for id in "$A" "$B" - ; do send "$id" "$b"; done            # owner · other account · anonymous
done
curl -sk "https://$H/api/orders?mine=1" -H "$A" | python3 -m json.tool | grep -iE 'id|state|total|paid'
```

| Clean request | Malformed request | Meaning |
|---|---|---|
| `401`/`403` | `2xx`, or the write lands | authorization skipped on the error path - **the report** |
| `403` | `500` naming the resource, owner or row count | the check ran after the query - disclosure at least |
| `2xx` | `2xx` with a field you never had rights to set | mass assignment via the error path - `zp-idor` |

**5. Drive the state machine out of order and replay it.** Step 3 first, a one-shot step repeated,
backwards, or step 2's continuation token reused on another object.

```bash
for step in 3 1 2 2 1 3; do printf 'step%-3s ' "$step"
  curl -sk -o /dev/null -w '%{http_code}\n' --max-time 20 -X POST "https://$H/checkout/step$step" \
    -H "$A" -H 'Content-Type: application/json' --data-binary "@step$step.json"; done
curl -sk "https://$H/api/orders/$OID" -H "$A" | python3 -m json.tool   # which state did it land in?
```

The question is never "did it error" but **can the object reach a state the success path cannot
produce** - shipped-unpaid, approved-with-no-approver, refunded-twice. Sequential probes only;
concurrent duplicates are `zp-race`.

**6. Read every error body, not the status line.** Every `500` gets grepped before it gets filed.

```bash
grep -ioE 'Traceback \(most recent|at [a-z.]+\([A-Za-z]+\.java:[0-9]+\)|Sequelize[A-Za-z]*Error|node_modules/[a-z@/-]+|/(var|home|usr|app|Users)/[A-Za-z0-9._/-]+|System\.[A-Za-z.]+Exception|Server Error in|on line [0-9]+|SQLSTATE\[|org\.hibernate|panic: |goroutine [0-9]+' /tmp/zp.out
```

**7. Resource-shaped inputs - prove the cap is missing, then stop.** Halt at the first signal and report the smallest input that produced it.

```bash
for d in 20 60 200; do printf 'depth %-4s ' "$d"
  curl -sk -o /dev/null -w '%{http_code} %{time_total}s\n' --max-time 20 -X POST "$EP" -H "$A" \
    -H 'Content-Type: application/json' --data-binary "$(python3 -c "print('['*$d+']'*$d)")"; done
send "$A" "$(python3 -c 'print("{\"note\":\"" + "a"*20000 + "\"}")')"    # 20 KB, not 20 MB
for n in 10 20 30; do printf 'regex %-3s ' "$n"                         # stop at the first jump
  curl -sk -o /dev/null -w '%{time_total}s\n' --max-time 20 -G "https://$H/search" -H "$A" \
    --data-urlencode "q=$(python3 -c "print('a'*$n+'!')")"; done
```

**Hard line.** Depth under a few hundred, body under a megabyte, each sent **once**. No zip or gzip bombs,
no billion-laughs (that is `zp-xxe-lfi`, and only its parse behaviour), no repeated slow queries, no
parallelism. You show only that a limit is absent - never that the host can be taken down.

**8. Stop point for this class.** You stop at the differential and the re-read that proves it. You do not
degrade the service, hold connections open, escalate a slow response into an outage, act on data
another tenant's error revealed, or keep a privileged object a fail-open created - undo it and say so.

---

## Probes and payloads

| Probe | What it tests | Positive looks like |
|---|---|---|
| field as `[]`, `{}`, `true`, `null`, `""` | wrong-type handling before the authorization check | uncaught exception, or the write happening anyway |
| `0`, `-1`, `-0.0`, `2**63`, `Infinity` | sign and range assumptions, overflow, float coercion | negative total, free order, wrapped identifier |
| duplicate and case-variant keys | two parsers, two winners | one component validates value A, another uses value B |
| truncated JSON, stray brace, wrong or missing `Content-Type` | body parser vs route middleware ordering | `500` from inside the handler, or a partial write |
| `\u0000`, `\r\n`, `U+202E`, unpaired surrogate, over-long UTF-8 | normalisation and encoding round-trips | value truncated at the null, split header, two stored forms |
| step out of order, step repeated, step token reused elsewhere | state-machine enforcement | an object in a state the UI cannot produce |
| nesting depth 20 -> 60 -> 200, once each | parser depth cap | `500` or a step change in `time_total` - **report, do not scale** |
| 40-char input to a search or regex filter | absent input-length cap | super-linear timing growth - stop immediately |
| every variant re-sent anonymous and as a second account | the whole point of the class | `2xx` where the clean request gave `401`/`403` |

`curl` plus `python3` stdlib is the whole toolchain - no fuzzer. `zp-proxy` replays the baseline with real cookies; `zp-browser` only when the error surfaces in the client.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| malformed request performs a write the clean request from the same identity is refused, re-read confirms | **confirmed fail-open authorization bypass.** High to Critical - the flagship of this class |
| anonymous variant returns data that requires a session | confirmed - severity from the data; cross-file with `zp-authz` |
| error path leaves an object in a state the success path cannot reach | confirmed - file with `zp-business-logic`, impact in money or trust |
| exception skips a signature, MFA or entitlement check and the action completes | confirmed, and usually the highest-paying shape here |
| `500` body carries a stack trace, ORM class, absolute path or library version | confirmed **information disclosure** - Low to Medium alone. `zp-info-disclosure` |
| `500` with a generic body, no state change, no identity differential | **killed.** An unhandled exception is not a vulnerability on almost every program |
| negative or huge quantity accepted at the API but rejected by the ledger or payment step | killed unless you re-read the final invariant and show it broken |
| `{"$ne":null}` or SQL metacharacters merely echoed back | killed - only an altered **result set** is a finding. `zp-sqli` |
| deep nesting or a long field yields `500` or a slow response | report as an **absent limit** with the smallest input that showed it. Low to Medium, and out of scope on many programs - read the policy first |
| timing grows super-linearly with input length | same - the missing length cap is the finding. Never scale the input to prove impact |
| reproduced once, not again from a clean session | killed until it reproduces twice, with both transcripts |
| error text differs for an existing and a non-existing account | enumeration oracle, not fail-open. `zp-info-disclosure` |
| you never captured the clean request's refusal | **incomplete.** The baseline is half the report - a triager cannot see a differential with one side missing |

"The API returns 500 on invalid input" is a bug report. "Sending `quantity` as an object makes the order
service write the row before the ownership check runs, so any user can add items to another user's cart"
is a bounty.

---

## High-value patterns

- **Authorization inside a `try` with a permissive `catch`** - a token that fails to parse becoming an anonymous-but-trusted principal instead of a rejection. The most valuable shape in this class. `zp-jwt-oauth`, `zp-session`.
- **Payment and webhook handlers** where signature verification throws, the exception is logged, and fulfilment continues - refund, capture and entitlement paths especially.
- **Validation after persistence** - the ORM saves, the validator throws, the handler returns `400`, the row survives. Only a re-read sees it. Same shape in **GraphQL partial responses**, where `data` is populated beside `errors` from resolvers whose authorization failed (`zp-graphql`).
- **Config and quota services that default-allow when unreachable**, and **bulk endpoints** where one bad element aborts the loop midway, leaving half the transaction applied and nothing rolled back. Same again in **upload pipelines** where the antivirus, mime or image step errors and the file is stored anyway (`zp-upload`).
- **Malformed bodies reaching a deserializer** the happy path never touches - polymorphic type hints, pickle, YAML tags. `zp-rce-ssti`. On Node, put `__proto__` and `constructor` in the same matrix: a merge that throws often polluted first. `zp-proto-pollution`.

---

## Pitfalls

- **Chasing `500`s.** Collect them, then ask what each one skipped; with no differential and no leak they are informative at best. Never believe a status code either - a `400` that wrote and a `200` that did not are both routine, and a mangled emoji is only a finding when two components disagree about what was stored.
- **Exercising a limit instead of proving it absent.** Zip bombs, billion laughs, megabyte payloads, held-open sockets, looped slow regexes and parallel probes are denial of service - out of scope, and grounds for removal from the program.
- **Fuzzing everything.** Step 2 is ~66 requests against one endpoint you chose deliberately. Keep the program's rate limit, and never run it against an endpoint that mails or charges real people. Mistaking the WAF for the app belongs here too - a `502`/`504` from the edge is not the app failing.
- **Testing shared or production objects** - another tenant's order, an org-wide setting, a live invoice. Your own objects only, and the wreckage (half-created orders, stuck workflows, objects a fail-open promoted) gets cleaned up and documented.
- **Skipping the baseline.** Without the clean request being refused, there is no report. And file the right class - a null byte in a path is `zp-xxe-lfi`, a metacharacter that changes a result set is `zp-sqli`, concurrent duplicates are `zp-race`.

---

## Hand off to

Skipped authorization -> `zp-authz`; object-level and mass-assignment variants -> `zp-idor`. Invariant
broken through an error path -> `zp-business-logic`; concurrent duplicates -> `zp-race`. Token and session
parse failures -> `zp-jwt-oauth`, `zp-session`. Stack traces, enumeration oracles and debug surfaces ->
`zp-info-disclosure`. Parser disagreement -> `zp-semantic-confusion`; request framing -> `zp-smuggling`.
Injection through a malformed field -> `zp-sqli`, `zp-rce-ssti`, `zp-xxe-lfi`; Node merge sinks ->
`zp-proto-pollution`, `zp-nodejs`. Partial GraphQL responses -> `zp-graphql`; endpoint inventory ->
`zp-api`; failed upload-pipeline checks -> `zp-upload`. Absent counters -> `zp-rate-limit`, `zp-captcha`.
Model and tool error paths -> `zp-llm`. Root cause in source -> `zp-code-audit`. Baseline replay ->
`zp-proxy`; client-side errors -> `zp-browser`. New host in a traceback -> `zp-scope`. Confirmed ->
`zp-triage`, then `zp-report`.

Class reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
