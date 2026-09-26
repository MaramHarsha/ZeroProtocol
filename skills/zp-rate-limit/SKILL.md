---
name: zp-rate-limit
description: ZeroProtocol hunter for missing rate limiting, lockout and throttling on sensitive endpoints - login, password reset, OTP and MFA verification, signup, search, export and anything metered or billed. Use when no 429, Retry-After or backoff appears under a small bounded probe, when a limit is keyed on a client-controlled header such as X-Forwarded-For, or when GraphQL aliasing or batching turns one request into many attempts. Proves the control is absent and never exercises what it protected.
---

# zp-rate-limit - proving the meter is not running

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

This skill answers one question - **does a limit exist on this operation, and what is it keyed to?**
It never answers what is behind the limit. A real finding names the protected operation, shows a bounded
probe with no 429, no `Retry-After`, no lockout, no backoff and no challenge, and says what unlimited
attempts are worth. Absence on a read endpoint is Low or N/A; on OTP verification, reset codes or a
billed operation it is what this class exists for.

---

## Procedure

**1. Read the program's own limit before sending anything** - the rules of engagement cap the probe,
and if the policy forbids automation you probe by hand or not at all and say so in the report.

```bash
zp-scope check target.tld || exit 1
zp-scope show --json | python3 -c 'import json,sys; s=json.load(sys.stdin); print("rps",s.get("rate_limit_rps"),"conc",s.get("max_concurrency"),s.get("notes"))'
```

**2. Read what the response already advertises.** Half of this class is answered by one request.

```bash
H=target.tld
curl -sk -D - -o /dev/null --max-time 15 -X POST "https://$H/api/login" \
  -H 'Content-Type: application/json' --data-raw '{"email":"zp@example.com","password":"x"}' \
| grep -iE '^(HTTP/|retry-after|ratelimit-|x-ratelimit-|x-rate-limit-|cf-mitigated|x-envoy-ratelimited|x-amzn-errortype)' | tr -d '\r'
```

`RateLimit-Limit`/`-Remaining`/`-Reset`, the `X-RateLimit-*` family, Kong's
`X-RateLimit-Remaining-Minute`, `x-envoy-ratelimited` and `cf-mitigated` all mean a limiter exists - the question becomes what it is keyed to (step 5).

**3. Build one fixed, provably-invalid value. This is the whole safety design.**

| Operation | The one value you send on every attempt |
|---|---|
| login | your **own** account plus a literal such as `ZeroProtocol-Not-My-Password-9134` |
| OTP / MFA verify | send the code to **your own** account, read it, then use one fixed code that differs from it - `python3 -c "print(f'{(int(\"$REAL\")+7)%1000000:06d}')"` |
| reset-token submit | one fixed token of the right shape that you know is not yours |
| coupon, invite or gift code | one fixed code you have already seen rejected once |

One value, reused unchanged. **Never a wordlist, never a generated range, never another user's identifier.**
A loop whose value changes each iteration is credential or code guessing, out of scope whatever it finds.

**4. The bounded probe - 7 to 15 attempts, three columns.** Then the known-good check, which is the
step that stops a false "no rate limit" - re-authenticate **correctly** as yourself, or submit the
**real** OTP from step 3. Still succeeding means the attempts were genuinely unlimited; now failing or
answered with a canned body means the endpoint was shadow-throttling, so a control exists - kill it.

```bash
EP="https://$H/api/login"; ME="zp+a1@example.com"; BAD='ZeroProtocol-Not-My-Password-9134'
RPS=$(zp-scope show --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("rate_limit_rps") or 2)')
for i in $(seq 1 12); do
  printf 'attempt %-3s ' "$i"
  curl -sk -o /tmp/zp_rl.body -D /tmp/zp_rl.hdr -w '%{http_code}  %{time_total}s  %{size_download}B\n' \
    --max-time 20 -X POST "$EP" -H 'Content-Type: application/json' \
    --data-raw "{\"email\":\"$ME\",\"password\":\"$BAD\"}"
  grep -iE '^(retry-after|ratelimit-remaining|x-ratelimit-remaining)' /tmp/zp_rl.hdr | tr -d '\r'
  sleep "$(python3 -c "print(1/$RPS)")"
done
curl -sk -o /dev/null -w 'known-good after probe -> %{http_code}\n' --max-time 20 -X POST "$EP" \
  -H 'Content-Type: application/json' --data-raw "{\"email\":\"$ME\",\"password\":\"$MY_REAL_PW\"}"
```

**A missing 429 is not a missing limit.** Four states, four different reports:

| State | What the columns show | Verdict |
|---|---|---|
| throttle | status flips to `429`/`403`, `Retry-After` appears | control present - record N and stop |
| hard lockout | account disabled; your **correct** password now fails too | control present, possibly account-DoS |
| challenge injection | status stays `200`, body grows, a captcha field appears | control lives one layer over - `zp-captcha` |
| silent throttle | status and size identical, latency climbing or bodies canned | **the trap** - the known-good check settles it |

**5. What is the limit keyed to?** Only after a limit has engaged - the earned 429 is the baseline and
the delta is the report. Ten requests per surface, not a hundred, and stop the moment one restores `200`.

```bash
# 5a. per-source keying - one header per request, same fixed invalid value
for h in X-Forwarded-For X-Real-IP X-Client-IP X-Originating-IP CF-Connecting-IP True-Client-IP; do
  IP="$(shuf -i 11-250 -n1).$(shuf -i 1-250 -n1).$(shuf -i 1-250 -n1).$(shuf -i 1-250 -n1)"
  printf '%-20s %-16s ' "$h" "$IP"
  curl -sk -o /dev/null -w '%{http_code}\n' --max-time 20 -X POST "$EP" -H "$h: $IP" \
    -H 'Content-Type: application/json' --data-raw "{\"email\":\"$ME\",\"password\":\"$BAD\"}"
done   # then comma lists ("1.2.3.4, <your ip>") - some parsers read the first hop, some the last
# 5b. identifier keying - spellings a counter may treat as different keys for one account
python3 -c 'b="zp+a1@example.com"; print([b, b.upper(), b+".", " "+b, b.replace("@","＠")])'
# 5c. route keying, then client keying with a fresh jar, then the window
for p in /api/login /api/login/ /API/login /api/./login /api/v1/../v1/login; do
  printf '%-24s ' "$p"; curl -sk -o /dev/null -w '%{http_code}\n' --max-time 20 -X POST "https://$H$p" \
    -H 'Content-Type: application/json' --data-raw "{\"email\":\"$ME\",\"password\":\"$BAD\"}"
done
```

Then two single requests finish the picture - one with a fresh cookie jar (`curl -c /tmp/zp.jar` on the
login page, then `-b /tmp/zp.jar`) shows whether the counter is keyed to client state, and one after
`sleep 60` gives the window length or proves there is no counter at all.

Attacker-triggerable lockout is tested on **your own second account only**. Locking an account you do
not own is denial of service against a real person, not testing.

**6. One request, many attempts - GraphQL and batch APIs.** The limiter counts HTTP requests while the
server performs N operations. Same single fixed invalid value in every alias.

```bash
Q='mutation{a1:login(email:"'"$ME"'",password:"'"$BAD"'"){token} a2:login(email:"'"$ME"'",password:"'"$BAD"'"){token} a3:login(email:"'"$ME"'",password:"'"$BAD"'"){token}}'
curl -sk -D - --max-time 25 "https://$H/graphql" -H 'Content-Type: application/json' \
  --data-raw "$(python3 -c 'import json,sys; print(json.dumps({"query":sys.argv[1]}))' "$Q")" | head -30
curl -sk -o /dev/null -w 'array batch -> %{http_code}\n' --max-time 25 "https://$H/graphql" \
  -H 'Content-Type: application/json' \
  --data-raw '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
```

Three aliases answered independently against one limiter decrement is the proof. Schema recovery,
depth and cost belong to `zp-graphql`.

**7. Metered operations - two or three requests, to your own address, serially.** Resend buttons on
OTP, magic links, invites, SMS, export jobs and AI inference are where absence costs the target money.

```bash
for i in 1 2 3; do
  printf 'send %s ' "$i"; curl -sk -o /dev/null -w '%{http_code}  %{time_total}s\n' --max-time 25 \
    -X POST "https://$H/api/otp/send" -H 'Content-Type: application/json' --data-raw "{\"email\":\"$ME\"}"
  sleep 1
done   # three messages you receive yourself, with no cooldown, is the whole proof
```

**8. Stop point for this class.** You stop at the fewest attempts that show the control is absent and
name its key. You do **not** run a wordlist, walk an OTP keyspace, exhaust a token space, flood an
endpoint, parallelise anything that mails, texts, renders or bills, or sweep the host list. Severity comes
from **arithmetic stated in the report** - keyspace, throughput, code lifetime - never from attempts made.

## Probes and payloads

| Probe | What it tests | Positive looks like |
|---|---|---|
| one request, header grep (step 2) | whether a limiter announces itself | no `RateLimit-*`, no `Retry-After`, no vendor header |
| 12 attempts, one fixed invalid value | throttle, lockout, challenge or nothing | identical status, size and latency throughout |
| known-good value after the probe | shadow throttling | it still authenticates - the attempts were real |
| `X-Forwarded-For` and friends, one per request | limit keyed to a client-controlled hop | the 429 you already earned disappears |
| `/api/login/`, `/API/login`, an upper-cased or padded identifier, a fresh cookie jar, a 60 s wait | limiter keyed to a literal route, a raw string, client state or a window | the count restarts while the handler still works |
| 3 aliases of one mutation in one POST, or a 3-item array batch | operations counted per request | 3 independent results, 1 decrement |
| 3 sends to your own address on any resend button | per-message cost unmetered | three messages, no cooldown |
| same operation on `/api/v1`, `/mobile`, the GraphQL mutation | limiter on the web path only | the quiet path takes attempt after attempt |

`curl`, `python3` and `shuf` cover every row. `ffuf` and `hydra` are deliberately absent - a wordlist
runner cannot express this class without crossing into guessing, and `nuclei`'s fuzzing templates infer "no rate limit" from a request count, which is the first row of the next table.

## Confirm or kill

| Evidence | Verdict |
|---|---|
| OTP/MFA verify or reset-code submit takes 12+ attempts with no 429, lockout or challenge, the code does not rotate, and the known-good check passes | **confirmed, the top of this class.** High to Critical - give keyspace ÷ observed throughput against code lifetime as the impact, and never run it |
| login unlimited, known-good check passed, no captcha or WAF engaged | confirmed. Medium to High as the credential-stuffing gate removed - describe stuffing, never perform it |
| a 429 exists, rotating `X-Forwarded-For` restores `200`, and removing the header brings the 429 back | confirmed bypass. **The toggle-off run is mandatory evidence.** Severity from the operation |
| a case, padding or unicode variant of your own identifier restarts the counter | confirmed - keyed on the raw string while auth normalises it |
| 3 aliases or a 3-item batch execute for one limiter decrement | confirmed - per-request limiting on a multi-operation endpoint. Write it with `zp-graphql` |
| OTP send, SMS, invite or inference accepts repeats with no cooldown | confirmed. Medium to High where the target is billed per unit - name the unit |
| your own second account locks out and lockout needs only a known email | Medium account-DoS **only** where the program accepts DoS; many exclude it. Never demonstrate on a third party |
| status stayed `200` throughout but the known-good value stopped working | **killed.** Shadow throttle - the control exists |
| no 429 in 12 attempts, but a captcha or a managed edge challenge appeared | **killed here.** The control is one layer up - `zp-captcha`, and cap severity by saying so |
| `429` present but no `Retry-After`, or a threshold that merely feels generous | **killed.** Header hygiene and threshold choice are product decisions |
| no limit on a public read - search, docs, price lookup, avatar fetch | **Low or N/A on almost every program.** Reportable only when the read is metered, paywalled or enumerable, and then the finding is the enumeration - `zp-info-disclosure` |
| unlimited attempts, but the operation needs a value you do not hold (current password, a live token) | the limit was not the gate. Informative at best |
| `200` returned and nothing was sent, created or counted | killed - you proved nothing. Re-read the resource or your inbox |
| "no limit" concluded from 3 attempts, or without the known-good check | killed as unproven |
| found by sending a wordlist, a code range, or high concurrency | **killed and out of scope.** Discard it, and report nothing about what it reached |

"There is no rate limit on `/api/login`" is not a report. "Twelve consecutive wrong passwords for my own
account returned identical 401s in 140 ms each, the correct one still worked afterwards, and no captcha
or lockout exists on any login path including `/api/v1/login`" is.

## High-value patterns

- **OTP and MFA verification, and reset-code submission** - a 6-digit code with no limit and no rotation is the ATO path this class is known for. Show absence in a dozen attempts, put tractability in arithmetic.
- **Anything metered** - SMS and email, AI inference, PDF and video render, export jobs, third-party API passthrough. The target's invoice is the impact; `zp-llm` owns the inference framing.
- **A flow limited on *send* but not on *verify***, and **GraphQL or batch entrypoints in front of a limited operation** - one POST, N attempts, and an honest limiter becomes irrelevant.
- **The second path to the same operation** - `/api/v1` for old clients, the mobile endpoint, a legacy `/auth/token`. A limiter added after an earlier report usually lands only on the reported path.
- **Limits enforced at a CDN whose origin also answers directly** - an origin IP from `zp-recon-passive` bypasses the entire control.
- **Invite, signup, referral and API-key issue** - unlimited creation feeds spam, promo abuse and damage to the target's own domain reputation.

## Pitfalls

- **Turning the probe into the attack.** A wordlist, an OTP range, a token sweep or parallel flooding is guessing or DoS, and it ends the engagement rather than the report.
- **Concluding "no rate limit" from missing 429s.** Run the known-good check - silent throttling is the commonest false positive here.
- **Rotating `X-Forwarded-For` before any limit engaged,** or reporting a bypass without the toggle-off control run. The delta is the evidence.
- **Unbounded loops on anything that mails, texts, renders or bills.** Two or three, to your own address, serially.
- **Probing or locking an account you do not own** - including `admin@target.tld`. Two accounts you own, always.
- **Ignoring the program's rps, concurrency ceiling or testing window,** or **filing a missing limit on a public read as Medium,** or measuring the edge instead of the app - check `cf-mitigated` and the served body.
- **Leaving probe accounts, invites or sent messages behind.** Clean up, and say so in the report.

## Hand off to

New host, path or origin IP -> `zp-scope` first, then `zp-recon-passive` for the origin. A challenge
instead of a limit -> `zp-captcha`. Lockout and clearance-cookie keying -> `zp-session`; OTP, reset,
magic-link and MFA flow logic -> `zp-jwt-oauth`. Aliasing, batching, depth and cost -> `zp-graphql`;
second and legacy paths -> `zp-api`, `zp-mobile`, `zp-content-discovery`. Concurrency and single-use
consumption -> `zp-race`; quotas, trials and coupons -> `zp-business-logic`. Valid-versus-invalid response
differences -> `zp-info-disclosure`. Billed inference -> `zp-llm`; limiter behaviour differing between
proxy and origin -> `zp-semantic-confusion`, `zp-smuggling`. A limiter component with a version ->
`zp-cve`. Captured requests -> `zp-proxy`; browser-only flows -> `zp-browser`. Then `zp-intel` for dedup, `zp-triage`, and `zp-report`.

Class reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
