---
name: zp-race
description: ZeroProtocol hunter for race conditions, TOCTOU flaws and business-logic abuse. Use when a limit, balance, quota, coupon, invite, vote or one-time token could be used twice, when testing concurrent requests against the same resource, when hunting double-spend or limit-overrun, or when checking a multi-step workflow for state-machine skips. Keeps concurrency low and uses disposable objects, because this class touches real balances and real limits.
---

# zp-race - two requests, one check

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

**This is the class most likely to cause real harm by accident.** You are deliberately making a
system apply an operation twice - and if that operation is a refund, a transfer or an order, you
have moved real money. Rules:

- Use **your own** disposable accounts, your own coupons, your own test objects.
- Keep concurrency at **5-20 requests**, never hundreds. A race needs a narrow window, not volume.
- Never race a payment capture, a refund, a payout, a withdrawal, or anything that touches a real
  ledger you do not own. Prove the pattern on a benign counter instead.
- If it works, **undo it** where you can, and say what you did in the report.

High volume here is indistinguishable from a denial-of-service attempt, which every program
excludes.

---

## Procedure

**1. Find the single-use invariants.** A race is only interesting where the application promises
"once".

```
coupon / promo / gift card / referral credit    invite or seat limit in a team plan
one-time token: password reset, email confirm, MFA enrolment, magic link
vote / like / rating / poll                     follow, friend request, join
withdrawal, transfer, refund, order            (test only on objects you own)
rate limit, free-tier quota, trial extension, API key count
file/storage quota                             "claim" or "reserve" actions
2FA verification attempts                       unsubscribe/resubscribe toggles
```

**2. Build the two states.** Before racing, know what "once" looks like:

```bash
# baseline: use the coupon normally, observe the response and the resulting state
curl -sk -X POST "https://$H/api/cart/coupon" -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' -d '{"code":"ZPTEST10"}' | jq
curl -sk "https://$H/api/cart" -H "Authorization: Bearer $TOK_A" | jq '.discount,.total'
# second attempt should be rejected. If it is not, you do not need a race at all.
```

Always try the naive sequential replay first. A surprising amount of the time the "single use"
check does not exist, and you have a simpler, cleaner finding with no concurrency at all.

**3. Race with single-packet or near-simultaneous delivery.** The point is to land all requests
inside the check-to-write window.

```bash
python3 - <<'PY'
import http.client, ssl, threading, json, sys
HOST, PATH, TOK, N = "target.com", "/api/cart/coupon", "TOKEN_A", 10
BODY = json.dumps({"code": "ZPTEST10"})
ctx = ssl._create_unverified_context()
barrier, out, lock = threading.Barrier(N), [], threading.Lock()

def go(i):
    c = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=20)
    # send the headers and all but the final body byte, then hold that byte
    c.putrequest("POST", PATH, skip_host=True)   # we set Host ourselves; without this
                                                 # http.client adds a second one and the
                                                 # request is invalid per RFC 7230
    c.putheader("Host", HOST)
    c.putheader("Authorization", f"Bearer {TOK}")
    c.putheader("Content-Type", "application/json")
    c.putheader("Content-Length", str(len(BODY)))
    c.endheaders()                     # http.client flushes the whole header block here
    c.send(BODY.encode()[:-1])         # everything except the last byte
    barrier.wait()                     # <-- all threads release together
    c.send(BODY.encode()[-1:])         # one byte each: the request completes on arrival
    r = c.getresponse()
    with lock: out.append((i, r.status, r.read()[:120]))
    c.close()

ts = [threading.Thread(target=go, args=(i,)) for i in range(N)]
[t.start() for t in ts]; [t.join() for t in ts]
for i, s, b in sorted(out): print(i, s, b.decode(errors="replace"))
PY
```

The barrier is what makes this work: all ten connections send their headers and all but one byte
of the body, then release that final byte together, so all ten requests become complete at the
server within microseconds of each other - no thread has a body write left to do after the gun
goes off. `endheaders()`
flushes the header block immediately, which is why the held byte has to be carved off the body
yourself; holding the *whole* body instead leaves every thread one extra write and TLS record
inside the window you are trying to close.

With HTTP/2 you can do better - one TCP packet carrying multiple streams removes network jitter
entirely. Use a tool that actually implements that primitive: Burp's **single-packet attack**, or
Turbo Intruder on the HTTP/2 engine, or a small `nghttp2`/`h2` client that writes N HEADERS+DATA
frames into a single `write()`. Not `h2load` - that is nghttp2's throughput benchmarker, driven by
`-n` total requests and `-c` connections with no last-byte or single-packet sync at all, and
pointing it at a target is the sustained high-volume traffic the rule above forbids.

**4. Read the *state*, not the responses.** Ten `200`s prove nothing; the ledger does.

```bash
curl -sk "https://$H/api/cart" -H "Authorization: Bearer $TOK_A" | jq '.discount,.total,.coupons'
```

| State after the race | Verdict |
|---|---|
| discount applied once, nine rejections | correctly locked. Killed |
| discount applied 4 times | **confirmed race.** Quantify it: N requests -> M applications |
| balance increased by more than one credit | confirmed, and directly monetary |
| two rows created where one is allowed | confirmed |
| all ten succeeded and the state is corrupt | confirmed, and note the corruption as extra impact |

**5. The other shapes of this class.**

| Shape | Test |
|---|---|
| **TOCTOU on a limit** | race the action that increments a counter checked before the write |
| **Single-use token** | race redemption of one reset/confirm token with N simultaneous requests |
| **State-machine skip** | call step 3 without step 2; call the post-payment webhook directly |
| **Negative or overflow values** | quantity `-1`, `0`, `1e9`, `0.001`; price or currency in the body |
| **Currency confusion** | change `currency` to a weaker one while the price stays numeric |
| **Parameter pollution** | `qty=1&qty=1000` - which one does each layer read? |
| **Idempotency-key reuse** | reuse a key with a *different* body; does it return the cached result or apply both? |
| **Rollback abuse** | cancel or refund after the fulfilment step has completed |
| **Concurrent role change** | race a role downgrade against an action needing the old role |
| **Free-tier reset** | delete and recreate a resource to reset a quota |

Business-logic abuse without concurrency is usually easier to prove and just as valuable -
always test the sequential version first.

**6. Verify by repetition.** Races are probabilistic. Run the experiment 3-5 times and record
how often it succeeds. `3 of 5 attempts applied the coupon twice` is a much stronger report than
`it worked once`.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| state shows N applications where 1 is allowed, reproducible | **confirmed.** Severity by what was multiplied |
| multiple `200`s but the final state is correct | killed - the app deduplicated after the fact |
| worked once, never again in 5 attempts | inconclusive. Say so, or keep tuning the window |
| sequential replay already works | **not a race** - it is a missing uniqueness check. Simpler and still valid |
| balance or credit multiplied | confirmed, High to Critical - direct financial impact |
| limit exceeded but no value gained (e.g. extra rows of a free resource) | Low unless it bypasses a paid tier |
| rate limit exceeded by racing | usually Low or N/A; check the program's stance on rate limiting |
| the second request got a `409`/`423` | proper locking. Killed |
| you caused a real charge, transfer or payout | **stop, self-report to the program immediately** |

---

## High-value patterns

- **Gift cards, store credit, referral bonuses** - directly monetary, easy to quantify, hard for the program to dispute.
- **Coupon stacking** - apply one code many times, or many codes designed to be exclusive.
- **Invite/seat limits in a paid tier** - get paid capacity for free.
- **One-time password-reset tokens** - racing redemption can leave a token valid, or bind it to two accounts.
- **MFA enrolment** - race two enrolments and end up with a factor the victim does not know about.
- **Withdrawal or transfer double-spend** - the highest severity, and the one you must only test between two accounts you own, with tiny amounts, and undo.
- **Payment webhook replay** - call the fulfilment callback twice.
- **Idempotency key reused with a different body** - under-hunted and often broken.

---

## Pitfalls

- **Hundreds of concurrent requests.** That is a DoS test. 5-20 is the whole technique.
- **Racing real money you do not own.** Two of your own accounts, minimum amounts, undo afterwards.
- **Reading response codes instead of state.** Ten `200`s with a correct final balance is nothing.
- **Reporting after one success.** Repeat it and give the hit rate.
- **Skipping the sequential test.** Often there is no lock at all and no race is needed.
- **Leaving inflated balances or extra resources behind.** Clean up; say so in the report.
- **Racing a destructive action** (delete, cancel) on anything shared.
- **Racing against a shared/staging environment other researchers are using** - you will corrupt their tests too.
- **Not recording the window.** Note the timing so the developer can reproduce it.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report`, with the hit rate and the before/after state.
State-machine skips and value manipulation -> `zp-authz` if they cross a privilege boundary.
Token reuse -> `zp-jwt-oauth`. Object-level effects -> `zp-idor`.
Source available -> `zp-code-audit` to find the missing transaction or lock.
