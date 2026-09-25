---
name: zp-business-logic
description: ZeroProtocol hunter for business logic flaws - workflow and state-machine bypass, domain invariant violations, price and quantity manipulation, coupon and limit abuse, trial and entitlement escape, and approval bypass. Use when testing checkout, payments, subscriptions, refunds, invites, quotas, multi-step workflows, or any feature where the rules are the product rather than the code. Requires modelling the business, not firing payloads.
---

# zp-business-logic - exploiting the rules as written

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

No scanner finds these, because nothing is technically malformed. Every request is well-formed
and authorised; the application simply lets you reach a state the business never intended. That
is why this class pays well and duplicates rarely.

**The method is modelling, not payloads.** Write the invariant down first - *"a user cannot hold
a paid entitlement without a settled payment"* - then look for a path that violates it.

---

## 1. Model the domain before touching anything

For the feature under test, write out:

```
actors        who can act, in which roles, across which tenants
objects       order, invoice, subscription, invite, credit, ticket, document
states        draft -> pending -> paid -> fulfilled -> refunded   (and every backward edge)
transitions   which actor may move which object between which states
invariants    the sentences that must always be true
money         where value is created, moved, or destroyed
```

The invariants are your test list. Typical ones:

- a paid entitlement requires a settled payment
- a discount applies at most once per order
- a refund never exceeds the amount captured
- a seat count never exceeds the plan's limit
- an approval is granted by someone other than the requester
- a trial converts once, and cannot be restarted by the same identity

---

## 2. Walk the workflow, then walk it wrong

Capture the happy path first (a proxy corpus from `zp-proxy` is ideal - you need the real
requests). Then attack the *sequence*:

| Attack | Concretely |
|---|---|
| **skip a step** | call the post-payment fulfilment endpoint without paying |
| **reorder steps** | apply a discount after totals are computed |
| **repeat a step** | submit the final step twice; apply the coupon again |
| **resume an abandoned flow** | reuse a half-finished cart/session after prices changed |
| **go backwards** | return a completed order to `draft`, edit it, re-complete |
| **parallel paths** | start checkout in two tabs and complete both -> `zp-race` |
| **cancel mid-flow** | cancel after fulfilment but before capture |
| **substitute the object** | swap another account's cart or invoice id -> `zp-idor` |

The two that pay most often: **skip the payment step**, and **mutate the object after approval
but before execution**.

---

## 3. Value manipulation

Send what the client would never send. Read the persisted object back afterwards - a `200` proves
nothing.

```
quantity      -1 · 0 · 0.0001 · 1e9 · "1"  (type confusion) · 2147483648 (overflow)
price/amount  negative, zero, a string, more decimal places than the currency has
currency      swap to a weaker unit while the numeric amount stays the same
discount      >100% · stack exclusive codes · apply to shipping/tax as well as goods
refund        more than captured · twice · to a different payment method
ids           another tier's plan_id, another tenant's price_id
rounding      repeated tiny operations that round in your favour each time
```

**Currency confusion and negative quantities are the two classics.** A negative line item that
credits the order total is a direct financial finding.

**Test only on your own accounts, with the smallest amounts the system allows, and undo what you
can.** If a probe would move real money you do not own, stop and describe the mechanism instead.

---

## 4. Entitlement and limit escape

```
trial restart        delete and recreate the account/resource; change email alias; new tenant
plan downgrade       keep premium features after downgrading; re-enable via a stale client flag
seat/quota limits    add members past the cap; race two invites -> zp-race
usage metering       does the meter count what the biller bills? off-by-one, unmetered path
feature flags        flip a client-side flag and see whether the API cares -> zp-authz
referral/credit      self-refer; loop credits between two accounts you own
expiry               use a coupon, invite, or token after its stated expiry
```

The question that generalises: **is the limit enforced where the value is granted, or only where
the UI displays it?**

---

## 5. Approval and separation of duties

```
approve your own request            (expense, refund, merge, deploy, access grant)
remove the approver, then act       (delete the reviewer, or downgrade their role mid-flow)
modify after approval               (change the amount/target between approve and execute)
partial approval                    (approve one line, execute all)
delegate to yourself                (assign the approval to an identity you control)
```

"Modify after approval" overlaps `zp-agentic`'s approval-binding tests and is the same root
cause: the approval did not bind the thing executed.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| reached a paid/entitled state without paying | **confirmed.** High to Critical - direct financial impact |
| negative or manipulated amount persisted and changed the total | **confirmed** |
| discount applied more times than allowed, verified in the final total | confirmed |
| limit exceeded and the extra capacity is actually usable | confirmed |
| approved your own request where policy requires a second party | confirmed |
| `200` returned but the object read back is unchanged | **killed** - the server rejected it |
| the flow is *designed* to allow this (documented) | killed - read the docs first |
| exceeded a soft limit with no value gained | Low at best |
| the discrepancy self-corrects on the next sync/settlement | killed, or Low - check the settled state, not the interim one |
| needs an insider role you were given for testing | state the precondition; severity drops sharply |
| you moved real money | **stop, self-report to the program immediately** |

**Always read the object back, and where money is involved read the *settled* state.** Many
systems accept an interim inconsistency and reconcile it minutes later - reporting the interim
window as theft is the standard false positive in this class.

---

## High-value patterns

- **Checkout and payment flows** - skip capture, negative quantity, currency swap.
- **Refund paths** - refund more than captured, or twice, or to a different instrument.
- **Subscription lifecycle** - downgrade while keeping entitlements; restart trials.
- **Credit, referral and gift-card systems** - loops between two accounts you own.
- **Multi-tenant seat limits** - free capacity in a paid plan.
- **Approval workflows** in finance, access management and deployment.
- **Anything with a webhook from a payment processor** - can you call it yourself? That is fulfilment without payment, and it is both a logic flaw and an authentication one.

---

## Pitfalls

- **Firing payloads instead of modelling.** Write the invariant first; otherwise you are guessing.
- **Testing with real money, real customers, or real refunds.** Your own accounts, minimum amounts, and undo it.
- **Trusting the response code.** Read the object back, and the settled state.
- **Reporting an interim inconsistency** that reconciliation fixes.
- **Missing the documentation** that says the behaviour is intended.
- **Escalating to volume** - hammering a coupon endpoint is a DoS test, not a logic test.
- **Leaving inflated balances, extra seats or test orders behind.** Clean up and say so.
- **Ignoring the payment-processor webhook**, which is often the weakest link in the whole flow.
- **Describing the flaw without quantifying it.** Triagers pay on demonstrated value.

---

## Hand off to

Concurrency variants -> `zp-race`. Object substitution -> `zp-idor`. Role and approval boundaries
-> `zp-authz`. Client-only enforcement found in the bundle -> `zp-js-secrets`.
Processor webhooks and callbacks -> `zp-api`, `zp-ssrf`. A real traffic corpus -> `zp-proxy`.
Confirmed -> `zp-triage`, `zp-report`, with the value quantified.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `business_logic`.
