---
name: zp-session
description: ZeroProtocol hunter for session lifecycle flaws - fixation, no rotation across a privilege change, sessions surviving logout or password change, idle and absolute timeout, concurrent-session revocation, cookie attribute and scope errors, remember-me handling, and identifiers leaking via URL or Referer. Use when a Set-Cookie carries a session, when a logout or credential change must revoke access, or when an identifier looks guessable. Token internals belong to zp-jwt-oauth.
---

# zp-session - the credential that outlives the password

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

This class is the **lifecycle**, not the bytes - who can plant a session, and which events fail to kill one.
The paid bug is nearly always one sentence: *the victim changed their password and the attacker's session
kept working.* Every claim needs three things or it is not a finding - a session **you captured** from a real
flow, the account's **identity marker** in the reply body, and a **garbage-cookie control** that fails on the
same endpoint.

---

## Procedure

**1. Two accounts you own, and a cookie reader.** Find out first whether the session lives in a
cookie, an `Authorization` header, or a URL.

```bash
H=target.tld; ME="https://$H/api/me"; JAR_A=$(mktemp); JAR_B=$(mktemp)
sess(){ awk '/^#HttpOnly_/{sub(/^#HttpOnly_/,"")} /^#/{next}   # jar: $6=name $7=value
              NF>=7 && $6 ~ /sess|sid|SID|auth|token|remember/ {print $6"="$7}' "$1" | tail -1; }
curl -sk -D - -o /dev/null "https://$H/login" | grep -i '^set-cookie'
```

**2. Baseline and negative control, before anything else.** This decides whether a later 200 means
anything at all.

```bash
curl -sk -c "$JAR_A" -b "$JAR_A" -X POST "https://$H/api/login" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$U_A\",\"password\":\"$P_A\"}" -o /dev/null
A=$(sess "$JAR_A"); echo "A=$A"
BEFORE=$(curl -sk -H "Cookie: $A" "$ME" -w '\n[%{http_code}]'); echo "$BEFORE" | head -c 300
curl -sk -H "Cookie: ${A%%=*}=zp91234deadbeef" "$ME" -w '\n[%{http_code}]' | tail -3  # MUST fail
```

Pick one **identity marker** from `BEFORE` - email, user id, account name. That string, not the status
code, is what you grep for from here on. A form login takes `-d "username=$U_A&password=$P_A"`; try both
content types before calling an endpoint dead.

**3. Fixation - does the session cross the auth boundary unchanged, and can you choose it?**

```bash
JAR_F=$(mktemp)
curl -sk -c "$JAR_F" "https://$H/login" -o /dev/null; PRE=$(sess "$JAR_F")
curl -sk -c "$JAR_F" -b "$JAR_F" -X POST "https://$H/login" -d "username=$U_A&password=$P_A" -o /dev/null
POST=$(sess "$JAR_F"); [ -n "$PRE" ] && [ "$PRE" = "$POST" ] && echo "NO ROTATION across login"
curl -sk -H "Cookie: $POST" "$ME" | grep -c "$MARK"      # and it authenticates?

FIX="${A%%=*}=zpfix00000000000000000001"                  # attacker-chosen id
curl -sk -b "$FIX" -X POST "https://$H/login" -d "username=$U_A&password=$P_A" \
  -D - -o /dev/null | grep -i '^set-cookie'
curl -sk -H "Cookie: $FIX" "$ME" -w '\n[%{http_code}]' | tail -2
```

No rotation is half the bug. The other half is a **planting primitive** - the id accepted from a URL
(`/login;jsessionid=X`, `?PHPSESSID=X`), a `Domain=.target.tld` cookie writable from a sibling host, or
an XSS. Without one, say so and grade it down.

**4. Invalidation - the money phase.** One helper, five events. Never reuse the jar after a logout;
replay the **literal captured value**.

```bash
replay(){ curl -sk -H "Cookie: $1" "$ME" -w '\n[%{http_code}]'; }
curl -sk -b "$JAR_A" -X POST "https://$H/api/logout" -o /dev/null;        replay "$A" | grep -c "$MARK"
# password change driven from a SECOND session of the same account (JAR_B), then replay A:
curl -sk -b "$JAR_B" -X POST "https://$H/api/change-password" -H 'Content-Type: application/json' \
  -d "{\"old_password\":\"$P_A\",\"new_password\":\"$P_NEW\"}" -o /dev/null
replay "$A" | grep -c "$MARK"
```

Repeat for **email change**, **MFA enrolment or removal**, and the app's own **"log out of all devices"**
control. Apps routinely kill the acting session and leave the siblings alive - that is the persistent-ATO primitive.

**5. Cookie attributes, scope and prefixes.** Read every `Set-Cookie` the login flow emits.

```bash
curl -sk -c "$JAR_B" -b "$JAR_B" -D - -o /dev/null -X POST "https://$H/api/login" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$U_B\",\"password\":\"$P_B\"}" \
| grep -i '^set-cookie' | while IFS= read -r l; do n="${l#*: }"; printf '%-26s' "${n%%=*}"
    for a in HttpOnly Secure SameSite Domain Path Max-Age Expires; do
      grep -qi "$a" <<<"$l" && printf ' +%s' "$a" || printf ' -%s' "$a"; done; echo; done
curl -skI "https://$H/" | grep -iE 'strict-transport-security|referrer-policy'
```

`__Host-` (requires `Secure`, `Path=/`, **no** `Domain`) cannot be written by a sibling host, so it
largely kills cookie fixation; its absence is the precondition for step 3. `Domain=.target.tld` means
every subdomain, including the forgotten one, can read and overwrite the cookie.

**6. Identifier quality - decode before you count.** Sample modestly, inside the program rate
limit, anonymous `/login` only.

```bash
IDS=/tmp/zpids.txt; : > $IDS
for i in $(seq 1 40); do J=$(mktemp); curl -sk -c "$J" "https://$H/login" -o /dev/null
  sess "$J" | cut -d= -f2- >> $IDS; rm -f "$J"; sleep 2; done
sort $IDS | uniq -d; awk '{print length($0)}' $IDS | sort -n | uniq -c   # a duplicate alone is fatal
python3 - <<'PY'
import base64, time, re
for t in [l.strip() for l in open('/tmp/zpids.txt') if l.strip()][:8]:
    for k,f in (("b64",lambda s: base64.urlsafe_b64decode(s+"="*(-len(s)%4))),("hex",bytes.fromhex)):
        try: d=f(t)
        except Exception: continue
        if d and sum(32<=c<127 for c in d)/len(d) > .8: print(k, t[:18], d[:70])   # readable structure
    for m in re.findall(r'\d{9,13}', t):                                          # unix secs / millis
        if abs(int(m[:10])-time.time()) < 86400*365: print("timestamp", t[:18], m)
PY
```

Structure is the finding - an embedded user id, a unix time, a counter. A long random-*looking* string with no duplicates and no decode is **not** weak, and 40 samples cannot prove that it is.

**7. Timeouts, remember-me, and the session in a URL.** The clock ones cost wall-time - background
them and hunt something else meanwhile.

```bash
( sleep 3600; replay "$A" | tail -2 ) &        # idle: touch nothing, then 30 / 60 / 240 min, overnight
grep -iE 'remember|persistent|_rt|device' "$JAR_A"           # the persistent cookie, if any
curl -sk -H "Cookie: remember_token=<captured>" "$ME" -w '\n[%{http_code}]' | tail -2
grep -hoE '[?&;](jsessionid|JSESSIONID|PHPSESSID|sid|session|session_id|auth)=[^&;"'"'"'[:space:]]+' \
  surface/urls.txt js/*.js 2>/dev/null | sort -u
curl -sk "https://$H/share/abc?sid=$(cut -d= -f2- <<<"$A")" | grep -oE 'src="https?://[^"]+' | head
```

A remember-me cookie that authenticates alone is a bearer credential - it must rotate on each
redemption and die on password change; test both. Absolute lifetime needs one request every few minutes
over hours - note the `Max-Age` claimed, then whether the server enforces it. A session in a URL reaches
history, proxy and access logs, `Referer` on every off-site asset, and anything pasted into a support
ticket; absent or `unsafe-url` `Referrer-Policy` plus one third-party include is the proof, and
`zp-browser` witnesses the outbound `Referer`.

**8. Stop point for this class - state it in the report.** You stop when **your own** session survives an
event it should not, or **your own** planted identifier authenticates as you. You never accept, guess or
brute-force another person's identifier, use a stolen cookie, call revoke-all on an account you do not own,
or open sessions in bulk to exhaust a session store - that is DoS.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| pre-auth cookie carried through login | no regeneration on the auth boundary | `PRE == POST` and that value returns your marker |
| `Cookie: sid=zpfix000…` on `/login`, then `/login;jsessionid=X`, `?PHPSESSID=X`, `?sid=X` | server accepts a client-chosen id - the planting primitive | `Set-Cookie` echoes it, or `$FIX` authenticates as the account that logged in |
| old value after `POST /logout`, email change, or MFA removal | server-side destroy missing on that event | 200 **with the identity marker** |
| old value replayed after password change | credential-change revocation missing | same - this is the High |
| sibling session after "log out everywhere" | family revocation missing | sibling still marker-positive |
| remember-me cookie alone, session cookie dropped, then replayed twice | persistent bearer credential, no rotation on redemption | authenticated without a session, and again after use |
| `Set-Cookie` from a sibling host with `Domain=.target.tld` | shared parent-domain scope, no `__Host-` | your value survives into the app context |
| 40 anonymous ids decoded; idle 30/60/240 min; absolute over hours | structure in the id, no timeout enforced server-side | duplicate, monotonic delta, readable decode, or marker-positive past the claimed `Max-Age` |

Nothing above `curl`, `awk` and `python3` is needed. With an intercepting proxy running, `zp-proxy` replays the app's real login and logout requests instead of guessing endpoints.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| old session, or a remember-me cookie, marker-positive after **password change**, garbage control fails | **confirmed persistent ATO.** High, Critical if the change flow needs no current password |
| old session marker-positive after **logout**, or a sibling surviving "revoke all sessions" | confirmed. Medium to High on logout alone, higher for the revoke control - the user trusts it and it does nothing |
| client-chosen id accepted and authenticates | **confirmed fixation.** High; Critical where the victim can be an admin or SSO user |
| `PRE == POST` but no way to plant an id (`__Host-`, no URL acceptance, no sibling write) | incomplete. Low or informational until you demonstrate the plant |
| 200 after logout, but the body matches the anonymous reply or the **garbage cookie also** returns it | killed - the classic status-code false positive; if nothing is session-gated, route to `zp-authz` |
| session dies on a second attempt a minute later | lazy expiry on next access. Killed - re-test with a delay |
| session id decodes to a user id, timestamp or counter | **High** on structure alone. Do **not** brute-force to "prove" it |
| long random id, no duplicates in the sample, no decode | killed. Character counting is not an entropy claim |
| missing `HttpOnly` with no XSS sink, or missing `Secure` behind preloaded HSTS with no `http` listener | informational. Say why it is not exploitable here - `zp-xss` for the sink |
| `SameSite` absent or `None` | reachability only. Prove a cross-site state change first - `zp-cors` |
| session in URL plus an off-site include and no `Referrer-Policy` | confirmed leak. Without the include, Low - logs and history only |
| concurrent sessions allowed and documented, or the attack needed the victim's password | not a finding. Killed |

---

## High-value patterns

- **Password reset that revokes nothing but the resetting browser.** The highest-paid shape in this class - it defeats the one action every user takes after a compromise. Impersonation and support-login exits fail the same way in both directions.
- **"Log out of all devices" that only kills the acting session**, and remember-me tokens that never rotate and outlive every credential change on a year-long `Max-Age`.
- **A `Domain=.target.tld` session cookie plus a claimable subdomain** - `zp-takeover` gives the write, this skill gives the fixation. The chain is the report.
- **Admin, support or staging hosts sharing the parent-domain cookie**, and containers that still accept a pre-auth id from a URL path parameter.
- **Session ids that decode**, in bespoke auth predating the framework, and in mobile APIs minted without expiry because the app "handles logout locally" - `zp-mobile`.

---

## Pitfalls

- **Status-only claims, and skipping the garbage-cookie control.** Body-diff against the authenticated baseline and grep the identity marker every time; without the control you cannot tell a surviving session from an ungated endpoint.
- **An edge cache serving the 200, or an IP-pinned session read as "invalidated".** Add a cache buster, replay from the egress you captured from; a cacheable authenticated page is its own finding - `zp-cache-poison`.
- **Placeholder tokens, or reusing the jar after logout** - logout overwrites it. Two sessions captured from real flows, replayed as literal values.
- **Credential stuffing, or touching a real user's session** - a cookie you were sent, one found in a log, or revoking someone's access. Program-issued accounts only.
- **Opening thousands of sessions** for entropy, or to exhaust a session table. Forty, rate-limited, decoded - never eyeballed.
- **Filing missing `HttpOnly` or `SameSite` standalone as High, or a fixation report with no planting primitive.** The first triage question is "how does the attacker set the id?"
- **Mixing token internals in.** `alg`, `kid`, `exp` and refresh rotation are `zp-jwt-oauth` - cross-reference, never duplicate.

---

## Hand off to

Token internals, refresh rotation, OAuth and SSO logout gaps -> `zp-jwt-oauth`. Cookie theft sinks and
`HttpOnly` chains -> `zp-xss`. `SameSite`, CSRF and cross-origin reads -> `zp-cors`. Endpoints never
session-gated -> `zp-authz`, `zp-idor`. Parent-domain cookie plus a dangling subdomain -> `zp-takeover`.
Authenticated responses in a shared cache -> `zp-cache-poison`. Ids or endpoints in bundles ->
`zp-js-secrets`. Real login traffic to replay -> `zp-proxy`; browser proof of a `Referer` leak or a
planted cookie -> `zp-browser`. Double-redemption of a one-time session -> `zp-race`. Impersonation and
entitlement logic -> `zp-business-logic`. Sessions minted in a binary -> `zp-mobile`. A new host found
mid-test -> `zp-scope` first. Confirmed -> `zp-triage`, then `zp-report`.
