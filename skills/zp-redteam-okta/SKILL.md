---
name: zp-redteam-okta
description: ZeroProtocol red-team skill for Okta and federated identity providers - tenant discovery, factor and policy weaknesses, ROE-gated MFA fatigue and factor downgrade, API token and service-account abuse, admin role assignment, SAML and OIDC app misconfiguration, inbound and outbound federation trust, session and device trust, and the IdP-to-SaaS blast radius. Use when a signed engagement names an Okta tenant or Okta as the SSO provider. Requires a signed engagement, not a bounty page.
---

# zp-redteam-okta - the IdP is the blast radius

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse, and name which of the six engagement facts is
missing (signed document, named scope, dates, two contacts, deconfliction channel, stop condition).
`zp-scope check <host>` still applies to every host you touch, and a plain bounty-tier allow is
**not** a substitute for the tier gate.

This skill answers one question - **from the position the engagement gave you, what can an
intruder make this identity provider assert, and which control stops them?** Okta rarely fails in
its own code; it fails at the trust edges around it - inbound federation, long-lived API tokens,
bearer session cookies and SAML apps nobody reviewed since onboarding. The deliverable is a path
in timestamped steps, the earliest control that breaks it, the downstream SaaS the assertion
reaches, and what the defenders saw. A `sessionToken` is not a trophy; the control gap is.

---

## Procedure

1. **Clear the tier gate** - the six engagement facts go into `.zeroprotocol/scope.yaml` by key
   name (`authorization_ref`, `contact_technical`, `contact_stop`, `window`, `deconfliction`,
   `stop_condition`), which is what `zp-scope tier redteam` reads. Then list every in-scope tenant
   by cell - `okta.com`, `okta-emea.com`, `oktapreview.com`, plus any government cell the SoW
   names. A preview or sandbox tenant is a **separate tenant with separate authorization**, and a
   sister brand's tenant is a third party until the scope says otherwise.
2. **Read the org's shape from outside** - tenant id, auth pipeline (Classic vs Identity Engine),
   issuers, custom domain, which corporate apps redirect here. Observable metadata, so it runs
   before any credential.
3. **Profile factors and policies with the account the engagement handed you**, never a guessed
   identity. `question` or `sms` beside `webauthn` is the finding before you touch anything.
4. **Validate only supplied credentials** - a client test account, or a dump the client gave you.
   No generated list unless the SoW contracts a spray in writing and fixes the per-user cap. Okta
   lockout is often three failures - one attempt per user, serial, jittered, state file, kill switch.
5. **Enumerate as the provided principal** - read-only directory, policy, app and role work
   through `/api/v1/*` with the token the engagement issued.
6. **Map the five escalation surfaces**, cheapest proof first - factor and policy downgrade, API
   token and service-account scope, admin role assignment, app and federation trust, session and
   device trust.
7. **Score the federation seam both ways.** Inbound - can an IdP object assert a subject that links
   to an existing Okta user? Outbound - which SaaS tenants accept this org's assertions, and does
   one of them grant administrative access?
8. **Ask what fired.** Query the System Log for each step's event and ask the contact whether an
   alert reached a human. Record it per step, not once at the end.
9. **Write the path, remove every artifact, verify each removal**, hand over the inventory.

---

## Commands

**Outside view - no credential**

```bash
T=client; H=$T.okta.com            # or $T.okta-emea.com / $T.oktapreview.com
curl -s "https://$H/.well-known/okta-organization" | jq .        # org id + pipeline: v1=Classic, idx=Identity Engine
curl -s "https://$H/.well-known/openid-configuration" | jq -r '.issuer,.authorization_endpoint'
for n in sso login auth okta idp; do dig +short "$n.client.example" CNAME; done
curl -skIL -o /dev/null -w '%{url_effective}\n' "https://app.client.example/login"
```

`pipeline` decides everything downstream - `v1` is the Classic `/api/v1/authn` flow, `idx` the
Identity Engine `/idp/idx/*` flow. Guessing wrong makes a hardened endpoint look broken.

**Factors and policy, with the engagement-provided account (Classic pipeline)**

```bash
curl -s -X POST "https://$H/api/v1/authn" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$U\",\"password\":\"$P\"}" \
  | jq '{status, factorResult, factors: [._embedded.factors[]? | {factorType, provider, status}]}'
```

`status` is the whole answer - `MFA_REQUIRED` or `PASSWORD_EXPIRED` means the password validated and
you stop there, `SUCCESS` plus a `sessionToken` means no second factor at all. Identity Engine orgs -
read `/api/v1/authenticators` instead of driving the `idx` flow. No `jq` - `python3 -m json.tool`.

**Enumeration as the provided principal - read-only**

```bash
A=(-H "Authorization: SSWS $OKTA_TOKEN" -H 'Accept: application/json')   # or -H "Authorization: Bearer $DPOP_OR_OAUTH_TOKEN"
curl -s "${A[@]}" "https://$H/api/v1/api-tokens/current" | jq '{id,name,userId,expiresAt,clientName}'
curl -sD - -o /dev/null "${A[@]}" "https://$H/api/v1/users/me" | grep -i '^x-rate-limit'
curl -s "${A[@]}" "https://$H/api/v1/users?limit=1" -D - -o /dev/null | grep -i '^link'   # reach, by paging - not by export
for t in PASSWORD OKTA_SIGN_ON MFA_ENROLL ACCESS_POLICY IDP_DISCOVERY PROFILE_ENROLLMENT; do
  curl -s "${A[@]}" "https://$H/api/v1/policies?type=$t" | jq -r --arg t "$t" '.[]? | [$t,.name,.status] | @tsv'
done
curl -s "${A[@]}" "https://$H/api/v1/policies?type=PASSWORD" | jq '.[].settings.password.lockout'
curl -s "${A[@]}" "https://$H/api/v1/authenticators" | jq -r '.[] | [.key,.type,.status] | @tsv'
curl -s "${A[@]}" "https://$H/api/v1/iam/roles"      | jq -r '.roles[]? | [.id,.label] | @tsv'
curl -s "${A[@]}" "https://$H/api/v1/users/$UID/roles"  | jq -r '.[] | [.type,.status] | @tsv'
curl -s "${A[@]}" "https://$H/api/v1/groups/$GID/roles" | jq -r '.[].type'        # admin by group membership
# applications and federation trust
curl -s "${A[@]}" "https://$H/api/v1/apps?limit=200" | jq -r '.[] | [.id,.signOnMode,.status,.label] | @tsv'
# the metadata resource is an XML document - ask for XML instead of reusing the JSON Accept in A[]
curl -s -H "Authorization: SSWS $OKTA_TOKEN" -H 'Accept: application/xml' \
  "https://$H/api/v1/apps/$APP/sso/saml/metadata" \
  | grep -oE 'WantAssertionsSigned="[a-z]+"|AuthnRequestsSigned="[a-z]+"|NameIDFormat[^<]*'
curl -s "${A[@]}" "https://$H/api/v1/apps/$APP" \
  | jq '.settings.oauthClient | {application_type,grant_types,response_types,token_endpoint_auth_method,redirect_uris,wildcard_redirect}'
curl -s "${A[@]}" "https://$H/api/v1/apps/$APP/grants" | jq -r '.[].scopeId'
curl -s "${A[@]}" "https://$H/api/v1/idps" \
  | jq -r '.[] | [.id,.type,.status,.policy.provisioning.action,.policy.accountLink.action,.policy.subject.matchType] | @tsv'
curl -s "${A[@]}" "https://$H/api/v1/trustedOrigins" | jq -r '.[] | [.origin,(.scopes|map(.type)|join(","))] | @tsv'
```

`accountLink.action` of `AUTO` on an inbound IdP is tenant-wide impersonation in one field - an IdP
an admin can add, asserting a subject that auto-links to an existing identity. Read the field;
never create an IdP to prove it.

**Detection check - run this after every step, not at the end**

```bash
S=$(date -u -d '-2 hours' +%Y-%m-%dT%H:%M:%SZ)
curl -s "${A[@]}" --get "https://$H/api/v1/logs" --data-urlencode "since=$S" \
  --data-urlencode 'filter=eventType eq "user.session.start" or eventType eq "system.api_token.create" or eventType eq "user.account.privilege.grant" or eventType eq "user.mfa.factor.deactivate" or eventType eq "policy.lifecycle.update" or eventType eq "user.authentication.auth_via_IDP" or eventType eq "user.session.impersonation.initiate" or eventType eq "security.threat.detected"' \
  | jq -r '.[] | [.published,.eventType,.outcome.result,.actor.alternateId] | @tsv'
```

Device-trust and FastPass behaviour on an **engagement-issued** host only - `OktaTerrify`
(silverhack) is the one verifiable public Okta-specific offensive tool. Everything else here is
`curl` and `jq`; write engagement scripts rather than cite a toolkit whose flags you cannot check.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| `status` is `MFA_REQUIRED` or `PASSWORD_EXPIRED` | **password confirmed valid.** Stop - you do not need the session to report it |
| `401` with `E0000004`, or any older primitive now returning identical bytes for existing and non-existing input | hardened. Okta unified unknown-user and wrong-password, so it is **not** an existence oracle - re-verify every primitive per engagement |
| `SUCCESS` plus a `sessionToken` on the first call | **no second factor for this principal.** Finding, and usually a policy scope gap rather than a missing factor |
| `question` or `sms` enabled alongside `webauthn` in an authentication policy rule | **factor-downgrade path.** The weakest permitted method is the org's real MFA strength |
| a global session or authentication policy whose rule excludes a service account, a break-glass user or a named app | **finding.** Exclusions are where Okta policy actually fails |
| API token with no `expiresAt`, bound to a super admin, or a group whose membership confers an admin role | **finding on the record alone** - a long-lived bearer token, or a group write that becomes org admin |
| SAML app with `WantAssertionsSigned="false"` | assertion-replay exposure -> `zp-jwt-oauth`. Confirm against the SP, do not forge |
| OIDC app with a wildcard `redirect_uris` entry or `token_endpoint_auth_method` of `none` for a confidential flow | **auth-code theft path.** Prove from the app config, then one redirect observation |
| inbound IdP with `accountLink.action` `AUTO` and a loose `subject.matchType` | **Critical - tenant-wide impersonation** by anyone who can add an IdP. Prove by reading it |
| session cookie replays from a different IP with no device or DPoP binding | **confirmed** - Okta sessions are bearer tokens. Replay once, from the engagement source IP |
| `oktapreview` or sandbox tenant federated to a production app | **Critical** - a weaker tenant asserting into production, usually unowned |
| a control blocked you and an alert fired | **not a finding - say so.** Controls that worked belong in the report |
| the telemetry recorded your step and no alert reached a human | **finding, first-class.** Often worth more to the client than another escalation path |

---

## Least-invasive proof

| Capability | Smallest action that proves it | Never |
|---|---|---|
| valid password | the post-validation `status` from one `authn` call | keep authenticating to "get a session anyway" |
| super administrator, or admin role via group | your own role assignments, the group's role grant, and one object only that role can read | create a user, assign a role, join the group, reset a password, deactivate MFA |
| directory read at scale | the first page plus the `Link` header, and the schema of one record | export the user, group or device list |
| API token or service-account scope | `/api/v1/api-tokens/current`, and the app's granted `scopeId` list | create a token, write with one, or mint a scope you were not asked to exercise |
| factor downgrade | the authenticator set plus the policy rule constraints | enrol, reset or deactivate a real user's factor |
| MFA fatigue exposure | that `push` is permitted and Number Challenge is not required, from policy | send a push to a real employee unless the ROE explicitly authorises user interaction, and then only to a consenting test account, capped and logged |
| SAML app trust | the SP metadata and the app's assignment list | mint an assertion for a real user, or sign into the SaaS as one |
| OIDC redirect weakness | the registered `redirect_uris` and one observed redirect to a host **you** own and the ROE names | complete a code exchange on a real user's authorization |
| inbound federation impersonation | the IdP object's linking and matching policy | create an IdP, change a `NameID`, link an account |
| outbound blast radius | the app inventory mapped to SaaS tenants, labelled as assessment | sign into a downstream SaaS to "confirm" reach |
| session replay, device trust and FastPass | one replay of your own session from the engagement source IP, and the device record's management attributes | replay a real user's cookie, carry one off the test host, or enrol a device on production unless the ROE names it |

The rule underneath all of it - **enumerate rather than exercise.** A read that shows you could is
worth as much in the report as a write, and cannot be mistaken for a real intruder.

---

## Deconfliction

| What | How |
|---|---|
| source IPs | fixed, listed in the engagement file, given to the SOC before step 2 - Okta network zones and ThreatInsight both key on them |
| naming | every object you create carries the engagement reference - `zp-<ref>-<n>`, never a plausible business name |
| logging | append-only JSONL per action - UTC timestamp, tenant, principal, endpoint, `status`/`errorCode`, attempt counter. Record the first four characters of any password tested, never the password |
| artifacts | every created or modified object lands in `.zeroprotocol/artifacts.md` at the moment of creation, not afterwards |
| call the contact | before any factor, policy, app or IdP change; before any authorised push campaign; the moment lockouts appear that your cap cannot explain; on any sign of a real intruder; if an action would reach a downstream SaaS or a partner tenant |
| answer speed | you must be able to tell the SOC which System Log entries were you, within minutes, for the whole window |

---

## Cleanup

| Artifact this skill can create | Removal | Verification |
|---|---|---|
| authenticated sessions and `sessionToken`s | `DELETE /api/v1/sessions/me`, and clear the sessions for any principal you authenticated as | a replay of the session is rejected |
| API token created during the run | revoke it by id | absent from `/api/v1/api-tokens`; `system.api_token.revoke` present in the System Log |
| app, IdP, policy, rule, trusted origin or network zone created or modified | delete what you created; restore what you changed from the pre-change snapshot | the object returns 404, or its config matches the snapshot field for field |
| group, membership, admin role assignment or enrolled device | remove it | the assignment list and device list match the pre-run snapshot |
| local working set - tokens, cookies, log exports, HAR captures, screenshots | destroy on completion; keep only redacted report evidence | the working directory is gone and no live secret survives in the report |

Snapshot every collection **before** you touch it, so cleanup is a diff and not a memory exercise.
Then walk `.zeroprotocol/artifacts.md` in reverse, verify each line, and hand the inventory over.

---

## Pitfalls

- **Running this off a bounty scope.** A `zp-scope check` allow is not `zp-scope tier redteam`. Wrong gate, no authorization.
- **Reading `E0000004` as user enumeration**, or trusting any 2022-era primitive without re-verifying it this engagement. Okta hardened most of them.
- **Guessing passwords the engagement did not provide**, or exceeding the agreed per-user cap. Okta lockout is often three failures - you become the outage.
- **Concurrency on authentication.** Parallel calls trip anti-automation and rate limits separate from per-user lockout, flood ambiguous lockout results and burn caps you cannot re-spend. Serial with jitter, always.
- **Sending pushes to real employees**, or any help-desk call, reset request or phishing page. MFA fatigue and every other route through a person is social engineering of staff, a separate written authorization; without it, document the exposure from policy and stop.
- **Resetting a real user's factor** to reach a weaker one, or **disabling ThreatInsight, network zones, behaviour detection or an event hook** to make a path work. Both are tampering with production controls.
- **Exporting the user, group or device directory** to show impact. The first page and the `Link` header prove reach.
- **Signing into a downstream SaaS** because the assertion would work, or **touching a tenant the scope does not name** - sister brands, acquisitions, `oktapreview` twins and partner IdPs are separate authorization decisions, and some are other companies.
- **Uploading a HAR or traffic capture to a vendor support case.** Those files carry live session cookies, and that is exactly how a well-known IdP breach started.
- **Leaving an API token, IdP, app, policy rule, group membership or device behind**, or keeping tokens and credentials after the window closes.
- **Testing sign-in availability limits.** Denial of service against the IdP takes the whole workforce offline at once.
- **Reporting only escalation paths.** Detection gaps are first-class findings - "the System Log captured this and no alert fired" is frequently worth more to the client than another route to super admin, and it is the half of the report only a red team can write.

---

## Hand off to

Tier gate and engagement facts -> `zp-redteam-mode`. Per-host scope -> `zp-scope`. Tenant surface
before any credential -> `zp-recon-passive`, `zp-recon-active`. SAML assertion, OIDC redirect and
token flaws -> `zp-jwt-oauth`; session lifetime, cookie binding and replay -> `zp-session`.
Okta-federated Entra or M365 -> `zp-redteam-entra`; on-prem AD behind an Okta AD agent ->
`zp-redteam-ad`. AWS or Azure roles assumed through an Okta app -> `zp-cloud`. Admin API
authorization gaps -> `zp-api`, `zp-authz`. Sign-in evidence in a real browser -> `zp-browser`.
Agent or MCP integrations consented into the org -> `zp-agentic`. Okta advisories -> `zp-cve`.
Tools -> `zp-toolchain`. Findings -> `zp-triage`, then `zp-report` for the attack narrative.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
