---
name: zp-redteam-entra
description: ZeroProtocol red-team skill for Entra ID and M365 adversary emulation - tenant and user enumeration, Conditional Access gaps, legacy auth, illicit OAuth consent grants, service principal and managed identity abuse, Graph permission escalation, cross-tenant access, PIM roles, device and PRT handling, and the Entra Connect seamless-SSO pivot. Use when a signed engagement names an Entra tenant, an onmicrosoft.com domain or login.microsoftonline.com. Requires a signed engagement, not a bounty page.
---

# zp-redteam-entra - the tenant is the perimeter

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse, and name which of the six engagement facts is
missing (signed document, named scope, dates, two contacts, deconfliction channel, stop
condition). `zp-scope check <host>` still applies to every individual host you touch, and the
plain bounty check is **not** a substitute for the tier gate.

This skill answers one question: **from the position the engagement gave you, how far into the
tenant can an intruder walk, and which control stops them?** In Entra there is no network edge to
hide behind - every identity, app registration and consent grant is reachable from the internet
with a token. The deliverable is a path written as steps with timestamps, the earliest control
that breaks it, and what the defenders saw at each step. A token is not a trophy; the control
gap is the finding.

---

## Procedure

1. **Clear the tier gate** - the six engagement facts go into `.zeroprotocol/scope.yaml` by key
   name (`authorization_ref`, `contact_technical`, `contact_stop`, `window`, `deconfliction`,
   `stop_condition`), which is what `zp-scope tier redteam` reads. Then confirm which tenant IDs
   are in scope. Sister brands and acquisitions often sit in **separate tenants** with separate
   policies - each needs its own line in the scope, and an out-of-scope tenant is a third party.
2. **Unauthenticated tenant profile.** Tenant ID, verified domains, federation type per domain,
   whether seamless SSO is advertised, whether SharePoint and Teams are provisioned. This is
   third-party-observable metadata, so it runs before any credential is used.
3. **User enumeration without an authentication attempt.** Prefer primitives that never reach a
   sign-in endpoint, because those cost nothing against Smart Lockout and leave a different
   telemetry trail. Re-verify each primitive still differentiates before trusting it - Microsoft
   hardens these continuously and a hardened endpoint returns identical answers for everything.
4. **Credential validation - only with what the engagement handed you.** Client-supplied stealer
   dumps or a provided test account. Never a generated guess list unless the SoW contracts for a
   spray in writing and fixes the per-user cap. One attempt per user per engagement, serial,
   jittered, atomic state file, kill switch.
5. **Authenticate as the provided principal** and pivot to enumeration. Everything from here is
   read-only directory work through Graph or ROADrecon.
6. **Map the four escalation surfaces** in this order, because each is cheaper than the last to
   prove and more valuable to the client - Conditional Access gaps, consent and app grants,
   role and PIM assignment, cross-tenant and device trust.
7. **Score the on-prem seam.** Entra Connect, password hash sync, pass-through auth agents and
   the seamless-SSO computer account are the hinge between the two estates in both directions.
8. **Ask what fired.** For every step, check whether sign-in and audit telemetry recorded it, and
   whether an alert reached anyone. Record the answer per step, not once at the end.
9. **Write the path, remove the artifacts, verify each removal**, hand over the inventory.

---

## Commands

**Outside view - no credential, no sign-in attempt**

```bash
D=client.example
curl -s "https://login.microsoftonline.com/$D/.well-known/openid-configuration" | jq -r '.issuer,.tenant_region_scope'
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@$D&xml=1"
msftrecon -d "$D"                       # tenant id, domains, federation, SharePoint, consent endpoint
```

No tool available - the two `curl` calls above give tenant ID and federation type on their own.
`Managed` means cloud-only credential handling; `Federated` means the credential is validated at
another IdP and that IdP is a separate authorization decision.

```powershell
Invoke-AADIntReconAsOutsider -DomainName $D | Format-Table   # domains, DesktopSSO (seamless SSO) state
```

**Enumeration as the provided principal - read-only**

```bash
az login --allow-no-subscriptions            # or Connect-MgGraph with the engagement account
G=https://graph.microsoft.com
az rest -m get -u "$G/v1.0/organization?\$select=id,displayName,onPremisesSyncEnabled"
az rest -m get -u "$G/v1.0/policies/authorizationPolicy"                     # user consent, app creation, guest rights
az rest -m get -u "$G/v1.0/identity/conditionalAccess/policies"            # needs Policy.Read.All or
                                                                           # Policy.Read.ConditionalAccess.
                                                                           # NOT policies/conditionalAccessPolicies -
                                                                           # that alias only ever existed under /beta
az rest -m get -u "$G/v1.0/oauth2PermissionGrants"                           # delegated consent already granted
az rest -m get -u "$G/v1.0/applications?\$select=id,appId,displayName,passwordCredentials,keyCredentials"
az rest -m get -u "$G/v1.0/roleManagement/directory/roleAssignments?\$expand=principal"
az rest -m get -u "$G/beta/policies/crossTenantAccessPolicy/partners"        # inbound MFA/device trust from partners
az rest -m get -u "$G/beta/auditLogs/signIns?\$filter=clientAppUsed%20eq%20'IMAP4'&\$top=20"
```

```bash
roadrecon auth --device-code --tenant <tenant-id>      # or -u/-p with the provided account
roadrecon gather && roadrecon plugin gui               # offline copy of the directory, queryable
```

```powershell
Import-Module .\GraphRunner.ps1
Invoke-GraphRecon -Tokens $tokens -PermissionEnum      # tenant settings plus what your token can do
Invoke-DumpCAPS   -Tokens $tokens -ResolveGuids        # Conditional Access as the tenant sees it
Invoke-DumpApps   -Tokens $tokens                      # app registrations, consent grants, owners
```

**Legacy and device paths**

```bash
# Legacy auth is a tenant-state question, not a probe. outlook.office365.com is Microsoft's shared
# multi-tenant endpoint: it returns the same banner for every tenant on earth, it is not the client's
# host, and it has not been through zp-scope check - so it decides nothing. Read the tenant instead:
az rest -m get -u "$G/v1.0/policies/authenticationMethodsPolicy"
#   plus the signIns query above filtered on clientAppUsed, the authentication-policy assignment, and
#   per-mailbox state from Exchange Online: Get-CASMailbox -Identity <upn> | fl *Enabled*

# ROE must name device registration AND the technical contact must be called first - both are
# MANDATORY below. Without either, stop at the device-trust read (the device record plus its
# compliance attributes): it proves the same gap and writes nothing to a production tenant.
roadtx device -a register -n zp-<engagement-ref>-01      # ARTIFACT, and the one write in this skill -
                                                         # log it at creation, delete it at the end
roadtx prt -a <device> ; roadtx browserprtauth           # PRT handling on an engagement-provided host only
```

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| sign-in returns a code Entra only emits **after** the password validated (MFA required, CA blocked, device state required, external auth required) | **credential confirmed valid.** Stop there - you do not need the token to report it |
| `"access_token"` appears in an error body | **not a token.** A CA step-up challenge is a JSON-encoded *string* in the `claims` field, and inside that string `access_token` is the top-level member wrapping `capolids` - `claims="{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"<policy-guid>\"]}}}"`. Parse the response JSON and require a real top-level `access_token` on the token response itself, never a substring match, or every MFA-blocked attempt becomes a fake bypass |
| user-not-found vs wrong-password differential | existence oracle; only the wrong-password branch costs a lockout attempt |
| many accounts already locked while your cap is one attempt each | **you did not cause it.** Either you tripped the IP anti-spray layer or a real intruder is spraying now - pause, diagnose, and if it is not you, that is the stop condition and the most valuable finding in the run |
| a CA policy exists but excludes a break-glass, a service account or a named app | **finding.** Exclusions are where CA actually fails |
| CA report-only policy that would have blocked the path | gap, Medium - it was designed and never enforced |
| user consent to apps left at the permissive default | **finding** - illicit consent grant is reachable without any credential theft |
| an app registration a non-admin can add a credential to | **escalation path.** Prove the write permission from role data, do not add the credential |
| a service principal holding `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All` | **Critical path to Global Administrator.** Prove by reading the grant, never by assigning a role |
| eligible-but-not-active PIM assignment with no approval or justification required | **finding** - PIM present, PIM not configured |
| inbound cross-tenant policy that trusts a partner's MFA and device claims | **finding** - the partner's tenant is now part of this blast radius, and it is out of your scope to test |
| seamless SSO enabled and the computer account's password never rotated | **finding on age alone**, from the directory record. Do not forge anything |
| legacy protocol answering but no successful legacy sign-in in the logs | exposure, not a path - report as hardening |
| a token you obtained has a permission you never exercised | still a finding. Describe the capability; the permission grant is the evidence |
| a control blocked you cleanly and an alert fired | **not a finding - say so.** Controls that worked belong in the report too |

---

## Least-invasive proof

| Capability | Smallest action that proves it | Never |
|---|---|---|
| valid credential | the post-validation error code from one sign-in | keep signing in to "get a token anyway" |
| Global Administrator | read your own role assignments plus one directory object only that role can read | assign a role, add an admin, reset a password |
| directory read at scale | `$count` on the collection and the schema of one record | export the user, group or contact list |
| mailbox access | list folder names for the provided account | read, move, forward or copy a real user's mail |
| SharePoint / OneDrive reach | the site inventory, titles only | download documents |
| consent-grant path | the authorization policy value plus the app's requested scopes | complete a consent grant on a real user |
| app credential injection | the role or ownership that would permit it | add a secret, certificate or federated credential |
| managed identity abuse | the identity's role assignments from ARM read APIs | request its token, or act with it |
| Graph permission escalation | the app role grant on the service principal | mint the higher-privileged token |
| PIM weakness | the eligibility and its approval settings | activate the role |
| device trust | the device record and its compliance attributes | register a device on a production tenant unless the ROE names it |
| PRT handling | that a PRT is obtainable on the engagement-issued host | carry a PRT off that host, or keep it after the run |
| on-prem to cloud seam | sync state, agent inventory, SSO account age | extract hashes, forge a ticket, impersonate a synced admin |

The rule underneath all of it - **enumerate rather than exercise.** A read that shows you could
is worth as much in the report as a write, and it cannot be mistaken for the real intruder.

---

## Deconfliction

| What | How |
|---|---|
| source IPs | fixed, listed in the engagement file, given to the SOC before step 2 |
| naming | every object you create carries the engagement reference - `zp-<ref>-<n>`, never a plausible business name |
| logging | append-only JSONL per action - UTC timestamp, tenant, principal, endpoint, outcome code, attempt counter. Record the first four characters of any password tested, never the password |
| artifacts | every created or modified object lands in `.zeroprotocol/artifacts.md` at the moment of creation |
| call the contact | before any device registration or app credential change; the moment lockouts appear that your cap cannot explain; on any sign of a real intruder; if an action would touch a partner tenant |
| answer speed | you must be able to tell the SOC which of their alerts were you within minutes, for the whole window |

---

## Cleanup

| Artifact this skill can create | Removal | Verification |
|---|---|---|
| registered device object | delete the device in Entra | the device ID returns 404 on a Graph read |
| PRT or refresh tokens on the test host | revoke the session for that principal, wipe the token cache and the host's working directory | a replay of the token is rejected |
| app registration or service principal created for a test | delete it, then purge from deleted items | absent from `/v1.0/applications` and from deleted items |
| secret, certificate or federated credential added to an existing app | remove that specific credential | the credential ID is gone and the app's remaining credentials match your pre-change note |
| consent grant made during the run | revoke the `oauth2PermissionGrant` or `appRoleAssignment` | the grant no longer appears for that principal |
| group membership or role activation | remove, and let any PIM activation expire rather than extending it | assignment list matches the pre-run snapshot |
| uploaded or created files in SharePoint, OneDrive or Teams | delete, then empty the recycle bin at both stages | not present in first or second-stage recycle bin |
| local working set - tokens, dumps, `roadrecon.db`, screenshots | destroy on completion; keep only redacted report evidence | the working directory is gone and the report carries no live secret |

Snapshot the collections you will touch **before** touching them, so cleanup is a diff and not a
memory exercise. Then walk `.zeroprotocol/artifacts.md` in reverse, verify each line, and hand the
completed inventory to the client. An artifact you forgot is persistence you installed.

---

## Pitfalls

- **Running this off a bounty scope.** The plain `zp-scope check` allow is not the tier gate. Wrong gate, no authorization.
- **Concurrency on authentication.** Parallel sign-ins trip an IP-reputation layer that is separate from per-user lockout, flood ambiguous lockout codes, contaminate your existence data and burn caps you cannot re-spend. Serial with jitter, always.
- **Guessing passwords the engagement did not provide**, or exceeding the agreed per-user cap. You become the outage.
- **Substring-matching OAuth error bodies** and reporting phantom CA bypasses.
- **Assuming one tenant.** Sister domains and acquisitions have their own policies - and any tenant not named in the scope is a third party you must not touch.
- **Treating a partner tenant as in scope** because cross-tenant trust made it reachable. It is someone else's estate.
- **Exfiltrating the user, mailbox or document set** to show impact. A count and a schema prove reachability.
- **Disabling or excluding yourself from CA, MFA or Defender** to make a path work. That is tampering with a production control.
- **Consent-phishing a real employee**, or any device-code flow that needs a real person to click. Social engineering is a separate authorization.
- **Leaving a registered device, app credential, consent grant or active role behind.**
- **Retaining tokens, hashes or credentials after the window closes.**
- **Testing sign-in availability limits.** Denial of service against a tenant takes the client's whole workforce offline.
- **Reporting only escalation paths.** Detection gaps are first-class findings - "the sign-in and audit telemetry captured this step and no alert fired" is frequently worth more to the client than another route to Global Administrator, and it is the half of the report only a red team can write.

---

## Hand off to

Tier gate and engagement facts -> `zp-redteam-mode`. Per-host scope decisions -> `zp-scope`.
Tenant surface from outside, before any credential -> `zp-recon-passive`, `zp-recon-active`.
Token, SAML assertion and federation flaws -> `zp-jwt-oauth`. Azure subscription and managed
identity blast radius -> `zp-cloud`. Graph and other API authorization gaps -> `zp-api`,
`zp-authz`. Browser-driven sign-in evidence and PRT-backed sessions -> `zp-browser`.
Copilot, agent and MCP integrations consented into the tenant -> `zp-agentic`. Published CVEs on
Connect, ADFS or an exposed appliance -> `zp-cve`. Tool availability -> `zp-toolchain`.
Findings -> `zp-triage`, then `zp-report` for the attack narrative and the artifact inventory.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
