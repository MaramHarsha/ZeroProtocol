---
name: zp-redteam-mode
description: ZeroProtocol engagement gate for the zp-redteam-* tier - internal red-team and adversary-emulation work against enterprise identity and infrastructure. Use before any Active Directory, Entra, Okta, VPN appliance, vCenter, cloud-IAM or supply-chain assessment, and whenever lateral movement or post-exploitation is contemplated. A bug bounty program page does NOT authorize this tier; it requires a signed engagement with named scope, dates, deconfliction contacts and an agreed stop condition.
---

# zp-redteam-mode - a different authorization bar

**Phase:** 1 (replaces the bounty gate for this tier) | **Gate:** this skill **is** the gate.

Everything else in ZeroProtocol stops at proof and never pivots. That discipline is what makes
the scope gate meaningful, and it is correct for bug bounty. The `zp-redteam-*` tier is
different: adversary emulation is *supposed* to move laterally, because the question being
answered is "how far could a real intruder get, and would we see them?"

That capability is only legitimate under a much higher authorization bar. A public bug bounty
program page authorizes testing named internet-facing assets. **It does not authorize touching
an identity provider, relaying credentials, or moving between hosts.** Doing that under a bounty
program is unauthorized access to a computer system, regardless of intent.

So this tier does not unlock from `scope.yaml` alone.

---

## The six things that must exist before this tier runs

Record them in `.zeroprotocol/engagement.yaml`. If any is missing, **stop and ask** — do not
proceed on a verbal "yes, go ahead".

| # | Requirement | Why it is not optional |
|---|---|---|
| 1 | **A signed engagement document** — SoW, contract, or a written authorization-to-test from someone with authority over the systems | The signature is what separates adversary emulation from intrusion |
| 2 | **Named scope**: domains, IP ranges, tenants, identity providers, and explicit exclusions | "The whole network" is not a scope; it is an absence of one |
| 3 | **Dates and hours** the engagement is authorized to run | Activity outside the window has no cover |
| 4 | **Two named contacts**: a technical point of contact and someone who can stop the engagement | You will need one of them at 2am |
| 5 | **A deconfliction channel and procedure** | The defenders must be able to ask "is this you?" and get an answer in minutes |
| 6 | **An agreed stop condition** — what ends the engagement immediately (evidence of a real intruder, production impact, reaching the crown jewel) | Decided in advance, never in the moment |

```bash
zp-scope init --target <primary> --platform private
# then record the engagement facts alongside it, and confirm with the authorization reference:
zp-scope confirm --by "<your name>" --authorization "SoW <ref>, signed <date>, contact <name>"
```

The `zp-scope` gate still applies to every host, exactly as in the bounty tier. This skill adds
requirements; it removes none.

---

## Deconfliction — the obligation people skip

Before the first action, agree and write down:

- the **source IPs** you will operate from, so defenders can distinguish you from a real attacker
- a **user-agent or header marker** where the protocol allows one
- a **naming convention** for every account, file, host and scheduled task you create
- who to call, and how fast they answer

Then, during the engagement, **log every action with a timestamp**. If the blue team opens an
incident, you must be able to say within minutes which of their alerts were you and which were
not. An engagement where that question cannot be answered has damaged the client's incident
response rather than tested it.

If you find evidence of a **real intruder**, stop immediately, preserve what you have, and call
the contact. That is the stop condition that overrides every objective.

---

## What stays forbidden, even here

A signed engagement widens the scope. It does not make these acceptable:

- **Destroying or encrypting data.** Ever. Prove access, do not exercise it destructively.
- **Exfiltrating real customer or employee PII.** Prove reachability with a count and a schema, not a copy.
- **Disabling or tampering with security controls** beyond what the ROE explicitly permits — and never EDR/AV on production without it in writing.
- **Denial of service**, unless the engagement explicitly contracts for it.
- **Touching systems outside the named scope**, including the client's suppliers, customers or partners.
- **Social engineering of real staff** unless separately and explicitly authorized — this is a distinct authorization, not implied by a technical SoW.
- **Leaving persistence behind.** Every implant, account, key, scheduled task and file is inventoried and removed at the end, and the removal is verified.
- **Retaining credentials or data after the engagement.** Destroy the working set; keep only what the report needs, redacted.

The standing rule from the rest of ZeroProtocol still holds: **stop at the least invasive action
that proves the point.** Domain admin is proven by a directory read, not by creating an account.

---

## Cleanup is a deliverable, not an afterthought

Maintain `.zeroprotocol/artifacts.md` from the first action, appending every change you make:

```
timestamp · host/tenant · what was created or changed · how to remove it · removed? (y/n) · verified by
```

At the end, walk it in reverse, remove everything, verify each removal, and hand the completed
list to the client. An artifact you forgot is a backdoor you installed.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| signed SoW, named scope, dates, contacts, deconfliction, stop condition | **proceed** with the tier |
| bug bounty program page only | **refuse.** This tier is not authorized. Stay in the bounty skills |
| verbal authorization, nothing written | **refuse**, and say what you need in writing |
| the person authorizing does not own the systems (e.g. a tenant the client rents) | refuse until the actual owner authorizes — cloud and SaaS tenancy matters |
| scope says "the whole network" | get an asset list; an unbounded scope protects nobody |
| engagement window has expired | stop, even mid-chain |
| you found a real intruder | **stop immediately**, preserve, call the contact |
| an action would be destructive or hit PII | do not take it; describe the capability instead |
| the client asks you to skip deconfliction | push back once, in writing; it is their incident response you would be degrading |

---

## Reporting

Red-team reporting differs from a bounty report. `zp-report` still owns the writing discipline,
but the deliverable is an **attack narrative**, not a list of bugs:

- the path taken, step by step, with timestamps, mapped to ATT&CK where useful
- **what the defenders saw** at each step — often the most valuable section in the whole report
- the specific control that would have broken the chain earliest, and the cheapest fix
- the artifact inventory with every item confirmed removed
- findings that stand alone, written as ordinary vulnerability reports

Detection gaps are findings. "You had the telemetry but no alert fired" is worth more to a client
than another privilege-escalation path.

---

## Hand off to

Gate cleared -> the tier: `zp-redteam-ad`, `zp-redteam-entra`, `zp-redteam-okta`,
`zp-redteam-vpn`, `zp-redteam-vcenter`, `zp-redteam-iam`, `zp-redteam-supplychain`.
External surface first -> the normal recon chain (`zp-recon-passive`, `zp-recon-active`), which
applies unchanged. Findings -> `zp-triage`, `zp-report`.

Gate not cleared -> the bug-bounty tier, and say plainly which authorization is missing.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0) enterprise attack matrices.
See `NOTICE.md`.
