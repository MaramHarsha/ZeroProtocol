---
name: zp-redteam-ad
description: ZeroProtocol red-team skill for on-prem Active Directory and Kerberos adversary emulation - domain and trust enumeration, attack-path analysis, Kerberoasting and AS-REP roasting, delegation abuse (unconstrained, constrained, RBCD), ACL and DACL abuse, ADCS template abuse ESC1-ESC8, NTLM relay paths and GPO abuse. Use when a signed engagement names an AD forest, a domain controller, an ADCS host or a tier-0 objective. Requires a signed engagement, not a bug bounty program page.
---

# zp-redteam-ad - the shortest path to tier-0, and the edge that breaks it

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse and say which of the six engagement facts is
missing (signed document · named scope · dates and hours · two named contacts · deconfliction
channel · agreed stop condition). `zp-scope check <host>` still applies to every individual host,
including every domain controller, every CA and every member server you touch.

This skill answers one question: **from the foothold the engagement gave you, what is the shortest
credible path to tier-0, and which single control breaks it earliest?** The deliverable is that
path written as an ordered edge list with the privilege each edge requires, plus what the
defenders saw at each step. It is not a Domain Admin screenshot. A path you enumerated and chose
not to walk, with the blocking control named, is a better finding than a trophy - and a path the
telemetry recorded with no alert firing is often the most valuable finding in the report.

---

## Procedure

1. **Clear the tier gate, then the host gate.** `zp-scope tier redteam`; then `zp-scope check` on
   each DC, CA and member server. Record the engagement's provided credential, its source, and the
   naming convention you agreed for any object you create.
2. **Establish domain topology.** Domain name, forest root, DC list, functional level, trusts and
   their direction and transitivity. Trust direction decides whether the forest is one blast radius
   or several.
3. **Collect the graph, once, read-only.** A single BloodHound collection is far quieter than weeks
   of ad-hoc LDAP. `DCOnly` first - it touches only the DC and asks no member host anything.
4. **Analyse before you act.** Run the shortest-path queries, then write the candidate paths out by
   hand with the privilege each edge needs. Rank by *edges you can traverse with what you already
   hold*, not by how interesting they are.
5. **Enumerate the credential-exposure classes** - SPN accounts, `DONT_REQ_PREAUTH` accounts,
   delegation flags, ADCS templates, writable GPOs, dangerous DACLs. Enumerate all of them; exercise
   the fewest.
6. **Prove exactly one edge per capability class**, at the least-invasive strength (next section),
   and log every artifact the moment you create it.
7. **Instrument the defence.** For each edge, ask the technical contact what their telemetry shows.
   Log the event IDs you expected against what alerted.
8. **Write the path, the earliest-breaking control, and the detection gaps.** Then clean up and
   verify.

---

## Commands

```bash
# 0. gates
zp-scope tier redteam || exit 9
zp-scope check dc01.corp.example

D=corp.example; DC=10.0.0.10; U='svc_engagement'; P='<engagement-provided>'

# 2. topology - trusts, direction, transitivity
ldapsearch -x -H "ldap://$DC" -D "$U@$D" -w "$P" -b "DC=corp,DC=example" \
  '(objectClass=trustedDomain)' trustPartner trustDirection trustType trustAttributes
netexec ldap "$DC" -u "$U" -p "$P" --trusted-for-delegation --password-not-required
netexec ldap "$DC" -u "$U" -p "$P" -M maq        # MachineAccountQuota - gates the RBCD path
netexec ldap "$DC" -u "$U" -p "$P" --pass-pol    # lockout threshold, before anything spray-like

# 3. graph collection, DC-only, no member-host contact
bloodhound-python -d "$D" -u "$U" -p "$P" -ns "$DC" -c DCOnly --zip -op zp-rt-

# 5a. Kerberoast - list first, request only what the path needs
GetUserSPNs.py "$D/$U:$P" -dc-ip "$DC"                      # enumerate, no tickets issued
GetUserSPNs.py "$D/$U:$P" -dc-ip "$DC" -request-user svc_sql \
  -outputfile artifacts/kerberoast.svc_sql.txt               # one account, named in the path

# 5b. AS-REP roast - only accounts already known to have preauth disabled
GetNPUsers.py "$D/" -usersfile users.preauth.txt -dc-ip "$DC" -no-pass \
  -format hashcat -outputfile artifacts/asrep.txt

# 5c. delegation - unconstrained, constrained, and constrained-with-protocol-transition
findDelegation.py "$D/$U:$P" -dc-ip "$DC"

# 5d. ADCS - enumerate vulnerable templates, do not request a certificate yet
certipy find -u "$U@$D" -p "$P" -dc-ip "$DC" -vulnerable -stdout

# 5e. DACL - read the ACE, do not write it
dacledit.py -action read -principal "$U" -target 'Domain Admins' -dc-ip "$DC" "$D/$U:$P"

# 6. relay surface - enumerate, do not relay. Never a CIDR: a /24 is 254 hosts none of which has
#    been through the host gate. Take the candidate list from the BloodHound collection or the
#    client inventory, funnel it through zp-scope, then ask only those hosts.
zp-scope filter < inventory.txt > hosts.inscope.txt
netexec smb hosts.inscope.txt --gen-relay-list artifacts/relay-candidates.txt
netexec ldap "$DC" -u "$U" -p "$P" -M ldap-checker   # LDAP signing / channel binding state
```

No-tool fallback, and the only step that needs no credential: an anonymous NTLM Type-1 to any
IIS/Exchange/SharePoint endpoint that offers `WWW-Authenticate: NTLM` returns a Type-2 whose
`AV_PAIR` block carries the NetBIOS domain and computer names, the DNS domain, the DNS **tree**
name (the forest root) and, where the server includes it, `MsvAvTimestamp`. The pairs come from the
host you asked - an IIS, Exchange or SharePoint server - so that timestamp is *that server's* clock,
not a DC's: never draw a Kerberos-skew conclusion from it. The domain and tree names are the forest
facts. One request is all it takes, because the Type-2 arrives in the `WWW-Authenticate` header of
the 401 that answers the Type-1. If that header is missing, suspect a load balancer or WAF stripping
it, and note that a few endpoints refuse `-I` (HEAD) - retry with `-X GET -o /dev/null -D -`:

```bash
curl -sk -I -H 'Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==' \
  "https://owa.$D/EWS/Exchange.asmx" | grep -i www-authenticate
```

Attack-path queries (BloodHound CE, Cypher). Run all three; the second is the one that matters:

```cypher
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.EXAMPLE"})) RETURN p
MATCH (n {owned:true}) MATCH p=shortestPath((n)-[*1..]->(m:Computer {domain:"CORP.EXAMPLE"}))
  WHERE m.unconstraineddelegation = true RETURN p
MATCH p=shortestPath((n {owned:true})-[*1..]->(o:GPO)) RETURN p
```

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| shortest path with every edge's required privilege named, and you hold the first one | **confirmed path.** Report it as the finding; walking it is optional |
| SPN on a user account with a crackable password | **confirmed** once the hash cracks offline. An uncracked hash is an exposure, not a path |
| SPN on a **machine** or **managed service account** | killed - 120-character random password, it will not crack |
| `DONT_REQ_PREAUTH` set | confirmed exposure; a path only if the AS-REP cracks |
| unconstrained delegation on a non-DC computer | **confirmed tier-0 path** - coercion plus TGT capture. Prove the flag, not the capture |
| constrained delegation with protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`) | confirmed - S4U2Self to any user against the listed SPN |
| RBCD writable but `MachineAccountQuota` is 0 and you control no computer object | **not a path yet.** Say what is missing |
| ADCS template with client-auth EKU, requester-supplied subject, no manager approval | **ESC1 confirmed** from the template ACL alone. Read it; do not enrol |
| CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` | **ESC6** - forest-wide. Confirmed from the CA config read |
| SMB signing not required on a host | relay *candidate*. Not a path until a coercion trigger and a valuable target both exist |
| LDAP signing off **and** channel binding off on a DC | **confirmed relay-to-LDAP path** to RBCD or DCSync rights |
| writable GPO linked to an OU containing tier-0 hosts | **confirmed** from the DACL and the `gPLink`. Do not modify the GPO |
| `GenericAll`/`WriteDACL` on a group or user | confirmed escalation edge; report the ACE, do not exercise it |
| `AdminCount=1` stale account, disabled | killed - no path through a disabled principal |
| a path that leaves the named scope, including a trusted forest not in the SoW | **stop.** Out of scope is out of scope even across a transitive trust |

---

## Least-invasive proof

**MANDATORY.** For every capability, the smallest action that proves it. Pick the row, not the row below it.

| Capability | Proof | Never |
|---|---|---|
| Domain Admin / tier-0 | a directory read only that group can do, e.g. reading a tier-0-only attribute, timestamped | create an account, add to a group, change a password |
| DCSync rights | the `DS-Replication-Get-Changes*` ACE read out of the domain DACL | replicate the hashes, ever - and never `krbtgt` |
| a single account's credential | one hash cracked offline from one requested ticket | roast every SPN in the domain |
| delegation abuse | the flag plus the `msDS-AllowedToDelegateTo` list | request the S4U ticket against a production service |
| RBCD | that you hold write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` | write the attribute on a tier-0 host |
| ADCS ESC1-ESC8 | template ACL, EKU, flags and CA config, read | enrol a certificate impersonating a real admin |
| NTLM relay | SMB/LDAP signing state plus a named coercion trigger plus a named target | relay into a production DC to plant RBCD |
| GPO abuse | GPO DACL plus `gPLink` plus the OU's tier-0 membership | add a scheduled task or startup script |
| local admin spread | one authenticated `--shares` listing, or a session enumeration | dump LSASS, touch SAM, or run a credential dumper |
| a trust path | trust direction, transitivity and SID-filtering state | forge a ticket across the trust |
| file-share access to sensitive data | a **count and a schema** - "14,220 rows, columns X, Y, SSN" | copy, download, or read the PII |

If the client explicitly asks for the loud version to test detection, get it in writing in the ROE,
agree the window and the target host with the technical contact, and log it as a scheduled test.

---

## Deconfliction

| What | How |
|---|---|
| operating source IPs | agreed and written down before the first LDAP bind, so defenders can separate you from a real intruder |
| naming convention | every object you create carries the engagement marker - `zp-rt-<ref>-01`, machine accounts `zp-rt-<ref>-01$`, files under `C:\zp-rt-<ref>\` |
| action log | timestamp, source IP, target host, exact command, expected event IDs. Written as you go, not reconstructed |
| noisy steps | Kerberoast requests, any coercion, any relay, any spray-adjacent action - tell the contact **before**, not after |
| lockout risk | check `--pass-pol` first; never spray without an agreed threshold and a per-account counter |
| blue-team question | when they ask "is this you?", answer within minutes from the action log, naming the alert |
| real intruder evidence | **stop immediately**, preserve, call the contact. This overrides every objective |

---

## Cleanup

Append to `.zeroprotocol/artifacts.md` the moment each is created, then walk the list in reverse and
verify each removal with a fresh read.

| Artifact this skill can create | Remove | Verify |
|---|---|---|
| computer account added under MachineAccountQuota | delete the account object | LDAP search returns no such object |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` written | clear the attribute back to empty | read the attribute; confirm empty, not "set to something harmless" |
| DACL / ACE added | `dacledit.py -action remove` with the same principal and target | `-action read` shows the original ACE set |
| issued certificate and private key | ask the CA operator to revoke; destroy the `.pfx` and any cached TGT | revocation confirmed in writing by the operator |
| Kerberos tickets in a `ccache` | shred the ccache files and unset `KRB5CCNAME` | no ccache on disk |
| cracked plaintext credentials | destroy the working set at engagement end; report names only, never plaintext | credential store deleted, confirmed to the client |
| BloodHound zip and LDAP dumps | contain full directory contents - treat as client-confidential, destroy or hand over encrypted | handover or deletion recorded |
| GPO edits, scheduled tasks, startup scripts | do not create them. If the ROE authorized one, revert and force replication | the GPO version number and content match the pre-test baseline |

An artifact you forgot is a backdoor you installed. The completed inventory is a deliverable.

---

## Pitfalls

- **Treating the bounty gate as sufficient.** `zp-scope tier redteam` is the gate here, not `zp-scope check` alone. Exit 9 means refuse.
- **Using a credential the engagement did not provide** - a password found in a share, a hash cracked from a third party's account, a cached token from a machine outside scope.
- **`DCSync` of `krbtgt`.** That is a golden-ticket capability and a credential you cannot hand back. The ACE read is the proof.
- **Dumping LSASS or SAM** on a production host. Out of proportion to any finding, and it is exactly the action the client's EDR should stop - let it.
- **Disabling or excluding EDR/AV** to get a tool running. Forbidden unless explicitly contracted; and a blocked tool is a *detection finding*, write it up.
- **Spraying without the lockout policy.** Locking out a production OU is a self-inflicted denial of service.
- **Crossing a transitive trust into a forest the SoW does not name.** The trust is not authorization.
- **Leaving a machine account, an ACE, an RBCD attribute or a certificate behind.** The certificate is the worst of these; it survives a password reset.
- **Reading PII off a share to demonstrate impact.** A count and a schema.
- **Reporting the trophy instead of the control.** The client buys the earliest-breaking control and the detection gaps.
- **Inventing tool flags.** If you are not sure a flag exists, describe the step and let the operator run it.

---

## Hand off to

Gate not cleared -> `zp-redteam-mode`, and say which of the six facts is missing.
Entra / M365 / federated identity reached from the on-prem forest -> stop at the on-prem boundary
and get the cloud tenant named in the SoW; cloud IAM blast radius -> `zp-cloud`.
Exposed AD-adjacent web surface (OWA, ADFS, SharePoint, ADCS web enrolment) found from outside ->
`zp-recon-active`, `zp-cve`, `zp-info-disclosure`.
Certificate or token validation flaws in an application -> `zp-jwt-oauth`.
A published CVE on a DC, CA or edge appliance -> `zp-cve`.
Findings that stand alone as ordinary vulnerabilities -> `zp-triage`, then `zp-report`, which owns
the attack narrative, the detection-gap section and the artifact inventory.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
