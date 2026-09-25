---
name: zp-redteam-vcenter
description: ZeroProtocol red-team skill for the virtualisation layer - vCenter and ESXi exposure and fingerprinting, the pre-auth CVE classes these appliances keep shipping, SSO and SAML token handling, vmdir and identity-source enumeration, guest-operations and VM-to-host reach, datastore browsing, and snapshot and backup exposure. Use when a signed engagement names vCenter, ESXi or the hypervisor estate as a target or as the crown jewel. Requires a signed engagement, not a bug bounty program page.
---

# zp-redteam-vcenter - the layer every other layer sits on

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse and say which of the six engagement facts is
missing (signed document · named scope · dates and hours · two named contacts · deconfliction
channel · agreed stop condition). `zp-scope check <host>` still applies to every individual host -
the vCenter appliance, each ESXi host, the management interface on 5480, and every replication,
backup or identity node you touch.

This skill answers one question: **who can reach the virtualisation management plane, what would
that let them do to the estate, and which control breaks the path earliest?** The deliverable is
that path plus the detection gaps, not a trophy. Treat this as **tier-0-equivalent** - whoever
controls the hypervisor controls every domain controller, database and backup running on it - so the
standing rule here is stricter than anywhere else in ZeroProtocol: **capability is proven by a
read-only inventory call, never by a VM operation.** No power changes, no snapshots, no consoles, no
guest processes, no datastore writes, nothing that touches a running workload.

---

## Procedure

1. **Clear the tier gate, then the host gate.** `zp-scope tier redteam`, then `zp-scope check` per
   host. A cluster shared with a parent company, an MSP or a co-located tenant is not authorized by
   the client's SoW even when it answers on their address space.
2. **Establish where the management plane is exposed from**, recording the segment each answer came
   from. The exposure is frequently the finding - a management plane reachable from a user VLAN, a
   guest network or the internet is worth more than anything you do next.
3. **Fingerprint the product and pin the build by behaviour**, one request per candidate path, and
   record a stripped banner as a positive control rather than a dead end.
4. **Hand every known-CVE question to `zp-cve`.** It owns KEV triage, template reading and the
   detection-half-only rule. This skill names *which* classes matter here and insists nothing
   weaponised runs against a hypervisor.
5. **Map the SSO and identity surface** - SSO domain, configured identity sources, federation to an
   external IdP, and whether ESXi hosts are joined to Active Directory. This decides which
   downstream skill owns the real weakness.
6. **Enumerate the permission model** with the engagement-provided credential - roles, global
   permissions, and who holds propagating privilege at the datacenter or folder level.
   Over-permissioned service accounts are the recurring finding on this estate.
7. **Enumerate reach, do not exercise it.** That the credential *holds* Guest Operations, datastore
   browse, snapshot or host-configuration privilege is the finding. Invoking any of them is not.
8. **Assess datastore, snapshot and backup exposure on paper.** A readable datastore reaches every
   guest disk and memory snapshot - credential material for the whole estate - and backup systems
   hold standing vCenter credentials plus a second copy of every VM. Name them, list one directory,
   authenticate to nothing.
9. **Instrument the defence** - ask the contact what vCenter, the hosts and the SIEM recorded per
   step, and whether anything alerted. Then write the path, the earliest-breaking control and the
   detection gaps, clean up and verify.

---

## CVE classes that matter here - confirmation belongs to `zp-cve`

| Class | Why it is on this list | Discipline |
|---|---|---|
| vCenter plugin and service pre-auth file upload / RCE (the 2021 wave - CVE-2021-21972, CVE-2021-21985, CVE-2021-22005) and DCE/RPC pre-auth memory corruption (CVE-2023-34048) | default-enabled components, mass-exploited, still present on stale appliances; the RPC bug was a long-lived state-actor zero-day | detection half only. These PoCs write files and leave webshells, and a crashed `vmdird` is a client outage |
| Identity-manager and automation SSTI and auth bypass (CVE-2022-22954, CVE-2022-22972, CVE-2022-31656) | pre-auth, single request, KEV-listed, reaches the SSO estate | detection half; treat the identity plane as tier-0 too |
| ESXi Active Directory group-trust bypass (CVE-2024-37085) | turns any AD foothold into hypervisor root; ransomware operators' preferred route | **enumerate only.** Proving it means creating an AD group - that is a change, and it is forbidden here |
| ESXi legacy discovery-service memory corruption (CVE-2019-5544, CVE-2020-3992, CVE-2021-21974) | the ESXiArgs mass-encryption vector | check whether the service is enabled at all. Never send a crafted frame to a hypervisor |
| Aria / Operations for Networks pre-auth command injection (CVE-2023-20887) | management-adjacent appliance holding credentials into vCenter | detection half, and scope the appliance separately |

Stated plainly for the client: this family's critical bugs are **pre-auth, network-reachable and
mass-exploited within days of the advisory**. Reachability of the management plane is the finding;
the patch level is the aggravating factor.

---

## Commands

```bash
# 0. gates
zp-scope tier redteam || exit 9
zp-scope check vcenter.client.example

H=vcenter.client.example

# 2/3. product and build fingerprint - read-only, one request each, no credentials
curl -sk --max-time 10 "https://$H/sdk/vimServiceVersions.xml"          # API generations offered
curl -skI --max-time 10 "https://$H/ui/login" | tr -d '\r' | head -5    # UI presence
curl -sk -o /dev/null -w 'appliance api %{http_code}\n' "https://$H/api/appliance/system/version"
# 401 here is itself a fingerprint - the modern REST plane is present and does require auth.

# TLS names, issuer and validity - identifies the estate and hints at build age
openssl s_client -connect "$H:443" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 2. which management surfaces answer, and from which segment you are standing in
for p in 443 5480 636; do
  printf 'tcp/%-5s ' "$p"; timeout 5 bash -c "echo >/dev/tcp/$H/$p" 2>/dev/null && echo open || echo closed
done

# 5. SSO surface - anonymous, and it names the SSO domain and the federating IdP
curl -sk --max-time 15 "https://$H/websso/SAML2/Metadata/vsphere.local" | head -40
ldapsearch -x -LLL -H "ldap://$H:389" -s base -b "" '(objectClass=*)' 2>&1 | head -20
curl -skI --max-time 10 "https://$H/mob" | tr -d '\r' | head -3   # MOB: 401 is correct, 200 is a finding

# 6/7. authenticated read-only inventory, engagement-provided credential ONLY
export GOVC_URL="https://$H" GOVC_USERNAME='<engagement account>' GOVC_INSECURE=1
read -rs GOVC_PASSWORD; export GOVC_PASSWORD      # never on the command line or in shell history
govc about                             # build, exactly, as the API reports it
govc ls -l /                           # datacenter and folder topology
govc find / -type h                    # hosts - the inventory call that proves access
govc permissions.ls -a /               # who holds what, propagating
govc role.ls                           # role definitions, including custom roles
govc session.ls                        # who else is logged in, and from where
govc datastore.info                    # names and capacity - metadata, not contents
govc datastore.ls -l '[datastore1] .'  # ONE top-level listing. No recursion, no download
govc find / -type m -name '*backup*'   # 8. name the backup estate; authenticate to none of it
```

No-tool fallback: without `govc`, the same read-only inventory comes from a `/api/session` token plus
`GET /api/vcenter/host`, `/api/vcenter/datastore` and `/api/vcenter/vm`; without `curl`,
`openssl s_client` and a hand-typed `GET` cover the whole unauthenticated fingerprint.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| management plane answers from a user VLAN, guest network or the internet | **confirmed, and usually the headline finding.** Segmentation, not patching, is the control |
| version banner in a known-vulnerable range | **lead only.** `zp-cve` confirms by behaviour, or it is nothing. A stripped banner is a positive control - record it |
| a vendor detection check fires for a pre-auth class | **confirmed exposure, Critical.** Report the same hour. Exploitation needs separate written sign-off you should not seek on a hypervisor |
| MOB or any inventory surface answers without credentials | **confirmed.** Full topology disclosure - hosts, VMs, datastores, sessions |
| anonymous LDAP bind returns directory data | **confirmed disclosure** of the SSO domain structure |
| a session list shows unfamiliar logins, or unexpected snapshots exist | possible **live compromise.** Stop, preserve, call the contact |
| ESXi hosts joined to AD, admin rights granted by group name | **confirmed trust path** - an AD foothold becomes hypervisor root. Enumerate the group and stop |
| an account holds propagating administrator at the datacenter root | **confirmed over-permission.** A `permissions.ls` output is the whole proof |
| a service account (backup, monitoring, automation) holds Guest Operations or host configuration | **confirmed** - the real crown-jewel path on most estates. The privilege is the proof; running anything in a guest is not |
| datastore browse privilege present | **confirmed reach to every guest disk and snapshot** - including retained snapshots of domain controllers, and any `.vmsn`/`.vmem` memory snapshot, which is a credential-exposure path. That the files exist is the finding. One listing, then stop |
| backup system holds standing vCenter administrator credentials | **confirmed design weakness.** Name the account; do not authenticate to the backup system |
| the cluster belongs to an MSP, a parent company or a co-tenant | **not in scope.** Back to `zp-scope`, and tell the client whose estate it is |

---

## Least-invasive proof

**MANDATORY.** Take the row, never the row below it - here the row below it is often a production incident.

| Capability | Proof | Never |
|---|---|---|
| vulnerable build present | the vendor's own detection signature, or a read-only behavioural difference | the file-write, memory-corruption or command-execution half - hypervisor crashes are client outages |
| hypervisor / vCenter access | **a read-only inventory call** - `govc about`, `govc find / -type h` | powering, cloning, migrating, reconfiguring or consoling any VM |
| administrative rights on the estate, incl. the ESXi AD trust weakness | `permissions.ls` and `role.ls` output, or the privileged group's name, members and the host's join state | creating a role, user, permission, local ESXi account - or that group. Creating it grants real access and is forbidden |
| guest-operations reach | the privilege present on the role, named | starting a process, transferring a file or reading a guest filesystem |
| datastore and backup exposure | one top-level directory listing; the backup system named with the vCenter account it uses | recursing the datastore, downloading any `.vmdk`/`.vmsn`/`.vmem`/`.nvram`, authenticating to the backup system, mounting or restoring anything |
| access to data inside a guest | a **count and a schema** from the owner, or the disk's existence | mounting a guest disk, or reading customer or employee records |
| credentials stored in vCenter or host config | that the field exists and is populated | extracting, decrypting or reusing an identity-source bind or host password |
| logging and alerting coverage | the technical contact's answer per step, recorded | disabling vCenter logging, clearing task and event history, or touching the syslog forwarder |

**Detection gaps are first-class findings.** "vCenter forwarded the privileged-session event, the
SIEM ingested it, and no alert fired" is routinely worth more to this client than one more
escalation path - because the hypervisor is where they have exactly one chance to notice.

---

## Deconfliction

| What | How |
|---|---|
| operating source IPs and the segment each test ran from | agreed in writing first - on this estate *where you stood* is half the finding - and worked at a patient pace, because vCenter task and event logs are the client's earliest hypervisor-intrusion signal |
| before any authenticated session or CVE detection check | tell the contact the account, the host, the check and the attempt count against the lockout threshold. A privileged vCenter login and an exploit signature against a hypervisor are the two alerts defenders take most seriously |
| mid-engagement patching or hardening | if the appliance updates or a rule appears while you test, that is a **second finding** - record before and after |
| action log, and the blue-team question | timestamp, source IP, account, exact command and what you expected vCenter to record - kept so you can answer "is this you?" within minutes, naming their alert |
| anything that would change estate state | stop and call the contact. There is no step in this skill that requires it |
| real intruder evidence - unfamiliar sessions, unexpected snapshots, unknown VMs, disabled logging | **stop, preserve, call the contact.** This overrides every objective, and on the hypervisor it is the one signal that cannot wait |

---

## Cleanup

Append to `.zeroprotocol/artifacts.md` the moment each is created, then walk the list in reverse and
verify every removal with a fresh read. This skill is designed to create almost nothing - if your
inventory has entries beyond sessions and local files, you went further than the skill sanctions.

| Artifact this skill can create | Remove | Verify |
|---|---|---|
| authenticated vCenter / ESXi / REST API sessions, and any token in a shell variable or history | log out, have the operator terminate them server-side, unset the variable and shred the history | `govc session.ls` shows none for the engagement account, and no token remains on disk |
| downloaded inventory, permission, topology and identity-metadata output | client-confidential - it maps the whole estate and names the IdP. Encrypt for handover or destroy | handover or destruction recorded |
| a file written by a CVE detection check, or an account, role or permission the client created for you | operator deletes the file by path and notes it as a detection artifact; client disables and deletes the account at engagement end | the path is gone and the login is refused afterwards, both confirmed in writing |
| credentials the engagement provided, and any capture file of management-plane traffic | destroyed at engagement end, never retained - report account names, never secrets | credential store and captures deleted, confirmed to the client |

An artifact you forgot on the virtualisation layer is a backdoor into every system the client runs.
The completed inventory is a deliverable.

---

## Pitfalls

- **Treating the bounty gate as sufficient.** `zp-scope tier redteam` is the gate here; exit 9 means refuse and name the missing engagement fact.
- **Any VM operation as proof.** Power, clone, migrate, reconfigure, console, snapshot, revert - none are proof, and all are production changes on systems you cannot see inside. Taking a snapshot "to be safe" is the most common self-inflicted outage here: chains grow, fill datastores and stall clusters.
- **Running the weaponised half of a vCenter or ESXi exploit**, or testing a DoS-class CVE. A crashed hypervisor takes every VM on it down, including the ones the client did not tell you about.
- **Downloading a memory snapshot or a guest disk, or reading PII out of a guest** to show impact. The file's existence is the finding; a count and a schema from the owner is the rest.
- **Spraying SSO.** Lockout thresholds are low, and password spraying real staff accounts is not authorized by a technical SoW.
- **Using credentials the estate disclosed to you** - out of a host config, an identity-source bind, a guest customisation spec, a backup job, an unattended file on a datastore. Enumerate them, report them, do not authenticate with them.
- **Following the estate out of scope.** vCenter sees hosts, VMs and networks the SoW never named, including other tenants - inventory visibility is not authorization.
- **Disabling logging, clearing task and event history, or touching EDR** to make a step work - a blocked or logged step is a *finding*, so write it up - or **leaving persistence** behind: a role, a permission, a local host account, an enabled shell service, an uploaded file, a live session, or the engagement credential retained afterwards.
- **Reporting the trophy instead of the control.** The client buys the earliest-breaking control - usually management-plane segmentation, then least-privilege on service accounts, then patch currency - and the detection gaps alongside it.

---

## Hand off to

Gate not cleared -> `zp-redteam-mode`, and say which of the six engagement facts is missing.
Known-CVE confirmation, KEV triage and the detection-half rule -> `zp-cve` (this skill deliberately
does not duplicate it).
Exposure of the management plane from outside -> `zp-recon-active`, `zp-info-disclosure`. SAML, OIDC
and token mechanics behind the SSO surface -> `zp-jwt-oauth`; session lifetime -> `zp-session`.
Identity sources backed by an on-prem forest -> `zp-redteam-ad`; federated to a tenant ->
`zp-redteam-entra`, with the tenant named in the SoW first. Reached through a remote-access
appliance -> `zp-redteam-vpn`. Cloud-hosted virtualisation, an exposed orchestration plane or
object storage holding backups -> `zp-cloud`.
Findings that stand alone -> `zp-triage`, then `zp-report`, which owns the attack narrative, the
detection-gap section and the artifact inventory.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
