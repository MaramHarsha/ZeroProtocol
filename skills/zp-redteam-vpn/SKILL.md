---
name: zp-redteam-vpn
description: ZeroProtocol red-team skill for internet-facing VPN and remote-access appliances - vendor fingerprinting, the pre-auth CVE classes these products keep shipping, authentication and MFA enforcement gaps, session handling, split-tunnel and client-config disclosure, and the appliance-to-internal pivot. Use when a signed engagement names a VPN portal, an SSL-VPN gateway or remote access as the initial-access objective. Requires a signed engagement, not a bug bounty program page.
---

# zp-redteam-vpn - the front door everyone attacks and nobody patches twice

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse and say which of the six engagement facts is
missing (signed document · named scope · dates and hours · two named contacts · deconfliction
channel · agreed stop condition). `zp-scope check <host>` still applies to every individual host,
including every portal, every management interface and every secondary node in an HA pair.

This skill answers one question: **can an unauthenticated internet client become an authenticated
internal client here, and which control breaks that earliest?** The deliverable is that path -
fingerprint, the enforcement gap or CVE class that lets you through, what the tunnel actually
reaches once established, and what the defenders saw at each step. It is not a screenshot of an
internal host. These appliances are load-bearing production infrastructure and the single most
targeted class on the perimeter, so every step here uses the least invasive check that decides the
question, and detection-only before exploitation is the default, not the courtesy.

---

## Procedure

1. **Clear the tier gate, then the host gate.** `zp-scope tier redteam`; then `zp-scope check` on
   the portal, each HA member and any separately-named management interface. An appliance shared
   with a parent company or an MSP is not authorized by the client's SoW.
2. **Fingerprint the vendor passively, then with one request each.** Cookie name and portal path
   identify the product with near certainty and cost one `HEAD`. Do this before anything else,
   because the whole path depends on which product it is.
3. **Pin the version by behaviour, not by banner.** Vendors back-port fixes without bumping the
   string, and hardened builds strip it entirely. Record a stripped banner as a positive control.
4. **Hand the known-CVE work to `zp-cve`.** That skill owns KEV triage, template reading and the
   detection-half rule. This skill's job is to tell it *which* classes to look for on this vendor
   and to insist the detection half runs first. Do not duplicate the workflow here.
5. **Map the authentication surface** - local database, RADIUS, LDAP, SAML to an IdP - and the
   realm or tunnel-group structure. The AAA backend decides where the real weakness lives and
   which downstream skill owns it.
6. **Test MFA and policy *enforcement*, not MFA's existence.** The recurring finding is not a
   broken second factor; it is a realm, a group, a legacy client path or an API endpoint where the
   policy is simply not applied. Enumerate those paths; exercise one.
7. **Read what the portal discloses before auth** - client configuration, bookmark and resource
   lists, tunnel routes, internal hostnames, realm names. Unauthenticated config disclosure is a
   finding on its own and it is the map for step 8.
8. **Assess the pivot on paper first.** With an engagement-provided VPN credential, connect and
   enumerate what the tunnel *reaches* - routes, split-tunnel exclusions, whether the appliance
   itself is reachable from the tunnel. Reachability is the finding; exploitation of what you reach
   belongs to the next skill and needs the host in scope.
9. **Instrument the defence.** Ask the technical contact what the appliance forwarded to the SIEM
   for each step, and record expected-versus-alerted.
10. **Write the path, the earliest-breaking control and the detection gaps.** Then clean up and verify.

---

## Commands

```bash
# 0. gates
zp-scope tier redteam || exit 9
zp-scope check vpn.client.example

H=vpn.client.example

# 2. vendor fingerprint - one request per candidate, headers only
for p in '/+CSCOE+/logon.html' '/remote/login' '/vpn/index.html' \
         '/global-protect/login.esp' '/dana-na/auth/url_default/welcome.cgi' \
         '/cgi-bin/welcome' '/my.policy'; do
  printf '%-46s ' "$p"
  curl -skI --max-time 10 "https://$H$p" | tr -d '\r' | awk 'NR==1{c=$2} /^[Ss]et-[Cc]ookie/{k=$2} END{print c, k}'
done

# 3. TLS certificate - names, issuer and validity often identify the estate and the build age
openssl s_client -connect "$H:443" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 5. SAML service-provider metadata, where the vendor publishes it - anonymous, and it names the IdP
curl -sk --max-time 15 "https://$H/+CSCOE+/saml/sp/metadata" | head -40    # Cisco path
# Fortinet, Citrix and Ivanti publish SP metadata at vendor-specific paths - confirm the path from
# the vendor's current documentation rather than guessing, then fetch it the same way.

# 7. pre-auth disclosure - realm and portal responses, no credentials sent
curl -sk --max-time 10 "https://$H/" | grep -oiE 'realm|tunnel.?group|gateway|[a-z0-9-]+\.(corp|internal|local|ad)\b' | sort -u

# 8. what the tunnel reaches, using the engagement-provided client and credential only
ip route show ; ip -o addr show          # routes and address pushed by the appliance
getent hosts intranet.corp.example      # does the tunnel push internal DNS
nmap -sn -n --max-rate 20 10.10.0.0/24  # only ranges the SoW names, and only at an agreed pace
```

No-tool fallback: every fingerprint and disclosure step above is a single `curl`; if `curl` is
absent, `openssl s_client -connect` plus a hand-typed `GET / HTTP/1.1` and `Host:` header reads the
status line and cookie name, which is all step 2 needs.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| portal path plus cookie name identify the vendor | **fingerprinted.** Not yet a finding - it is the input to everything else |
| version banner in a known-vulnerable range | **lead only.** `zp-cve` confirms by behaviour or it is nothing |
| banner stripped, no version anywhere | **positive control.** Record it as defence that works, and keep going behaviourally |
| a vendor CVE's *detection* check fires | **confirmed exposure.** Report it now, at Critical if pre-auth; exploitation needs a separate written OK |
| a pre-auth RCE PoC exists for the confirmed build | do **not** run the weaponised half. Bricking a concentrator is a client outage, not a finding |
| DoS-class appliance CVE | **do not test.** Out of scope unless the engagement contracts for it in writing |
| one realm or group enforces MFA and another does not | **confirmed enforcement gap** - usually the highest-value finding on the box |
| a legacy or API authentication path that skips the MFA step | **confirmed bypass.** One engagement account, one login, then stop |
| MFA prompt appears and the factor is genuinely required | killed. "MFA is weak because push exists" is not a finding without a bypass |
| session cookie valid after logout, or portal session reusable from a second source IP | **confirmed session-handling flaw** -> `zp-session` |
| unauthenticated client configuration, bookmark or route list readable | **confirmed disclosure.** Internal hostnames and routes are the pivot map |
| split tunnel permits the client to reach the appliance's own management interface | **confirmed** - this is the appliance-to-internal escalation route |
| tunnel routes reach a range the SoW does not name | **stop.** A pushed route is not authorization |
| default credentials accepted | **confirmed, Critical**, and call the contact before you use the session |
| authentication failures distinguish valid from invalid users | enumeration exposure - real, but Low on its own; it is the input to a spray you are probably not authorized to run |
| the appliance belongs to an MSP or a parent company | **not in scope.** Back to `zp-scope`, and tell the client whose box it is |

---

## Least-invasive proof

**MANDATORY.** For each capability, the smallest action that decides it. Take the row, never the row below it.

| Capability | Proof | Never |
|---|---|---|
| vulnerable build present | the vendor's own detection signature, or a read-only behavioural difference | the file-write, memory-corruption or command-execution half of the exploit |
| pre-auth file read | one non-sensitive path fetched once, e.g. a vendor-shipped template | the session or credential store the same bug also reaches |
| memory-disclosure class | that the response is abnormally large or inconsistent | harvesting the leak until a live session token appears, then using it |
| valid credential accepted | one successful login with the **engagement-provided** account, timestamped | reusing any credential the appliance disclosed to you |
| MFA not enforced on a path | reaching the post-factor step once with the engagement account | scripting it, or running it against a real employee's account |
| user enumeration | the two differing responses for one known-good and one known-bad name | walking an employee list through the login form |
| administrative access | a read-only configuration or version view | changing a policy, adding an account, or saving config |
| internal reachability from the tunnel | a routing table plus one ICMP or one TCP connect per named range | scanning the estate, or authenticating to anything you reach |
| credentials stored in the appliance config | that the field exists and is populated | extracting, decrypting or reusing the LDAP bind or RADIUS secret |
| access to internal data through the tunnel | a **count and a schema** - "the share holds 14,220 rows, columns X, Y, SSN" | reading, copying or exporting the records |
| appliance logging and alerting | the technical contact's answer for each step, recorded | disabling logging, clearing logs, or tampering with the SIEM forwarder |

If the client wants the loud version to exercise detection, get it in the ROE in writing, agree the
window and the exact host with the technical contact, and log it as a scheduled test.

---

## Deconfliction

| What | How |
|---|---|
| operating source IPs | agreed and written down before the first request, because this appliance's logs are the client's earliest intrusion signal |
| pace | patient and jittered. Every request here is likely SIEM-forwarded, and the box is production |
| naming convention | any account, bookmark, uploaded file or profile carries the engagement marker - `zp-rt-<ref>-01` |
| action log | timestamp, source IP, URL or client action, exact command, and what you expected the appliance to log |
| before any CVE check | tell the contact which appliance and which check. A vendor exploit against an edge box is the alert defenders take most seriously |
| before any authentication attempt | agree the account, the attempt count and the lockout threshold. Locking the VPN realm is a self-inflicted outage |
| mid-engagement patching | if the appliance updates or an IPS rule appears while you test, that is a **second finding** - record the before and after |
| blue-team question | answer "is this you?" within minutes from the action log, naming their alert |
| real intruder evidence | these appliances are mass-exploited - webshells and unfamiliar sessions are a live-compromise signal. **Stop, preserve, call the contact.** This overrides every objective |

---

## Cleanup

Append to `.zeroprotocol/artifacts.md` the moment each is created, then walk the list in reverse and
verify every removal with a fresh read.

| Artifact this skill can create | Remove | Verify |
|---|---|---|
| authenticated portal and tunnel sessions | log out, then have the operator terminate the session server-side | the session list shows none for the engagement account |
| a file written by a detection check on a traversal or injection class | ask the operator to delete it by path; it usually sits outside the web root | operator confirms the path is gone, in writing |
| an engagement account, realm, group or bookmark created by the client for you | client disables and deletes it at engagement end | the login is refused afterwards, and you confirm the deletion |
| downloaded client configuration, profiles or bookmark lists | these contain internal routes and hostnames - client-confidential. Destroy or hand over encrypted | handover or deletion recorded |
| captured session tokens or cookies | shred the working files, clear the browser profile and any proxy history | no token on disk, proxy corpus purged |
| credentials the engagement provided | destroyed at engagement end, never retained. Report account names, never secrets | credential store deleted, confirmed to the client |
| local VPN client profiles and cached certificates | remove the profile and any client certificate from the keychain or store | client no longer offers the connection |
| proxy or capture files containing portal traffic | encrypt for handover or destroy | recorded in the inventory |

An artifact you forgot is a backdoor on the client's perimeter. The completed inventory is a deliverable.

---

## Pitfalls

- **Treating the bounty gate as sufficient.** `zp-scope tier redteam` is the gate here, and exit 9 means refuse and name the missing fact.
- **Running the weaponised half of an appliance exploit.** These boxes crash, and a failed VPN concentrator is every remote employee offline. Detection half, then written permission.
- **Testing DoS-class CVEs** on the one device the workforce depends on.
- **Concluding "patched" from one 404.** Patch deployment is uneven across HA pairs and virtual servers. Check several classes, and check both nodes.
- **Trusting the version banner.** Silent back-ports are routine on this class.
- **Spraying or brute-forcing the portal.** Lockout on a VPN realm is a denial of service you caused, and password spraying real employee accounts is not authorized by a technical SoW.
- **Using credentials the appliance disclosed to you** - a leaked session file, an LDAP bind out of the config, a token from a memory leak. Enumerate them, report them, do not authenticate with them.
- **Following a pushed route out of scope.** The appliance's routing table is not a scope document.
- **Treating the tunnel as a licence to hunt.** Everything past the tunnel needs its own `zp-scope check` and its own skill.
- **Disabling EDR or the appliance's own logging** to make a step work. A blocked step is a detection finding - write it up.
- **Reading PII off an internal share to show impact.** A count and a schema.
- **Leaving a session, a written file or an account behind**, or retaining the engagement credential afterwards.
- **Reporting the trophy instead of the control.** The client buys the earliest-breaking control and the detection gaps - "the appliance forwarded the event and no alert fired" is frequently worth more to them than one more pivot.
- **Inventing tool or vendor paths.** If you are not certain a path or flag exists on this build, describe the step and let the operator confirm it from current vendor documentation.

---

## Hand off to

Gate not cleared -> `zp-redteam-mode`, and say which of the six engagement facts is missing.
Known-CVE confirmation, KEV triage and template discipline -> `zp-cve` (this skill deliberately
does not duplicate it). External surface and the rest of the perimeter -> `zp-recon-active`,
`zp-info-disclosure`.
SAML, OIDC, token and MFA-bypass mechanics behind the portal -> `zp-jwt-oauth`; session lifetime,
logout and fixation -> `zp-session`.
AAA backed by an on-prem forest -> `zp-redteam-ad`; backed by Entra or a federated tenant ->
`zp-redteam-entra`, with the tenant named in the SoW first.
Cloud-hosted appliance, its instance role or an exposed management plane -> `zp-cloud`.
Findings that stand alone as ordinary vulnerabilities -> `zp-triage`, then `zp-report`, which owns
the attack narrative, the detection-gap section and the artifact inventory.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
