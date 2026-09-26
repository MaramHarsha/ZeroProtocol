---
name: zp-redteam-supplychain
description: ZeroProtocol red-team skill for supply chain and third-party reconnaissance under a signed engagement - vendor and SaaS inventory from DNS, SSO and egress signals, shared CI and artifact infrastructure, package namespace and dependency-confusion exposure, code-signing and release provenance, and managed provider access paths. Use when an engagement asks which supplier a real intruder would arrive through. Mapping only - never touch a supplier. Requires a signed engagement, not a bounty page.
---

# zp-redteam-supplychain - the way in that your client does not run

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse and say which of the six engagement facts is
missing (signed document, named scope, dates, two contacts, deconfliction channel, stop condition).
`zp-scope check <host>` still applies to every individual host, org, tenant and registry you read,
and the plain bounty check is **not** a substitute for the tier gate.

This skill answers one question - **which third party could deliver code, an identity or a command
into the client's estate, and which single control breaks that delivery?** The deliverable is a
path drawn hop by hop from a supplier to the client's production, the earliest control that severs
it, and what the client's own telemetry recorded while you mapped it. **Hard boundary - this is
reconnaissance and exposure mapping only.** The engagement authorises the client, not the client's
suppliers. A supplier exposure you find is something you tell the client about; it is never
something you probe.

---

## Procedure

1. **Clear the tier gate** - the six engagement facts go into `.zeroprotocol/scope.yaml` by key
   name (`authorization_ref`, `contact_technical`, `contact_stop`, `window`, `deconfliction`,
   `stop_condition`), which is what `zp-scope tier redteam` reads. Then list the client-owned
   sources you may read - DNS zones, IdP tenant, source orgs, CI, artifact registries, and any log
   export the client hands you. Everything else is a third party until the scope names it.
2. **Build the supplier inventory from client-side signals only** - SPF and DMARC records, MX and
   CNAME targets, SSO application lists, OAuth consent grants, and top external destinations in
   proxy or DNS logs the client exported for you. Never authenticate to a vendor to enumerate it.
3. **Classify each supplier by what it can deliver** - code into a build, an identity into the
   directory, a command into production, or data out. A supplier that can only receive data is a
   different finding from one that can push code.
4. **Map the build and artifact plane** - who may trigger a build, which third-party actions and
   images the client consumes, whether references are pinned, which runners are shared, and which
   secrets each job can read. Secret *names* only, never values.
5. **Check namespace exposure** for every internal package name that appears in a client lockfile,
   bundle or manifest - is the name unclaimed on the public index, and does the client's resolver
   config route that scope to the internal registry.
6. **Verify release provenance** on the artifacts the client itself installs or auto-updates from -
   signature, attestation, and whether verification is actually enforced on the consuming side.
7. **Trace managed service provider and partner access** - delegated admin relationships, guest
   identities, cross-account trusts naming a vendor account, standing vendor accounts in the
   directory, and vendor jump hosts or site-to-site links.
8. **Ask what fired** at each step - did the CI audit log, registry pull log or directory audit
   record your reads, and did an alert reach a human.
9. **Write the path, remove every artifact, verify each removal**, hand over the inventory.

---

## Commands

**Supplier inventory from the client's own records**

```bash
D=client.com
dig +short TXT "$D" | tr ' ' '\n' | grep -E '^include:|^ip4:|^ip6:'     # email and marketing vendors
dig +short TXT "_dmarc.$D"                                              # rua/ruf report processors
dig +short MX "$D"
for s in sso idp vpn mail status support docs help pay; do
  printf '%-10s %s\n' "$s" "$(dig +short CNAME "$s.$D")"
done
awk -F'\t' '{print $NF}' client-dns-export.tsv | sort | uniq -c | sort -rn | head -50   # client export
```

**SSO and consent - the client's own tenant, read-only**

```bash
curl -s -H "Authorization: SSWS $OKTA_TOKEN" "https://$ORG.okta.com/api/v1/apps?limit=200" | jq -r '.[].label'
az ad sp list --all --query "[].{name:displayName,appId:appId,home:appOwnerOrganizationId}" -o table
az rest -m get -u "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
  | jq -r '.value[] | [.clientId, .consentType, .scope] | @tsv'
az ad user list --filter "userType eq 'Guest'" --query "[].{upn:userPrincipalName,name:displayName}" -o table
az rest -m get -u "https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships"
```

**Build and artifact plane**

```bash
gh api "orgs/$ORG/actions/permissions"                                  # who may run which actions
gh api "orgs/$ORG/actions/runners" --jq '.runners[] | [.name,.status] | @tsv'
gh api "orgs/$ORG/actions/secrets" --jq '.secrets[].name'               # names only
grep -rhoE 'uses: *[^ ]+/[^ ]+@[^ ]+' .github/workflows/ | grep -vE '@[0-9a-f]{40}' | sort -u
grep -rhoE '^ *(FROM|image:) *[^ ]+' . | grep -v '@sha256:' | sort -u
aws organizations list-delegated-administrators --output table
```

**Namespace exposure - a public index lookup, never a publish**

```bash
grep -rhoE '"@[a-z0-9-]+/[a-z0-9._-]+"' package-lock.json | tr -d '"' | sort -u > pkgs.txt
while read -r pkg; do
  printf '%-40s %s\n' "$pkg" "$(curl -s -o /dev/null -w '%{http_code}' "https://registry.npmjs.org/$pkg")"
done < pkgs.txt        # a 404 here means only "not published at that path"
# For a scoped package the publishable unit is the SCOPE, not the package path. npm answers 404 for
# @scope/name both when the scope is unregistered and when the scope exists but belongs to another
# user or org - and in the second case nobody else can claim the name, so there is no confusion path.
# Resolve the scope before you grade anything:
sed -E 's:(@[a-z0-9-]+)/.*:\1:' pkgs.txt | sort -u > scopes.txt
while read -r s; do
  printf '%-20s %s\n' "$s" "$(curl -s -o /dev/null -w '%{http_code}' "https://registry.npmjs.org/-/org/${s#@}/package")"
done < scopes.txt      # a lead, not a verdict: this path is auth-sensitive, so corroborate ownership
                       # from the scope's public org/user page before calling the scope unregistered
grep -rE '^@[a-z0-9-]+:registry=|^registry=' .npmrc                    # scope-to-registry mapping
# Unscoped internal names have no scope layer - there the package-path 404 is the right check.
```

**Provenance on what the client consumes**

```bash
gh attestation verify ./client-agent.tar.gz --owner "$ORG"
cosign verify "ghcr.io/$ORG/service:1.4.2" --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation "ghcr.io/$ORG/service:1.4.2" --type slsaprovenance \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

No tooling - read the manifests. An unpinned reference, an absent `@sha256:`, a missing
`integrity` field and a missing scope mapping are all visible in text and prove the same thing.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| internal scope in a lockfile the CI installs, the **scope itself** unregistered on the public index (not merely a 404 on the package path), and no scope-to-registry mapping in the client's resolver config | **confirmed dependency-confusion exposure.** Three facts, all read from the client's side. Never publish the name |
| the package path 404s but the scope is registered to another user or org | killed - the name is not claimable by anyone else, so there is no confusion path. Informational at most |
| the name is unclaimed but `.npmrc` maps the scope to the internal registry | killed - the control is working. Recommend defensive registration as hygiene |
| third-party action or base image on a mutable tag, in a job that can read org secrets or runs on a shared runner | **confirmed code-delivery path.** The workflow text and the secret names are the proof |
| self-hosted runner reachable from a repo outsiders can open a PR against | **confirmed pivot** from configuration. Do not run a job on it |
| the client auto-updates from a channel whose artifacts carry no signature or attestation | **confirmed.** Name the channel and the consuming host class |
| artifacts are signed but the consumer never verifies | **confirmed** - an unenforced signature is decoration. Show the consuming config |
| delegated admin relationship or vendor account holding standing privileged access | **confirmed MSP path.** Time-bound, approved, just-in-time access is the control - if it is there, killed |
| guest or partner identity from a supplier tenant in a privileged group | **confirmed.** Directory read only |
| a CNAME to a decommissioned vendor host | **confirmed dangling record** by resolution and the vendor's own error signature. Registering the name would be touching the vendor platform - report it, hand it to the client to claim |
| a supplier of the client turns out to be exposed or already compromised | **stop.** Tell the client and the engagement contact. Not yours to probe, confirm or exploit |
| a vendor with a poor security page or a bad scorecard | not a finding. No delivery path, no report |
| every read you made appears in the audit log and no alert fired | **finding in its own right** - see deconfliction |

---

## Least-invasive proof

**Every capability below is proven by a read of the client's own configuration.**

| Capability | Smallest action that proves it | Never |
|---|---|---|
| namespace takeover reach | a `404` from the public index plus the client's resolver config | publish a package, reserve a name, upload an empty placeholder |
| CI code execution via a mutable reference | the workflow or Dockerfile line plus the secret names that job can read | push a branch, open a PR, trigger a run, replace an action |
| self-hosted runner pivot | runner labels and repository permission from the org API | queue a job, shell onto the runner, touch its filesystem |
| artifact registry write | the token scope or registry ACL from configuration | push an image, move a tag, overwrite a layer |
| code-signing key reach | the job definition that can read the key, plus the key's ACL | sign anything, export the key, mint a certificate |
| release-channel poisoning | one unsigned artifact plus the auto-update configuration that consumes it | upload, replace or modify any published artifact |
| MSP administrative access | the delegated-admin record or the role assignment | authenticate as the provider, use their path, log into their portal |
| supplier account in the directory | the account's group memberships from a directory read | spray, authenticate, reset a password, or enable a disabled account |
| dangling vendor DNS record | the resolution plus the vendor's documented error response | register the name on the vendor platform |

Domain admin is proven by a directory read, hypervisor access by a read-only inventory call, and a
supply-chain path by the manifest that would fetch the attacker's code - never by fetching it.

---

## Deconfliction

| What | How |
|---|---|
| source IPs | fixed, in the engagement file, handed to the SOC, the platform team and whoever watches the CI before step 4 |
| naming | any object the ROE lets you create carries the engagement reference - `zp-<ref>-<n>` - and never a plausible vendor or business name. A supply-chain artifact with a credible name is indistinguishable from a real attack |
| logging | append-only JSONL per action - UTC timestamp, source, API or index queried, object, result. Record a secret's name and never a character of its value |
| artifacts | every created or changed object goes into `.zeroprotocol/artifacts.md` at the moment of creation, before you continue |
| call the contact | before any action that would reach a supplier system; before running or triggering any build; before opening a pull request against a client repo; when a live supplier credential appears in client data; when a supplier looks already compromised; on any sign of a real intruder |
| answer speed | the client must get an answer within minutes on whether a given registry pull, workflow run or admin login in their logs was you |

**Detection gaps are first-class findings.** Pull the client's own trail for your reads - GitHub org
audit log, registry pull log, directory sign-in and audit logs - and ask whether an alert reached
anyone. "Your registry logged a pull of an internal package name from an external resolver and
nobody was paged" is often worth more than a second delivery path, and it is the half of the report
only a red team can write.

---

## Cleanup

| Artifact this skill can create | Removal | Verification |
|---|---|---|
| cloned client repositories, exported manifests, lockfiles and SBOM copies | destroy the working set on completion, keep only redacted report excerpts | the working directory is gone and no live secret or customer record is in the report |
| pulled container images and extracted layers | `docker rmi` each tag and delete the extraction directory | `docker images` lists none of them; the extraction path is absent |
| local credential material - `gh auth`, `az login`, `npm` and registry tokens, cosign keys | log out of every CLI, remove the token from the config, destroy any key you generated | `gh auth status`, `az account show` and `npm whoami` all fail |
| a test branch, workflow file or pull request the ROE explicitly permitted | delete the branch, close the PR, revert the file from your snapshot | a diff against the snapshot is empty and the branch is absent on the remote |
| any registry name the client asked you to reserve defensively | transfer ownership to the client before the window closes | the client is sole owner and you hold no publish rights |

Snapshot any file before you touch it, so cleanup is a diff and not a memory exercise. Then walk
`.zeroprotocol/artifacts.md` in reverse, verify each line, and hand the inventory over. A package
name you reserved and forgot, or a workflow file you left behind, is a supply-chain backdoor you
installed.

---

## Pitfalls

- **Running this off a bounty scope.** `zp-scope check` returning 0 is not the tier gate; `zp-scope tier redteam` is.
- **Touching a supplier.** Probing a vendor's portal, VPN, artifact server, internal Nexus or SaaS platform is unauthorized access to a company that did not sign your engagement - no matter what it would prove about your client.
- **Publishing anything to a public registry.** A dependency-confusion or typosquat package reaches every consumer of that index, not just your client. It is outside any engagement scope and illegal in most jurisdictions without the ecosystem's authorization.
- **Opening a pull request against a client repository** to demonstrate workflow injection without that specific step in writing. It executes code on their CI and involves developers who did not consent.
- **Using a supplier credential found in client data.** A vendor token in a log or lockfile is a retrievability finding that stops at reporting - authenticating with it crosses into the vendor's estate.
- **Confusing an unclaimed name with an exploitable one.** Without the resolver-config fact - and, on a scoped package, without the scope itself being unregistered - it is informational, and calling it Critical costs you credibility on the findings that are real.
- **Enumerating a public index at scan speed**, or pulling multi-gigabyte images blindly - hammering a shared registry is a denial-of-service risk against infrastructure everyone depends on.
- **Weakening a control to prove the point** - disabling branch protection, dependency review, required signing or an EDR agent on a build host. Forbidden here, and it destroys the detection half of the report.
- **Leaving persistence in the build plane** - a workflow file, deploy key, runner registration token, PAT, registry credential or reserved package name. This is the tier's one unforgivable outcome, because everything in the build plane ships.
- **Exfiltrating a supplier's or the client's PII** to show blast radius, or retaining an export after the window closes - a count and a redacted schema prove reach, and any note holding PII is destroyed with the working set.
- **Social engineering a vendor's support desk or the client's staff** - a separate authorization that a technical SoW never implies.

---

## Hand off to

Tier gate and engagement facts -> `zp-redteam-mode`. Per-host and per-org scope decisions ->
`zp-scope`. Secrets and internal package names in repositories, bundles and mobile builds ->
`zp-code-audit`, `zp-js-secrets`, `zp-mobile`. External registry, bucket and orchestration exposure
under the no-credential rules -> `zp-cloud`. Cloud trust edges and CI federation reached from a
supplier -> `zp-redteam-iam`. Third-party enterprise applications and consent grants ->
`zp-redteam-entra`, `zp-redteam-okta`. Vendor appliances at the edge -> `zp-redteam-vpn`; on-prem
identity holding vendor accounts -> `zp-redteam-ad`. Third-party agent, plugin and MCP integrations
-> `zp-agentic`. Dangling records - report, do not claim -> `zp-takeover`. Published CVEs in a
consumed component -> `zp-cve`. Passive supplier discovery before the gate clears ->
`zp-recon-passive`. Tools -> `zp-toolchain`. Findings -> `zp-triage`, then `zp-report` for the
attack narrative and the artifact inventory.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
