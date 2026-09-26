---
name: zp-redteam-iam
description: ZeroProtocol red-team skill for cloud IAM privilege escalation under a signed engagement - AWS, Azure and GCP role and policy enumeration, PassRole plus compute primitives, policy-version manipulation, lambda and glue role takeover, GCP service-account impersonation, Azure role assignment and managed identity abuse, cross-account trust and blast radius. Use when an engagement hands over cloud credentials and asks how far an intruder could walk. Requires a signed engagement, not a bounty page.
---

# zp-redteam-iam - the control plane is the whole estate

**Phase:** red-team tier | **Gate:** **engagement-gated.** `zp-scope tier redteam` must exit 0.
Exit 9 means the tier is not authorized - refuse, and name which of the six engagement facts is
missing (signed document, named scope, dates, two contacts, deconfliction channel, stop condition).
`zp-scope check <host>` still applies to every individual host, endpoint and tenant you touch, and
the plain bounty check is **not** a substitute for the tier gate.

This skill answers one question - **from the identity the engagement issued you, which chain of
IAM grants reaches an administrator or the data, and which single grant breaks the chain?** This
is the tier where a live credential is actually used, so the boundary is sharp - only credentials the
engagement provided, enumerate rather than exercise, never production data, never durable access.
The deliverable is a path drawn grant by grant, the earliest control that severs it, and what the
client's audit trail recorded at each step. An assumed role is not a trophy.

---

## Procedure

1. **Clear the tier gate** - the six engagement facts go into `.zeroprotocol/scope.yaml` by key
   name (`authorization_ref`, `contact_technical`, `contact_stop`, `window`, `deconfliction`,
   `stop_condition`), which is what `zp-scope tier redteam` reads. Then list every in-scope account,
   subscription, project and org node. A linked account is a third party until the scope names it.
2. **Fix the starting identity** - what you hold, who issued it, when it expires. If a credential
   turns up mid-run that the engagement did not grant, stop and call the contact.
3. **Pull the authorization graph in one read**, not with a thousand probes. Every provider exports
   principals, policies and bindings in bulk, quieter and more completely than permission probing.
4. **Resolve effective permissions offline**, then let the provider's own evaluator confirm -
   simulation and troubleshooting APIs answer "would this be allowed" without performing it.
   This is the core move of the skill.
5. **Score the escalation primitives** against the graph. Each is a grant *plus* a service that
   will act on your behalf, so look for the pair and not the verb.
6. **Map trust at the edges** - cross-account assume-role policies, missing external IDs, wildcard
   principals, CI federation, workload identity pools, cross-tenant guests. Trust is where the
   blast radius leaves the account you were given.
7. **Compute blast radius from grants** - the data stores, secrets, key material and compute the
   chain reaches, labelled as an assessment from policy, not as something you exercised.
8. **Ask what fired** per step - did the control-plane trail record it, did an alert reach a human.
9. **Write the path, remove every artifact, verify each removal**, hand over the inventory.

---

## Commands

**AWS - identity, then one bulk read**

```bash
aws sts get-caller-identity
aws iam get-account-authorization-details > aws-authz.json   # users, roles, policies, trust, one call
aws organizations list-accounts --output table                # in-scope accounts only
jq -r '.RoleDetailList[] | select(.AssumeRolePolicyDocument | tostring | test("\"AWS\":\"\\*\"|:root")) | .Arn' aws-authz.json
jq -r '.RoleDetailList[] | select(.AssumeRolePolicyDocument | tostring | test("sts:ExternalId") | not) | .Arn' aws-authz.json
```

**AWS - prove a permission without using it**

```bash
A=arn:aws:iam::111122223333:role/EngagementRole
aws iam simulate-principal-policy --policy-source-arn "$A" \
  --action-names iam:PassRole lambda:CreateFunction iam:CreatePolicyVersion sts:AssumeRole \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
aws iam generate-service-last-accessed-details --arn "$A"    # then get-service-last-accessed-details --job-id
aws accessanalyzer list-analyzers --output table              # external and unused access the client already tracks
```

No simulation permission - read the documents and resolve by hand.

```bash
aws iam list-attached-role-policies --role-name EngagementRole
aws iam get-policy-version --policy-arn <arn> --version-id v3
aws lambda list-functions --query 'Functions[].[FunctionName,Role]' --output table
aws glue get-dev-endpoints --query 'DevEndpoints[].[EndpointName,RoleArn]' --output table
```

CloudSplaining scores the exported `aws-authz.json` for wildcard actions entirely offline
(`cloudsplaining scan --input-file aws-authz.json`) and sends nothing. PMapper is not offline: it
builds its own graph with live read-only calls (`pmapper graph create` enumerates IAM plus EC2,
Lambda and the other services it models, using your credentials) and cannot be pointed at your
export - only its path analysis afterwards is local. Declare those calls and log them, because
Deconfliction below requires the client to attribute every API call to you.

**GCP - bindings, impersonation and actAs**

```bash
P=client-prod; SA=svc@$P.iam.gserviceaccount.com
gcloud projects get-iam-policy "$P" --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)" --filter="bindings.members:$SA"
gcloud asset search-all-iam-policies --scope="projects/$P" --query="policy:\"$SA\""
gcloud iam service-accounts get-iam-policy "$SA"             # who may impersonate this SA
gcloud projects get-ancestors "$P"                           # folder and org inheritance
gcloud policy-troubleshoot iam "//iam.googleapis.com/projects/$P/serviceAccounts/$SA" \
  --principal-email="<the identity you hold>" --permission=iam.serviceAccounts.actAs
# actAs, getAccessToken, signJwt and signBlob are permissions on the *service-account* resource, so
# troubleshoot them against the SA with yourself as the principal. Aimed at the project resource, or
# with the target SA as the principal, it answers a question that is not the impersonation question.
gcloud functions describe <name> --gen2 --format='value(serviceConfig.serviceAccountEmail)'
```

`policy-troubleshoot` is the GCP answer to simulation - allow or deny explained per binding,
nothing performed.

**Azure - assignments, custom roles, managed identity**

```bash
az account show
az role assignment list --all --include-inherited --include-groups --assignee <objectId> --output table
az role definition list --custom-role-only true \
  --query "[].{name:roleName,actions:permissions[0].actions}" --output json
az identity list --output table                              # user-assigned managed identities
az vm identity show --name <vm> --resource-group <rg>        # system-assigned identity on a VM
az rest -m get -u "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
```

A custom role with `Microsoft.Authorization/roleAssignments/write`, or `*/write` at subscription
scope, is the Azure admin policy - read the definition, never assign.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| `iam:PassRole` scoped to `*` plus any of lambda, ec2, glue, cloudformation, codebuild, datapipeline | **confirmed escalation path.** The pair is the finding, simulation is the proof |
| `iam:PassRole` scoped to one named role no more privileged than yours | killed - the resource constraint is the control working |
| `iam:CreatePolicyVersion` or `iam:SetDefaultPolicyVersion` on a policy attached to an admin | **confirmed.** List the versions, never create v2 |
| trust policy with a wildcard principal, or a third-party account and no `sts:ExternalId` | **confirmed confused deputy.** Read the document, do not assume from outside |
| a role the engagement's identity was plainly meant to assume | that is the issued position, not an escalation. Baseline it and move on |
| `lambda:UpdateFunctionCode` or `UpdateFunctionConfiguration` on a function with a privileged role | **confirmed** from configuration alone - replacing code is a production change |
| `iam.serviceAccounts.getAccessToken`, `signJwt`, `signBlob` or `actAs` on a higher-privileged SA | **confirmed impersonation path**, proven by `policy-troubleshoot` |
| `iam.serviceAccountKeys.create` on any SA | **confirmed**, and durable access if exercised - never mint the key |
| `Microsoft.Authorization/roleAssignments/write` at subscription or management-group scope | **Critical.** Owner is one assignment away, and it is not yours to make |
| `Microsoft.Compute/virtualMachines/runCommand/action` | **confirmed** path to the VM's managed identity - read that identity's assignments instead |
| a permissive policy that an SCP, org policy or Azure Policy denies | **killed** at the effective layer. Say the guardrail held, and name it |
| every step appears in the trail and no alert fired | **finding in its own right** - see deconfliction |

---

## Least-invasive proof

**Every capability below is proven by a read.** Where a proof needs a write, the grant is the proof.

| Capability | Smallest action that proves it | Never |
|---|---|---|
| account administrator | the attached policy document granting all actions on all resources | attach a policy, create a user, mint an access key |
| PassRole plus compute escalation | a simulation decision of `allowed` for both actions, plus the target role's policy | launch the instance, create the function, start the stack |
| trust rewrite or cross-account assumption | the trust document naming your principal, and the grant that could edit it | chain assumptions beyond baselining the issued position |
| lambda or glue role takeover | the function or endpoint configuration plus the role's policy | replace code, add a layer or an environment variable |
| GCP impersonation | `policy-troubleshoot` allow on `getAccessToken` or `actAs` | mint a token, create an SA key, redeploy a function |
| Azure Owner reachability | the role definition plus the scope of your assignment | create the role assignment |
| managed-identity abuse | the identity's role assignments from ARM read APIs | request its token, or act with it |
| secrets reach | the secret's name, version metadata and the grant | retrieve the secret value |
| data blast radius | a resource count and one object's schema, values redacted | list or download a production data set |
| durable access risk | the grant that would create it | create the key, user, federation or trust that persists |

Domain admin is proven by a directory read, hypervisor access by a read-only inventory call, and
cloud administrator by the policy document - never by using it.

---

## Deconfliction

| What | How |
|---|---|
| source IPs | fixed, in the engagement file, handed to the SOC and the cloud team before step 3 |
| session names | every assume-role session and created object carries the engagement reference - `zp-<ref>-<n>`, never a plausible business name. The session name lands in the trail and is your alibi |
| logging | append-only JSONL per action - UTC timestamp, account or project or subscription, principal, API call, decision, request ID. Record the first four characters of a key id and nothing more of it |
| artifacts | every created or changed IAM object goes into `.zeroprotocol/artifacts.md` at the moment of creation, before you continue |
| call the contact | before any IAM write the ROE permits; before touching a shared or linked account; when a denial suggests a real incident; on any sign of a real intruder; if a chain reaches a partner tenant |
| answer speed | you must be able to tell the client within minutes which control-plane events were you, for the whole window |

**Detection gaps are first-class findings.** Pull the trail for your own activity
(`aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole`,
Azure Activity Log, GCP Cloud Audit Logs) and ask whether an alert reached anyone. "The telemetry
recorded every step and nobody was paged" is frequently worth more to the client than a second route
to administrator, and it is the half of the report only a red team can write.

---

## Cleanup

| Artifact this skill can create | Removal | Verification |
|---|---|---|
| assumed-role sessions | let them expire, do not refresh | no session for your principal in the trail after the window |
| local credential material - env vars, AWS profiles, `gcloud` and `az` caches | destroy the working set, sign out of every CLI, remove the profile | `aws sts get-caller-identity`, `gcloud auth list` and `az account show` all fail |
| exported graphs - `aws-authz.json`, asset exports, PMapper graphs | destroy on completion, keep only redacted report excerpts | the working directory is gone and no live secret is in the report |
| any IAM object the ROE permitted you to create (test role, policy, SA, key, binding) | delete it, and the credential it issued | absent from a fresh bulk read; any key it issued is inactive |
| a policy version or trust document you were permitted to change | restore the pre-change document from your snapshot | a diff against the snapshot is empty |
| storage objects or compute created as part of a proof | delete, and empty any soft-delete stage | absent at both stages |

Snapshot every policy, trust document and binding **before** touching it, so cleanup is a diff and
not a memory exercise. Then walk `.zeroprotocol/artifacts.md` in reverse, verify each line, and hand
the inventory over. A forgotten IAM object is persistence you installed - and cloud activity is
trivially auditable, so the client will find it after you leave.

---

## Pitfalls

- **Running this off a bounty scope.** `zp-scope check` returning 0 is not the tier gate; `zp-scope tier redteam` is.
- **Using a credential the engagement did not provide.** A key from a repo, a bundle or a breach corpus is not yours to authenticate with, even to identify it - that is `zp-cloud`'s retrievability finding and it stops at reporting.
- **Exercising an escalation you already proved.** Minting the admin key turns a finding into durable access and a production change.
- **Reading production data to show impact.** A count and a redacted schema prove reachability; a customer table is an exfiltration.
- **Touching linked accounts, other projects or partner tenants** because trust made them reachable. Cloud tenancy means the owner may not even be your client.
- **Leaving an access key, service-account key, role, trust edge, federation mapping or binding behind**, or retaining any credential or export after the window closes. Durable access is the one thing this tier must never create.
- **Assuming an attached policy is the effective one.** SCPs, org policies, permission boundaries and resource policies all override - report the effective decision.
- **Destructive or availability-affecting IAM changes** - deleting a policy version, detaching a role in use, revoking sessions on a production identity. None of it is authorized here.
- **Disabling GuardDuty, Defender for Cloud, Security Command Center or the audit trail** to stay quiet. Tampering with a production control is forbidden, and it destroys the detection half of the report.
- **Social engineering a cloud admin, or any denial of service** against the control plane. Separate authorizations that this tier does not imply.

---

## Hand off to

Tier gate and engagement facts -> `zp-redteam-mode`. Per-host and per-tenant scope decisions ->
`zp-scope`. External cloud surface, buckets and metadata retrievability under the no-credential
rules -> `zp-cloud`. Entra, Graph and M365 identity -> `zp-redteam-entra`. On-prem identity across
the seam -> `zp-redteam-ad`. Federated IdPs feeding cloud roles -> `zp-redteam-okta`.
Virtualisation reached through a cloud role -> `zp-redteam-vcenter`. Token and federation mechanics
-> `zp-jwt-oauth`. Keys in repositories, CI and bundles -> `zp-code-audit`, `zp-js-secrets`.
Control-plane APIs -> `zp-api`, `zp-authz`. SSRF to a metadata endpoint -> `zp-ssrf`. Published
CVEs on an exposed control-plane component -> `zp-cve`. Tools -> `zp-toolchain`. Findings ->
`zp-triage`, then `zp-report` for the attack narrative and the artifact inventory.

Tier reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
