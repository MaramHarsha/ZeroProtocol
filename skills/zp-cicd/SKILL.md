---
name: zp-cicd
description: ZeroProtocol hunter for CI/CD and software supply chain exposure - pipeline config served by the app, secrets in build logs and artifacts, GitHub Actions workflow injection, over-broad GITHUB_TOKEN, unpinned or repojackable actions, self-hosted runners on public repos, image layer and registry exposure, dependency confusion and typosquats. Use when a target has a public GitHub or GitLab org, a workflow file is reachable, or internal package names appear in a bundle. Stops at exposure - never publish a package, never open a PR.
---

# zp-cicd - the build is production

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

The build system holds the credentials production only borrows, and almost none of it sits behind
the login page you were handed. This class is unusual in ZeroProtocol: the strongest findings are
**read from public artifacts** - a workflow file, a run log, an image layer - so the proof is a
static data flow plus a reachable trigger, not an execution. That is also the ceiling. **You never
make a pipeline run your code.** A finding is real when you can name the trigger, the untrusted
input, the sink and the secret in blast radius, all from material you were allowed to read.

---

## Procedure

**1. Split the surface first.** Reading `github.com` or `registry.npmjs.org` *about* a target is
third-party traffic, allowed while scope is unconfirmed (the `zp-recon-passive` rule). Requesting
`https://$H/.gitlab-ci.yml` is target traffic and needs exit 0. The **org must also be in scope** for
what you read there to be reportable - plenty of programs scope the web app and exclude the GitHub org.

**2. Ask the app for its own build config.** Deploys that copy the repo root into the webroot are the
commonest entry point here, and it is one loop.

```bash
H=target.tld
for p in .gitlab-ci.yml .github/workflows/ci.yml .github/workflows/deploy.yml Jenkinsfile \
         .circleci/config.yml azure-pipelines.yml bitbucket-pipelines.yml .drone.yml cloudbuild.yaml \
         buildspec.yml .travis.yml .npmrc .yarnrc.yml pip.conf NuGet.config Dockerfile \
         docker-compose.yml .env .git/config package-lock.json zpc-91234.yml; do
  printf '%-32s %s\n' "$p" "$(curl -sk -o /dev/null -w '%{http_code} %{size_download}' \
    --max-time 10 "https://$H/$p")"
done
```

The last path cannot exist - it is the calibration. A SPA answering `200` with `index.html` for
everything makes all of this look like a hit; compare sizes, then read the body.

**3. Harvest the org's workflows** (third-party, no target packets). `gh` with any token, plain REST
as the fallback.

```bash
ORG=targetorg
gh repo list "$ORG" --limit 200 --json name,visibility \
  --jq '.[]|select(.visibility=="PUBLIC").name' > /tmp/repos.txt \
  || curl -s "https://api.github.com/orgs/$ORG/repos?per_page=100" | jq -r '.[].name' > /tmp/repos.txt
while read -r r; do
  for wf in $(gh api "repos/$ORG/$r/contents/.github/workflows" --jq '.[]?.name' 2>/dev/null); do
    gh api "repos/$ORG/$r/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null | base64 -d \
      | grep -Eq 'pull_request_target|workflow_run|issue_comment' && echo "CANDIDATE $ORG/$r/$wf"
  done
done < /tmp/repos.txt
```

**4. Triage each candidate statically - trigger, untrusted value, sink.** All three or it is killed.
Run the analysers rather than eyeballing YAML.

```bash
git clone --depth 1 "https://github.com/$ORG/$r" /tmp/r && cd /tmp/r
zizmor .github/workflows/            # pip install zizmor; --offline skips API lookups
actionlint .github/workflows/*.yml   # also flags untrusted-input interpolation
grep -rnE '\$\{\{ *(github\.event|github\.head_ref|inputs\.)' .github/workflows/
grep -rnE 'pull_request_target|workflow_run|head\.(sha|ref)|self-hosted|download-artifact' .github/workflows/
```

| Condition | Reading it |
|---|---|
| **privileged trigger** | `pull_request_target`, `workflow_run`, `issue_comment` carry secrets and a write token on *untrusted* input. Plain `pull_request` from a fork does not |
| **untrusted value** | `github.event.*.title`/`.body`, `github.head_ref`, a comment body, a label, a commit message |
| **a sink** | the value lands in a `run:` block, or the job checks out `head.sha`/`head.ref` and then runs that tree - `npm ci`, `make`, a local action, an install hook |

`${{ }}` is substituted into the script *text* before any shell exists, so a newline or `$( )` in a PR
title becomes shell. The safe pattern - bound through `env:`, referenced as `"$VAR"` - is **not**
injectable. Say so and move on.

**5. Read the token and the pins.** Severity is blast radius, not the injection.

```bash
grep -rnE '^\s*permissions:|contents:|id-token:|packages:' .github/workflows/ | head -40
grep -rhoE 'uses: *[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[^ ]+' .github/workflows/ | sort -u
# any @tag or @branch is mutable; then check whether the owner namespace still exists
grep -rhoE 'uses: *[A-Za-z0-9_.-]+/' .github/workflows/ | awk -F'[ /]' '{print $2}' | sort -u \
  | while read -r o; do printf '%-22s %s\n' "$o" \
      "$(curl -s -o /dev/null -w '%{http_code}' "https://github.com/$o")"; done
```

No top-level `permissions:` means the repo default applies, which on older repos is `contents: write`.
A `404` owner is **repojacking** - the namespace is free and every build pinned to it is one
registration away from arbitrary code. Report it; **do not register the name.**

**6. Identify runners from runs that already happened.** No execution, no PR.

```bash
RID=$(gh api "repos/$ORG/$r/actions/runs?per_page=1" --jq '.workflow_runs[0].id')
gh api "repos/$ORG/$r/actions/runs/$RID/jobs" --jq '.jobs[]|{name,runner_name,runner_group_name,labels}'
```

A `runner_name` that is not `GitHub Actions N`, or a custom label, on a **public** repo whose
workflows run fork-triggered jobs, is a self-hosted runner an outsider can reach. The same output
pins the OS and toolchain for `zp-cve`.

**7. Mine logs and artifacts - where the secret is already published.**

```bash
gh api "repos/$ORG/$r/actions/runs?per_page=30" --jq '.workflow_runs[].id' | while read -r id; do
  gh api "repos/$ORG/$r/actions/runs/$id/logs" > /tmp/l.zip 2>/dev/null && unzip -oq /tmp/l.zip -d /tmp/logs
done
grep -rniE 'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{15,}\.' /tmp/logs
gh api "repos/$ORG/$r/actions/artifacts" --jq '.artifacts[]|"\(.id) \(.name) \(.expired)"'
trufflehog filesystem /tmp/logs --only-verified 2>/dev/null   # fallback is the grep above
```

Masking hides only the exact literal, so a base64, JSON-escaped or character-echoed secret passes
through, as does anything printed before `::add-mask::`. `upload-artifact` masks nothing - an artifact
built from the whole workspace ships `.git/config`, where `actions/checkout` leaves the run token by
default.

**8. Images and registries.** Layer history keeps what a later `RUN rm` removed.

```bash
curl -s "https://hub.docker.com/v2/repositories/$ORG/?page_size=100" | jq -r '.results[].name'
TOK=$(curl -s "https://ghcr.io/token?scope=repository:$ORG/$IMG:pull&service=ghcr.io" | jq -r .token)
curl -s -H "Authorization: Bearer $TOK" -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
     "https://ghcr.io/v2/$ORG/$IMG/manifests/latest" | jq '.config.digest, .layers[].size'
docker history --no-trunc "$ORG/$IMG:latest" | grep -iE 'ARG|ENV|token|secret|password|key'
crane config "ghcr.io/$ORG/$IMG:latest" | jq -r '.history[].created_by'   # no docker daemon needed
trufflehog docker --image "$ORG/$IMG:latest" --only-verified
```

**9. Dependency confusion and typosquats - three conditions, and you publish nothing.**

```bash
# a) the name is consumed by a build you can see (lockfile, manifest, bundle)
jq -r '.dependencies//{}|keys[]' package.json; grep -oE '@[a-z0-9-]+/[a-z0-9._-]+' /tmp/main.js | sort -u
# b) the name is unclaimed on the public registry (404)
N='@targetorg/internal-utils'
curl -s -o /dev/null -w 'npm %{http_code}\n' "https://registry.npmjs.org/$(printf '%s' "$N" | sed 's|/|%2f|')"
curl -s -o /dev/null -w 'pypi %{http_code}\n' "https://pypi.org/pypi/target-utils/json"
curl -s -o /dev/null -w 'crates %{http_code}\n' -A zp "https://crates.io/api/v1/crates/target-utils"
curl -s -o /dev/null -w 'nuget %{http_code}\n' "https://api.nuget.org/v3-flatcontainer/target.utils/index.json"
curl -s -o /dev/null -w 'gems %{http_code}\n' "https://rubygems.org/api/v1/gems/target-utils.json"
curl -s "https://proxy.golang.org/github.com/$ORG/$MOD/@v/list"
# c) the resolver would reach the public registry at all
grep -nE '^\s*(registry|@[a-z0-9-]+:registry)\s*=' .npmrc; grep -rn 'extra-index-url' . 2>/dev/null
grep -n 'packageSourceMapping' NuGet.config; grep -nE 'mavenCentral|repositories \{' build.gradle
```

All three, or it is informational. **Never publish**, not even a benign canary with a DNS callback - a
public registry is not the target's asset, the package reaches everyone who mistypes, and it outlives
the engagement. The report is the three-part argument plus the fix (`@scope:registry` pinning,
`packageSourceMapping`, an exclusive internal mirror).

**10. Provenance, last and lightly.** `gh attestation verify <file> --owner "$ORG"` and
`cosign verify-attestation` say whether a release traces back to a workflow. A missing attestation is
hardening advice, not a vulnerability - it matters only as an amplifier for step 4.

**11. Stop point, stated in the report.** You stop at the workflow file, the log line, the layer, the
`404` on a namespace. You do **not** open a PR against a real repo (draft or private fork included),
run a job on their runner, use a recovered credential beyond an identity call, publish or reserve any
package or namespace, push a tag or image, or delete a log or artifact. If the only proof would be
making their pipeline execute your code, the finding **is** the data flow - write that up.

---

## Probes and payloads

| Probe | What it breaks | Positive looks like |
|---|---|---|
| `GET /.gitlab-ci.yml`, `/Jenkinsfile`, `/.github/workflows/ci.yml` | repo root copied into the webroot | YAML body, size differing from the calibration path |
| `GET /.git/config`, `/.npmrc`, `/pip.conf` | same deploy, with registry URLs | internal registry host, `//registry/:_authToken=` |
| `github.event.*.title|.body|head_ref` inside a `run:` | template substitution into the script text | the expression unquoted in `run:`, not bound via `env:` |
| `checkout` at `head.sha` then `npm ci`/`make` | poisoned checkout - no `${{ }}` needed | a build step following a fork-controlled tree |
| `uses: org/action@v1` | mutable third-party code in a trusted job | any `@tag` or `@branch` ref |
| `curl -w %{http_code} github.com/<action-owner>` | retired namespace behind a pinned action | `404` - repojackable. Report, do not claim |
| no top-level `permissions:` | default token scope, often `contents: write` | the key absent from the whole file |
| `runs/<id>/jobs` → `runner_name`, `labels` | self-hosted runner reachable from a fork PR | a name that is not `GitHub Actions N` |
| run-log regex sweep | masking that covers only the literal | `AKIA…`, `ghp_…`, `xox…`, `BEGIN … PRIVATE KEY`, a JWT |
| artifact list, then read one | `upload-artifact` redacts nothing | `.git/config` with a token, `.env`, a kubeconfig |
| `docker history` / `crane config` | secrets deleted in a later layer | a credential in `ARG`/`ENV`/`created_by` |
| unauth `ghcr.io/v2/.../manifests` | registry ACL assumed, not set | `200` where auth should be required |
| registry `404` on an internal name | no scope pinning at the resolver | `404` **and** the name in a lockfile **and** a loose `.npmrc` |

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| privileged trigger + untrusted value + `run:`/checkout sink + a secret in the job | **confirmed workflow injection.** Critical with `contents: write` or cloud OIDC. Proof is the flow - no PR |
| a live credential in a log, artifact or layer, validated live and not used | **confirmed secret exposure.** Severity from the credential's reach |
| self-hosted runner on a public repo running fork-triggered jobs | **confirmed.** High - shared host, non-ephemeral state |
| action pinned to a tag whose owner namespace `404`s | **confirmed repojacking exposure.** High, and free to fix |
| internal name unclaimed **and** in a consumed manifest **and** no scope pinning | **confirmed dependency confusion.** High. Argument only, never a package |
| unauthenticated read of a registry path holding private images | confirmed exposure - blast radius via `zp-cloud` |
| public IaC with an OIDC trust policy on `repo:ORG/*:*` | confirmed over-broad federation. Read the policy, never assume the role |
| `pull_request_target` present, untrusted input only in `if:` or only via `env:` + `"$VAR"` | **not injectable.** Killed - that pattern is the fix, not the bug |
| plain `pull_request` from a fork | read-only token, no secrets. Killed |
| `${{ github.sha }}`, `github.repository`, `github.run_id` in a `run:` | not attacker-controlled. Killed |
| workflow reachable but holding no secret, internal host or injectable step | informational at best. Killed |
| a scanner flagged it and you have not read the YAML | unverified. Killed until you can name all three conditions |
| expired or example key in a log, or a trufflehog hit that will not verify | **not a finding.** Rotated strings are noise |
| `200` on every path including the calibration file | the config is not exposed. Killed - calibrate first |
| unclaimed registry name with no evidence any build resolves it | informational. The bulk of junk in this class |
| missing provenance or SBOM and nothing else | hardening note, not a vulnerability |
| the org or registry is outside program scope | **not yours to report.** Re-run `zp-scope check` |

---

## High-value patterns

- **A deploy that copies the repo into the webroot** - `.git/config`, an `.npmrc` auth token and the
  whole pipeline from one `GET`. Feed the paths to `zp-content-discovery`.
- **`issue_comment` and `workflow_run` handlers** - as privileged as `pull_request_target`, hunted far
  less; a `workflow_run` job that downloads a fork's artifact runs attacker files on the default branch.
- **A tiny public repo in a large org** - docs, examples, a landing page. Same org secrets, none of the
  review attention, and usually where the self-hosted runner still is.
- **Logs of a workflow that added masking later** - the history keeps the unmasked run.
- **An action owned by a renamed or deleted account** - the `tj-actions/changed-files` tag rewrite
  (CVE-2025-30066) showed how far one mutable third-party ref reaches.
- **`id-token: write` beside an over-broad cloud trust policy** - the injection stops being a repo
  problem and becomes cloud access. Hand to `zp-cloud`.
- **Internal scope names in a bundle or source map** - `zp-js-secrets` already collected them.
- **An exposed CI dashboard** on a forgotten subdomain from `zp-recon-passive` - fingerprint it, then
  route the exploit to `zp-cve` or `zp-rce-ssti`.

---

## Pitfalls

- **Opening a PR to test an injection.** The line this skill will not cross, on any repo, with any
  payload, however benign - it puts your code in a queue a human trusts. Prove the flow statically.
- **Publishing a "harmless" canary package.** That is a live supply-chain attack, not a PoC.
- **Registering a repojackable namespace** to demonstrate the gap. Naming it is the finding.
- **Running a job on a self-hosted runner.** The jobs API already names it.
- **Reporting `pull_request_target` on sight.** Most instances are safe; filing it unread is the
  signature junk report of this class.
- **Calling a version or a permission impact.** Name the secret and its reach.
- **Using a recovered credential.** Validate that it lives, then stop - the `zp-js-secrets` rule. Note
  that a `--only-verified` scan *is* an authentication attempt against the provider.
- **Cloning the whole org at full speed.** GitHub rate-limits, and a scrape is not a hunt.
- **Deleting a log, artifact, tag or image.** Never - you are reading, and destroying evidence is worse
  than a bad report.
- **Testing a vendor's pipeline** because their action appears in the target's workflow. Different asset.
- **Forgetting the org may be out of scope** while the web app is in scope.

---

## Hand off to

Credentials and blast radius -> `zp-cloud`. Exposed CI dashboards and versioned components ->
`zp-cve`, `zp-rce-ssti`. Source recovered from an exposed repo or config -> `zp-code-audit`; internal
names in bundles -> `zp-js-secrets`. More config paths -> `zp-content-discovery`. Forgotten CI hosts ->
`zp-recon-passive`, `zp-recon-active`. Registry and dashboard auth -> `zp-authz`, `zp-jwt-oauth`.
Build debug output and stack traces -> `zp-info-disclosure`. A new host in a pipeline file ->
`zp-scope` before touching it. Confirmed -> `zp-triage`, then `zp-report` with the trigger, the sink
and the secret named.
