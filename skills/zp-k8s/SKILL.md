---
name: zp-k8s
description: ZeroProtocol hunter for externally-reachable Kubernetes and container platforms - anonymous API-server access, the read-only kubelet on 10255 versus the full kubelet on 10250, exposed etcd, token-less dashboards, and ingress that misroutes between namespaces or tenants. Use when a host answers on 6443, 8443, 10250, 10255 or 2379, when a web app leaks a service-account token, or when a container-escape or admission gap is reachable externally. Confirms with one read-only call and stops.
---

# zp-k8s - one read-only call, then stop

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

A control-plane port answering is a **lead**, not a finding. The whole class turns on one
distinction the defender needs proven, not inferred - **can an unauthenticated outsider read or
change cluster state, or does RBAC quietly deny them behind a `200`?** ZeroProtocol answers that
with a single read-only call (`/version`, `/pods`) and stops. Never create a workload, never
`exec`, never read a Secret value. The proof is *reachability with no credential* - that is the
report; the exploitation half is the defender's incident, not yours.

Cross-references `zp-cloud` for the port sweep, metadata-credential pivot, object storage and
registry exposure. This skill goes deeper on the Kubernetes control plane; do not duplicate that.

---

## Procedure

**1. Fingerprint the control-plane ports** (`zp-recon-active` found the open ones).

```bash
H=target.tld
for p in 6443 8443 10250 10255 2379 2380 4194 44134; do
  printf '%-6s ' "$p"
  curl -sk -o /dev/null -w '%{http_code}\n' --max-time 8 "https://$H:$p/" 2>/dev/null \
    || printf 'closed\n'
done
curl -sk --max-time 8 "https://$H:6443/version"      # gitVersion is anonymous on most clusters
```

`gitVersion` gates every version-bound CVE - carry it to `zp-cve`, do not report it alone.

**2. API server (6443) - is anonymous access real, or an RBAC-filtered `200`?**

```bash
S="https://$H:6443"
curl -sk --max-time 8 "$S/version"; echo
curl -sk --max-time 8 "$S/api" | head -c 200; echo         # APIVersions, often pre-auth
curl -sk --max-time 8 "$S/api/v1/namespaces" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d.get("items",[])),"namespaces")' \
    2>/dev/null || echo "not JSON / denied"
```

A `200` with a populated `items` array from `system:anonymous` is the finding and the whole proof.
A `200` with `items: []`, or a `403`/`401` body, is RBAC doing its job - stop there. Do **not**
POST a SelfSubjectAccessReview loop, list Secrets, or create anything to "prove" more.

**3. Kubelet - 10255 (read-only, HTTP) is not 10250 (full, HTTPS).** Conflating them is the
defining error of this class.

```bash
curl -s  --max-time 8 "http://$H:10255/pods" | head -c 200; echo    # read-only, no exec/run
curl -sk --max-time 8 "https://$H:10250/pods" | head -c 200; echo   # full kubelet
```

A `/pods` body from either is a confirmed unauthenticated read. That is the stop point. The 10250
`/run` and `/exec` primitives are RCE and are **out of scope for ZeroProtocol** - a `/pods` read
proves the exposure without them.

**4. etcd (2379) - confirm reachability, never dump.**

```bash
curl -s --max-time 8 "http://$H:2379/version"; echo          # etcd + server version, unauth
curl -s --max-time 8 "http://$H:2379/metrics" | head -c 200; echo
```

A `/version` or `/metrics` body over plain HTTP with no client cert is the finding. etcd holds
every Secret in the cluster - do **not** issue a `range`/`get` to read keys; note that the store
is reachable and stop.

**5. Dashboard (8443) - the HTML shell is just the login page.**

```bash
curl -sk --max-time 8 "https://$H:8443/" | grep -io 'kubernetes dashboard' | head -1
curl -sk -o /dev/null -w '%{http_code}\n' --max-time 8 "https://$H:8443/api/v1/login/status"
```

Presence of the shell is Low/informational. The question is whether login is enforced - a
token-less data view is the finding, but confirm it by *one* resource-list status code, not by
reading secrets through it.

**6. Ingress misrouting between namespaces or tenants.** Pin the connection to the ingress IP and
vary the `Host`, which is what actually selects the backend.

```bash
IP=$(dig +short "$H" | grep -E '^[0-9.]+$' | head -1)
for vh in "tenant-b.$H" "admin.$H" "internal.$H" "kubernetes.default.svc"; do
  printf '%-28s ' "$vh"
  curl -sk -o /dev/null -w '%{http_code}\n' --max-time 8 --resolve "$vh:443:$IP" "https://$vh/"
done
```

A `200` serving another tenant's or namespace's app from the shared ingress is a
cross-tenant isolation finding. Confirm you reached a *different* backend (title, distinct
content), not the same default page.

**7. Service-account token reachable from the web app.** When an LFI or SSRF (`zp-xxe-lfi`,
`zp-ssrf`) can read `/var/run/secrets/kubernetes.io/serviceaccount/token`, the retrievability is
the finding. Decode the claims **offline** to judge blast radius - do not replay the token.

```bash
# TOK is what the LFI/SSRF returned; this is pure local base64, no request to the cluster
echo "$TOK" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool
# aud = audience (a vault/OIDC aud will NOT authenticate to the API), exp = expiry (may be dead)
```

**8. Stop point - state it in the report.** You stop at: a read-only body from an anonymous port,
a decoded token claim set, or a cross-tenant `200`. You never create a Pod, `exec`, attach an
ephemeral container, read a Secret value, dump etcd, or use a recovered token. Version-gated
escapes (runc, ingress-nginx) route to `zp-cve` as leads, not exploits.

---

## Probes and payloads

| Probe | Surface | Positive looks like |
|---|---|---|
| `GET https://$H:6443/version` | API server fingerprint | JSON `gitVersion` - a lead for `zp-cve` |
| `GET https://$H:6443/api/v1/namespaces` | anonymous API read | `200` with populated `items[]` from `system:anonymous` |
| `GET http://$H:10255/pods` | read-only kubelet | pod JSON, no auth - info disclosure, no exec |
| `GET https://$H:10250/pods` | full kubelet | pod JSON, no auth - stop here, do not `/run` |
| `GET http://$H:2379/version` | etcd, plain HTTP | etcd version JSON with no client cert |
| `GET https://$H:8443/api/v1/login/status` | dashboard | `200` data view without a token |
| `--resolve <vh>:443:$IP` Host swap | ingress routing | a *different* backend served for another tenant/namespace |
| decode SA-token `aud`/`exp` | leaked token | claims readable offline - judge, never replay |

No-tool fallback: every probe above is `curl`/`dig`/`python3` stdlib already. No `kubectl`,
`etcdctl`, `nmap` or `kubeletctl` is required to reach the stop point - and their exec/dump
sub-commands are past it.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| anonymous `GET /api/v1/namespaces` returns populated `items[]` | **confirmed anonymous API read.** High to Critical by what is listed |
| same call returns `items: []` or `403`/`401` | RBAC is denying you - **killed.** A `200` is not access |
| `/pods` body from 10255 (HTTP) | confirmed read-only kubelet exposure. **Medium** - info disclosure, not RCE |
| `/pods` body from 10250 (HTTPS), unauth | confirmed full-kubelet exposure. **Critical** - report the read, do not exec |
| a bare `302`/`101` from 10250 with no `/pods` body | streaming endpoint, not proof of read - killed until `/pods` answers |
| etcd `/version` or `/metrics` over plain HTTP, no cert | **confirmed** etcd exposure. Critical. Do not dump keys |
| `200` on etcd peer port 2380, or a TLS handshake error | peer/TLS-required port - **not** unauth client access. Killed |
| dashboard returns only the HTML login shell | just the login page. **Low/informational** unless a data view answers token-less |
| ingress serves a different tenant's backend on a swapped `Host` | **confirmed cross-tenant misrouting.** Severity by what leaks |
| ingress returns the same default page for every `Host` | no isolation broken - killed |
| SA token retrievable via LFI/SSRF, `aud` matches the API server, `exp` in the future | **confirmed** token exposure. Report retrievability; never replay it |
| SA token whose `aud` is `vault`/OIDC, or already expired | will not authenticate to the API - note it, but the cluster impact is unproven |
| a version banner only, no reachable behaviour | **not a finding** - a `zp-cve` lead |

---

## High-value patterns

- **A forgotten cluster on an acquisition or staging subdomain** with anonymous API read - the
  same missed-patch-cycle story as `zp-cve`, found via `zp-recon-passive`.
- **10250 answering `/pods` unauthenticated** - historically the highest-impact external K8s
  finding, and the read alone proves it.
- **etcd on 2379 over plain HTTP** - the store of every Secret; reachability is the whole report.
- **Shared ingress with `Host`-only tenant routing** - swapping `Host` crosses a tenant boundary
  the app assumed the network enforced.
- **A web-app LFI/SSRF that reaches the projected SA-token path** - the app becomes the cluster
  foothold; the audience claim decides whether it is Critical or noise.
- **A version-gated control-plane CVE** (CVE-2018-1002105 API proxy, IngressNightmare
  CVE-2025-1974 on an exposed admission controller, Leaky Vessels CVE-2024-21626 runc) - fingerprint
  and hand to `zp-cve`.

---

## Pitfalls

- **Reading a `200` as access.** The API server returns `200` with an RBAC-filtered empty list to
  anyone. Read `items`, not the status code.
- **Calling a 10255 hit "kubelet RCE".** The read-only port has no `exec`/`run`. It is disclosure.
- **Running `/run`, `/exec`, `kubectl exec`, or `kubeletctl scan rce`** against a live target -
  that is exploitation past ZeroProtocol's stop point. A `/pods` read is the proof.
- **Dumping etcd keys** to "show the Secrets". Reachability of `/version` is the finding.
- **Replaying a recovered SA token**, or POSTing SelfSubjectAccessReview loops - decode offline,
  report retrievability.
- **Creating a Pod, ephemeral container, or namespace** for a PoC. Never create workloads.
- **Reporting the dashboard login shell** as unauthenticated access.
- **Treating a `gitVersion` string as a bug** rather than a `zp-cve` lead.
- **Testing a K8s port on an out-of-scope or shared-infrastructure host** just because it appeared
  in recon. Re-run `zp-scope check` for every new host and IP.

---

## Hand off to

Metadata-credential pivot, object storage, container registry, Docker API (`2375`) exposure ->
`zp-cloud`. SSRF that reaches a metadata endpoint, docker.sock or an internal admission webhook ->
`zp-ssrf`. Version-gated control-plane and runc CVEs -> `zp-cve`. Read-only kubelet metrics and
banner leakage -> `zp-info-disclosure`. LFI/SSRF that recovered the SA token -> `zp-xxe-lfi`,
`zp-ssrf`. Exposed CI, Helm/Tiller and pipeline surface -> `zp-cicd`. Ports still to enumerate ->
`zp-recon-active`. New hostname or IP in any response -> `zp-scope` before touching it. Confirmed
exposure -> `zp-triage` then `zp-report`.
