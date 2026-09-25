---
name: zeroprotocol
description: ZeroProtocol - the unified authorized bug-bounty and web-security hunting protocol. Use whenever a target is handed over to test, hunt, recon, map, or audit (a URL, domain, wildcard, program handle, IP, APK/IPA, or source repo), or when the user says "hunt", "bug bounty", "find vulnerabilities", "recon this", "pentest this", "check this target", "what's the attack surface", "ZeroProtocol", or asks to install/set up ZeroProtocol. Owns the phase pipeline (scope gate -> passive recon -> surface map -> ranked class hunt -> proof -> triage -> report), routes to its thirty-five zp-* skills, and enforces the authorization gate that keeps every packet inside a human-confirmed scope. Also fires when resuming a prior engagement or when asked which ZeroProtocol skill applies.
---

# ZeroProtocol

One protocol over thirty-five focused skills. You are handed a target; you return
reproduced, in-scope, impact-bearing findings written the way a triager wants to read
them - or you return an honest, evidenced "nothing here", which is also a result.

ZeroProtocol is for **authorized testing only**: a bug bounty program you are enrolled
in, an engagement with a signed scope, or an asset you own. The gate in Phase 1 is not
paperwork, it is the thing that makes the rest of this legal.

---

## The three laws

**1. No packet leaves without a confirmed scope.**
`zp-scope` is a program, not a promise. Every skill that sends traffic runs
`zp-scope check <target>` and obeys the exit code. Exit 0 or you do not send it. When
the scope file is missing or unconfirmed you may still run **passive** recon, because
passive recon queries third parties, not the target.

**2. No theoretical bugs.**
The only question that matters: *can an attacker do this right now, against a real user
who has taken no unusual action, and does it cause real harm?* "Could theoretically",
"an attacker with X, Y and Z", "wrong but harmless", dead code, source maps without
secrets, DNS-only SSRF callbacks, lone open redirects - all killed on sight. A weak
report costs your signal, and signal is the only currency you have.

**3. Evidence before claim.**
Nothing is "confirmed" until it is reproduced, and High/Critical needs two independent
stacks (curl plus a proxy, or python `requests` plus a raw socket). Redaction happens
when the evidence is captured, never as cleanup afterwards.

---

## Pipeline

Phases are **non-linear**. Stuck at N, go back to N-1: a WAF at hunt time sends you
back to recon for an origin IP; a new endpoint found while hunting sends you back to
mapping. The numbering is the order of first traversal and the order the gates fire.

| # | Phase | Skill | Gate to enter | Artifact it must leave |
|---|---|---|---|---|
| 0 | Engagement setup | this skill | none | `.zeroprotocol/notes.md` with mode + objective |
| 1 | Scope + authorization | `zp-scope` | none | `scope.yaml` with `confirmed: true` |
| 1b | Toolchain survey | `zp-toolchain` | none | known capability set, fallbacks chosen |
| 1c | Browser | `zp-browser` | none to install; scope-gated to navigate | a JS engine, or an honest `no browser` record |
| 2 | Passive recon | `zp-recon-passive` | scope file exists (confirmation not required) | `surface/hosts.txt`, `surface/urls.txt` |
| 3 | Active recon | `zp-recon-active` | **scope confirmed** | `surface/live.jsonl`, `surface/tech.md` |
| 3b | Content + parameter discovery | `zp-content-discovery` | scope confirmed | `surface/endpoints.txt` |
| 3c | Client-side asset mining | `zp-js-secrets` | scope confirmed | `surface/js-findings.md` |
| 4 | Rank the surface | this skill | phase 3 artifacts exist | `queue.md` ranked P1/P2 |
| 5 | Class hunt | the hunter skills (dispatch table below) | ranked queue exists | `coverage/<host>/<class>.json` |
| 6 | Prove | this skill + the hunter | a PASS signal | `evidence/`, second-stack repro |
| 7 | Triage | `zp-triage` | a proven finding | verdict PASS/KILL/DOWNGRADE/CHAIN |
| 8 | Report | `zp-report` | triage PASS | `findings/NNN-slug.md` |

**Gate discipline:** do not load a hunter skill before `queue.md` exists. The one
exception is the user handing you a single endpoint and a single class - then say out
loud that you are skipping the recon gate, and log it in `notes.md`.

---

## Phase 0 - engagement setup

Before the first request, in the current directory:

```bash
zp-init            # or, by hand:
mkdir -p .zeroprotocol/{surface,coverage,evidence,findings}
```

Write line 1 of `.zeroprotocol/notes.md`: the **mode**, because the same behaviour is a
payable finding in one mode and noise in another.

| Mode | Tell in the request | What counts as a finding |
|---|---|---|
| bug bounty | "in scope", "out of scope", "safe harbor", a program URL | reproducible impact only; hygiene is noise |
| pentest / WAPT | "PCI", "HIPAA", "remediation timeline", an asset list | impact **and** hygiene, mapped to a standard |
| own asset / audit | "my app", "our staging", a repo path | anything actionable, including hardening |

If the request does not tell you, **ask once**, then stop. Mixed signals default to bug
bounty discipline: it is the strictest, and you can relax a claim later but you cannot
un-submit a bad report.

Then declare the objective in one line - *"today I target <feature> to reach
<ATO | RCE | mass exfil | tenant break | payment manipulation>"* - and pick **one or
two** vuln classes. "Just looking around" is the most expensive mode there is.

### Priors - two minutes that reshape the session

```bash
zp-intel program <handle>      # what actually gets found and paid on this program
zp-intel class <class>         # how accepted reports of a class were framed
```

A class that appears repeatedly in a program's disclosures means the codebase has a *pattern* of
it - hunt the siblings nobody reported, and check whether shipped fixes still hold. A bypass of a
deployed fix is a new bug and never a duplicate. See `zp-intel`.

### Budget

Allocate before recon starts, or recon will eat the engagement:

| Engagement shape | Recon | Hunt | Prove + report |
|---|---|---|---|
| Defined-scope SaaS bounty | 10% | 70% | 20% |
| Wide wildcard / external | 40% | 30% | 30% |
| Asset list handed to you | 0% | 60% | 40% |
| Single product, deep | 5% | 50% | 45% |

Half your time in recon on a defined-scope program is procrastination. Ten percent of a
wildcard engagement in recon and you have already lost - there the surface map *is* the
deliverable.

---

## Phase 1 - the gate

Load **`zp-scope`**. It ends with `scope.yaml` and `confirmed: true`, or it ends the
engagement. Summary of the contract every other skill depends on:

```bash
zp-scope check https://api.target.com/v1/users   # 0 allow, 1 deny, 3 unconfirmed, 4 no file
```

| Exit | Meaning | What you do |
|---|---|---|
| 0 | in scope, human-confirmed | proceed |
| 1 | out of scope | refuse, tell the user which pattern denied it, do not retry |
| 3 | not confirmed yet | passive only; take the user through `zp-scope confirm` |
| 4 | no scope file | stop; run `zp-scope init` |

Never hand-roll this check. Never cache a previous allow for a different host. When you
feed a host list into anything that sends traffic, funnel it:

```bash
cat surface/hosts.txt | zp-scope filter > surface/in-scope.txt
```

---

## Phase 4 - rank the surface

Score every live item, write `queue.md`, and **re-rank after every confirmed capability,
every hard block, and every new recon artifact**.

```
score = class weight + 5 (if it is a parameter) + 55 (if it came from a leaked secret)
class weight:  rce 100 | ato 95 | tenant-break 90 | sqli 85 | ssrf 80 | idor 75
               authz 70 | upload 65 | deser 60 | xss 55 | smuggling 50 | cache 45
               graphql 40 | cors 35 | info-leak 30
```

Buckets: `P1` / `P2` / `blocked` / `chain-pending` / `killed`. A 401 on `/api/admin/` is
a **P1**, not a dead end - it proves the route exists.

Then dispatch in this order:
1. **Surface-probe seeds** - something already looks wrong (wildcard `Access-Control-Allow-Origin` -> `zp-cors`; a reflected `returnTo` -> `zp-authz` + `zp-jwt-oauth`).
2. **Stack signals** - GraphQL endpoint -> `zp-graphql`; file upload -> `zp-upload`; S3 URLs -> `zp-cloud`.
3. **Crown-jewel proximity** - tenant boundary, billing, admin delegation, file ingestion, OAuth callback, password reset.
4. **Default sequence** - the table below, top to bottom.

---

## Phase 5 - dispatch table

| Signal on the surface | Skill |
|---|---|
| reflected input, any sink | `zp-xss` |
| any parameter reaching a datastore | `zp-sqli` |
| template syntax reflected, shell-ish params, `eval`-ish behaviour | `zp-rce-ssti` |
| XML/SVG/DOCX accepted, or a file path in a parameter | `zp-xxe-lfi` |
| any upload endpoint | `zp-upload` |
| numeric/UUID object ids in path, body, or JSON | `zp-idor` |
| role-gated routes, admin paths, 401/403 that vary | `zp-authz` |
| JWT, OAuth callback, SAML, SSO, reset token | `zp-jwt-oauth` |
| URL-valued parameter, webhook, importer, PDF/screenshot renderer | `zp-ssrf` |
| CDN or reverse proxy in front (`cf-ray`, `x-cache`, `via`) | `zp-smuggling`, `zp-cache-poison` |
| coupons, balances, limits, invites, concurrent state | `zp-race` |
| `/api/`, Swagger, OpenAPI, versioned routes | `zp-api` |
| `/graphql`, `__schema`, Apollo | `zp-graphql` |
| any `Access-Control-Allow-*` header | `zp-cors` |
| dangling CNAME, vendor 404, unclaimed bucket | `zp-takeover` |
| a URL-valued parameter that redirects (next, returnTo, callback, dest) | `zp-open-redirect` |
| two components read the same value - parser, normalizer, validator vs sink | `zp-semantic-confusion` |
| a 500 leaks a path, /actuator answers, or login replies differ for real vs fake accounts | `zp-info-disclosure` |
| a 101 Switching Protocols, `new WebSocket`, or socket.io | `zp-websocket` |
| cloud metadata reachable, bucket URLs, IAM artifacts | `zp-cloud` |
| an APK/IPA in scope | `zp-mobile` |
| a contract address or chain asset in scope | `zp-web3` |
| source in hand | `zp-code-audit` |
| chatbot, AI assistant, AI search, summarise/translate feature, RAG pipeline | `zp-llm` |
| the AI can call tools, install plugins/MCP servers, keep memory, or delegate | `zp-agentic` |
| checkout, payments, refunds, subscriptions, quotas, invites, approvals | `zp-business-logic` |
| Node/Express/Next/SPA target, JSON merge or clone, query-string-to-object parsing | `zp-proto-pollution` |
| a proxy is running, or a captured traffic corpus exists | `zp-proxy` |
| a client-side class needs execution proof, or a route only exists after JS | `zp-browser` |
| a version banner, dependency manifest, or an edge appliance is fingerprinted | `zp-cve` |
| cPanel/WHM exposed (ports 2082/2083/2086/2087, `cpsrvd`, `whostmgrsession`) | `zp-cve-2026-41940` |
| LightRAG / `lightrag-hku` server (port 9621, `LightRAG Server API`), or any self-hosted RAG/LLM API server | `zp-cve-lightrag` |

## Agents

Five agents ship with the pack, for when a phase is worth running in its own context. Use them
when the work is wide (many sources, many hosts, many classes) or when a finding needs an
independent second opinion; do the work inline when it is one host and one question.

| Agent | Use it for | Gate |
|---|---|---|
| `zp-recon-sweep` | passive fan-out across sources, one root domain | none - sends nothing to the target |
| `zp-surface-probe` | live-probe and rank **one** host | checks `zp-scope` itself |
| `zp-class-hunter` | **one** class against **one** host, isolated context | checks `zp-scope` itself |
| `zp-verifier` | adversarially refute a candidate finding | read-only on the target |
| `zp-report-drafter` | turn a verified finding into a draft | **no network tools at all** |

Parallelism that pays: one `zp-class-hunter` per (host, class) pair off the ranked queue, and one
`zp-verifier` per candidate finding. Keep each invocation to a single host and a single class -
that is what makes the coverage records honest.

**Every dispatch must carry the rules of engagement.** A subagent inherits none of this session's
context: paste the rate limit, the attribution header with its real value, the excluded classes and
the target into the prompt. The agents re-check `zp-scope` themselves as a backstop, but the
backstop is not the plan.

`zp-verifier` runs **before** `zp-report-drafter`, always. Its default verdict is REFUTED when
uncertain, which is the correct bias - a false positive costs signal with the program.

---

**Depth floor per dispatched class.** Before you may write the word *exhausted*: build
the variant matrix `method x content-type x auth-state x encoding x transport` first,
send a benign and a known-bad baseline to calibrate, walk the encoding ladder (raw ->
url -> double-url -> unicode -> html-entity -> mixed case) and then **stack** encodings,
rotate auth states (unauth / user A / user B / admin / expired / cross-tenant), and
replay every partially-firing payload on sibling endpoints under the same router.
Minimum 25 distinct attempts and 3 encoding steps on a P1 surface. A single payload is
never a verdict, in either direction.

**On every confirmed bug, sweep the siblings before writing anything.** A confirmed bug
proves the developer made a *class* of mistake: walk adjacent HTTP methods, adjacent
route segments, alphabetically adjacent GraphQL operations, and paired action names
(enable/disable, lock/unlock, reset/verify). Budget 20-30 minutes. A large share of paid
access-control bugs are sibling bugs found this way.

**On every PASS, search for the chain.** Name the capability gained - read, write,
execute, or control - and try at least three next links or twenty minutes, whichever
ends first. Feeder classes (open redirect, CORS, info disclosure, CSRF, takeover, XXE,
upload, race, business logic) are **not submitted atomically**: for those the chain *is*
the report.

---

## Phase 6 - prove

```
target · identity used · UTC timestamp · scope context
sanitised request AND response · expected vs observed · the negative control
side effects and cleanup performed · tool versions
```

Redact cookies, tokens and any other user's PII at capture time. Keep trace ids, request
ids, your own test account id, and response shapes - triagers need those.

Client-side classes (reflected/stored/DOM XSS, prototype pollution, postMessage, DOM
clobbering) need **browser verification**: a curl reflection is not execution. Use a DOM
marker, not `alert()`.

Quality gates on your own output, before you believe yourself:

```bash
grep -q "$MARKER" baseline.html && echo "FAIL: marker appears in the baseline, pick another"
diff <(curl -s "$BASE") <(curl -s "$BYPASS") >/dev/null && echo "IDENTICAL - not a bypass"
# timing claims need >=10 interleaved samples and a 2-sigma separation, not one slow response
```

---

## Phase 7-8 - triage and report

`zp-triage` runs the kill gate and returns PASS / KILL / DOWNGRADE / CHAIN-REQUIRED.
`zp-report` writes it. Thirty seconds to kill a lead, thirty minutes to write a report -
so always triage first.

**Never submit anything automatically.** A human approves every submission, every time.

---

## Workspace

```
.zeroprotocol/
  scope.yaml                    the gate - the only source of truth for what may be touched
  notes.md                      mode, objective, budget, session log, next command
  queue.md                      ranked surface: P1 / P2 / blocked / chain-pending / killed
  surface/hosts.txt urls.txt live.jsonl endpoints.txt tech.md js-findings.md
  coverage/<host>/<class>.json  attempts, variants, encodings, blocker, not-applicable reasons
  evidence/<host>/<class>/      requests, responses, screenshots - redacted at capture
  findings/NNN-slug.md          one file per finding, report-shaped from the start
  submissions.md                what was sent where, and the outcome
```

Files, not memory. A long session drifts; a file does not. Write as you go, not at the
end - and on resume read `notes.md` and `queue.md` **first**, before touching the target.

---

## Stop conditions

Do not summarise, and do not claim completion, while any of these is true:

- a live host is unranked, or a P1 host has no surface artifacts
- a dispatched class has no `coverage/` record, and no `not-applicable: <reason>` that cites actual surface evidence
- a dispatched class recorded fewer than 25 attempts, or is missing its differential evidence
- `chain-pending` is non-empty
- a confirmed finding has no second-stack reproduction
- the budget is unspent and the queue still has P1 items

When the gate fails, name the failing condition, go back to that host and class, and
re-check. If the same condition fails three times, stop and tell the user what is
blocking - do not paper over it.

Honest outcomes, in order of frequency: *nothing exploitable found, here is the coverage
map*; *one finding, reproduced and reported*; *a chain*. The first is the most common
result in real bug bounty work and is a perfectly good answer.

---

## Memory

On the first run in a new project, seed the ZeroProtocol operating notes into your memory
directory so the discipline survives the session: the three laws, the gate exit codes,
the workspace layout, and this project's program priors. Thereafter record what the
platform actually paid for and what came back N/A or duplicate - class priors are the
part of hunting that genuinely compounds. `memory/` in the ZeroProtocol repo holds the
seed notes; `zp-memory-seed` copies them in.

---

## Never

- Send a packet to a host that `zp-scope check` did not clear.
- Test a class the program excludes (DoS, volumetric, social engineering, physical, spam).
- Use a real user's data as your proof. Register two of your own accounts instead.
- Exfiltrate more than the minimum that proves the issue - one record, not the table.
- Leave a shell, a file, a user, or a webhook behind. Clean up and record the cleanup.
- Auto-submit, auto-purge a cache, auto-send mail, or use a credential you found.
- Claim "exhausted" on the strength of one payload, or on an auxiliary tool's silence.

---

## Skill index

**Gate and setup** - `zp-scope`, `zp-toolchain`, `zp-proxy`, `zp-browser`, `zp-intel`
**Recon** - `zp-recon-passive`, `zp-recon-active`, `zp-content-discovery`, `zp-js-secrets`, `zp-takeover`, `zp-info-disclosure`
**Injection** - `zp-xss`, `zp-sqli`, `zp-rce-ssti`, `zp-xxe-lfi`, `zp-upload`, `zp-proto-pollution`
**Access control** - `zp-idor`, `zp-authz`, `zp-jwt-oauth`
**Server-side logic** - `zp-ssrf`, `zp-smuggling`, `zp-cache-poison`, `zp-race`, `zp-business-logic`, `zp-semantic-confusion`
**Interfaces** - `zp-api`, `zp-graphql`, `zp-cors`, `zp-open-redirect`, `zp-websocket`
**Platforms** - `zp-cloud`, `zp-mobile`, `zp-web3`, `zp-code-audit`
**AI systems** - `zp-llm`, `zp-agentic`
**Known CVEs** - `zp-cve` (the general sweep), `zp-cve-2026-41940` (cPanel/WHM pre-auth bypass), `zp-cve-lightrag` (three
LightRAG advisories: CORS-with-credentials, non-constant-time password compare, unthrottled login)
**Output** - `zp-triage`, `zp-report`
**Agents** - `zp-recon-sweep`, `zp-surface-probe`, `zp-class-hunter`, `zp-verifier`, `zp-report-drafter` (see Agents above)

Known-CVE skills are checks against a *specific* published vulnerability, and they verify
exposure and stop. They never carry a post-exploitation path, however available the access
looks - see `zp-cve-2026-41940` for the reasoning, which applies to every skill of this
shape added later.

The per-class skill shape used throughout this pack (context-to-payload mapping, the unique
numeric canary, confirm-or-kill, high-value targets) descends from `elementalsouls/Claude-BugHunter`
(CC BY 4.0). Full attribution for every source is in `NOTICE.md`.
