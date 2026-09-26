---
name: zp-agentic
description: ZeroProtocol hunter for AI agent and MCP tool-ecosystem security - effective-authority mapping, confused-deputy behaviour, tool poisoning, side-effect authorization, approval binding, cross-tenant isolation and shadow integrations. Use when a target's AI can select tools, call remote or local services, keep memory, delegate to other agents, or install skills, plugins or MCP servers. Pairs with zp-llm for the instruction attack and with the classic hunters for the downstream sink.
---

# zp-agentic - what the agent is actually allowed to do

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop. Read the program's AI scope: agent infrastructure is often listed separately
from the web app, and sometimes excluded.

`zp-llm` asks whether untrusted text can steer the model. This skill asks the harder question:
**when it does, what authority does it reach?** The bug is rarely the injection. The bug is that
a summariser holds a credential that can send, delete or deploy.

---

## 1. Draw the effective-authority map

Do this before any payload. It is the whole method.

```
user / external content
  -> model context and memory
  -> planner / router / policy
  -> tool or delegated agent
  -> credential and target system
  -> side effect / returned data
```

For each node, record:

- **trust source** and which tenant or user owns it
- **component identity**: server/package name, version, transport
- **capabilities**: tools, resources, prompts, model endpoints, plugins, MCP servers
- **credential identity**: issuer, audience, subject, tenant, scopes, expiry, where it is injected
- **reach**: what it can read, write or execute; test vs production target
- **controls**: argument validation, where authorization happens, where approval happens, audit log
- **feedback**: what returns to the model, and whether it can contain new instructions

Then the comparison that matters: **the user's authority versus the agent credential's
authority.** Test from the lowest-privileged realistic account. Every gap between those two is a
candidate finding.

---

## 2. Tool discovery and argument boundaries

```bash
# what the protocol accepts, versus what the UI exposes. MCP is JSON-RPC 2.0 over ONE
# endpoint - `tools/list` is a method name, never a URL path, and the array is at .result.tools
MH=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'
    -H 'MCP-Protocol-Version: 2025-06-18' -H "Authorization: Bearer $TOK")
SID=$(curl -sk -D - -o /dev/null "$MCP" "${MH[@]}" -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
  "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"zp","version":"1"}}}' \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
curl -sk "$MCP" "${MH[@]}" ${SID:+-H "Mcp-Session-Id: $SID"} \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' > /tmp/zp.mcp
# Streamable HTTP may SSE-frame the reply - take the data payload when it does
grep -q '^data: ' /tmp/zp.mcp && sed -n 's/^data: //p' /tmp/zp.mcp > /tmp/zp.r || cp /tmp/zp.mcp /tmp/zp.r
jq '.result.tools[] | {name, description, inputSchema}' /tmp/zp.r
# same JSON-RPC frames for resources/list and prompts/list; a stdio server takes them on its pipe
```

- A `404`/`405` here usually means you sent REST at a JSON-RPC server, not that the server is
  toolless - only an empty `.result.tools` says that. Some gateways do bolt a REST shim in front;
  treat that shim as a second surface, and compare its list against the protocol's.
- Enumerate advertised **and conditionally available** tools, resources, prompts and schemas.
- Compare the UI's tool list against what the runtime will actually accept directly. Tools the UI
  hides are frequently still callable.
- Fuzz the argument boundary: missing, extra, duplicate, nested, oversized, wrong-type, and
  **cross-tenant identifiers**.
- Validate at the tool boundary, not in the prompt: scheme/host/path, filesystem paths, cloud
  resource ids, recipient identities, query fields, command arguments.
- **Canonicalise tool identity** as `server identity + version + transport + tool name + schema
  digest`. Two identically-named tools from different servers must not collapse into one trust
  decision - that is a real and under-hunted bug class.
- Protocol hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) are
  **untrusted metadata, not authorization**. Test whether the server enforces them.
- Unknown tool names and schema-invalid calls must **fail closed**, not fall back to a broader
  handler.

---

## 3. Confused deputy - the core class

Ask one question of every path: *can untrusted content choose the tool, the target, the identity
or the action?*

| Test | What it proves |
|---|---|
| read-to-write escalation | a summariser that sends/publishes/deletes because retrieved text asked |
| tool selection by content | injected text picks which tool runs |
| argument control by content | injected text picks the recipient, the path, the resource id |
| identity substitution | the agent acts as its service credential rather than as you |
| cross-tenant reach | tenant A's content drives an action in tenant B |

**Prove it at the target and in the audit log.** Model narration is not evidence, and a fabricated
tool result is not a side effect.

---

## 4. Approval binding

A confirmation prompt is only a control if it binds the thing being approved. Test whether
approval covers:

```
server identity + version · tool name · schema digest · normalised arguments
credential · target · side effect · expiry
```

Then test whether those fields can **change after approval and before execution**. A generic
"Continue?" that does not revalidate arguments is a finding on its own.

Also exercise: **replay, retry, parallel calls, partial failure, cancellation, delegated
execution**. Each is a route to a duplicate or unapproved action - and this overlaps `zp-race`,
so use its concurrency discipline (5-20 requests, disposable objects, never real money).

---

## 5. Tool poisoning and supply chain

Tool descriptions, names, examples, resource metadata and returned content are all
**attacker-influenceable** unless provenance is enforced. A malicious MCP server can:

- ship a tool whose *description* contains instructions to the model
- shadow a legitimate tool name from another server
- return content that reads as new instructions to the calling agent
- mutate its schema between listing and invocation

If the target lets users install skills, plugins or MCP servers, that installation path is a
supply-chain surface. Test whether an installed component can reach credentials or tools belonging
to the host or to other users.

---

## 6. Shadow integrations - only on your own estate

Discovery of unapproved agents, local MCP servers and AI credentials is a legitimate part of an
**internal** engagement, and **out of scope for a typical bug bounty**, because it means
inspecting hosts rather than the target application.

Run this only against machines you own or an engagement that authorises host inspection:

```bash
ss -lntp                                     # Linux: loopback MCP/agent listeners
lsof -nP -iTCP -sTCP:LISTEN                  # macOS
rg -l 'mcpServers|modelContextProtocol|OPENAI_API_KEY|ANTHROPIC_API_KEY' <reviewed-roots>
```

A loopback listener is a **lead, not proof** of reachable authority. Correlate to PID, parent
process, binary version, config file, destination and credential reference before calling it an
active agent component.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| untrusted content causes a privileged tool call, verified at the target | **confirmed.** High to Critical by the side effect |
| agent credential reaches data the user cannot reach | **confirmed** privilege gap |
| cross-tenant action driven by another tenant's content | **Critical** |
| approval does not bind arguments; they change before execution | confirmed |
| unknown tool name falls back to a broader handler | confirmed fail-open |
| duplicate side effect via replay/retry/parallel | confirmed -> also `zp-race` |
| tool description contains instructions the model obeys | confirmed tool poisoning |
| two servers' same-named tools share one trust decision | confirmed |
| hint metadata (`readOnlyHint`) trusted as authorization | confirmed |
| model *says* it called a tool, no target-side evidence | **killed until verified** |
| tool exists but is properly authorized at its boundary | killed - record it as tested |
| a local loopback listener with no demonstrated reachable authority | not a finding |
| injection works but every tool is read-only and scoped to you | low - name the real impact or drop it |

---

## High-value patterns

- **A summariser or assistant holding a write-capable credential** - the canonical confused deputy.
- **Agent-to-agent delegation** where the second agent trusts the first's text.
- **Memory that persists across sessions or users** - inject once, fire later, possibly for someone else.
- **An MCP server installable by users** in a multi-tenant product.
- **Tool arguments reaching SQL, shell, filesystem or HTTP** - the classic sinks behind a new front door.
- **Approval UX that shows a summary but executes the raw arguments.**
- **A service credential shared across tenants** because the agent runs server-side.

---

## Pitfalls

- **Testing the prompt and calling it done.** The authority map is the work.
- **Accepting model narration as proof.** Verify at the target system and the audit log.
- **Inspecting hosts during a bug bounty.** Shadow-integration discovery needs host authorization.
- **Triggering real side effects** - sent mail, real purchases, deleted records, deployments. Use disposable objects you own, and prefer a read-only privileged call as proof.
- **Installing a malicious MCP server on shared infrastructure.** Your own tenant only.
- **Treating a loopback listener as a finding.**
- **Leaving an installed component, memory entry or webhook behind.** Remove it and say so.
- **Reporting "the agent has broad permissions"** with no demonstrated crossing. Show the gap being used.

---

## Hand off to

The instruction attack -> `zp-llm`. Tool arguments reaching a datastore or shell -> `zp-sqli`,
`zp-rce-ssti`. Agent-fetched URLs -> `zp-ssrf`. Cross-tenant object reach -> `zp-idor`,
`zp-authz`. Duplicate side effects -> `zp-race`. Agent output rendered -> `zp-xss`.
Credentials the agent holds -> `zp-cloud` for blast radius only, never used.
Confirmed -> `zp-triage`, `zp-report`.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `agentic_system_security`.
