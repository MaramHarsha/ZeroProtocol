---
name: zp-browser
description: ZeroProtocol headless-browser layer for terminal-based agents, built on the agent-browser CLI with Playwright and raw Chromium as fallbacks. Use whenever a finding must be proven in a real browser rather than with curl - reflected, stored or DOM XSS, prototype pollution, postMessage handlers, CORS cross-origin reads, clickjacking, markdown or model-output rendering, SPA routes that only exist after JavaScript runs, and any flow needing a logged-in session. Owns session hygiene, DOM-marker proof and traffic capture.
---

# zp-browser - proving it in a real engine

**Phase:** 1b / continuous | **Gate:** the browser itself is local, but every page you open is a
request to the target. `zp-scope check <url>` must exit 0 before you navigate. Exit 1 refuse ·
3 stop · 4 stop. A redirect to a new host needs its own check before you follow it.

`curl` cannot execute JavaScript, so for a whole family of classes it cannot tell you whether a
bug is real. ZeroProtocol's own rules say browser verification is **mandatory** for client-side
findings - this skill is how that happens from a terminal.

| Class | Why curl is not enough |
|---|---|
| reflected / stored XSS | reflection is not execution |
| DOM XSS | the `#fragment` payload never reaches the server |
| prototype pollution (client) | the gadget runs in the page |
| `postMessage` handlers | needs a second origin sending a real message |
| CORS cross-origin read | the browser is what enforces CORS |
| clickjacking | needs an actual frame |
| LLM output rendering | markdown-image exfil fires on render |
| SPA route discovery | routes exist only after JS builds them |

---

## The tool

**`agent-browser`** (Vercel Labs, Apache-2.0) - a native Rust CLI driving Chrome/Chromium over
CDP, with no Playwright or Puppeteer dependency. It is built for exactly this: accessibility-tree
snapshots with compact `@eN` refs let an agent act on a page in a few hundred tokens instead of
parsing raw HTML.

```bash
npm install -g agent-browser
agent-browser install          # fetches Chrome for Testing, first run only
agent-browser doctor           # verify the install
```

**Do not memorise its flags from this file, and do not copy its skill text into the repo.** The
CLI ships its own always-current documentation - load that at runtime and work from it:

```bash
agent-browser skills get core   # the authoritative workflow guide for the installed version
agent-browser --help            # full command surface
```

The core loop, which is stable:

```bash
agent-browser open <url>      # 1. navigate
agent-browser snapshot -i     # 2. interactive elements only, as @e1 @e2 ... refs
agent-browser click @e3       # 3. act on a ref
agent-browser snapshot -i     # 4. RE-SNAPSHOT - refs go stale the moment the page changes
```

Refs are reassigned on every snapshot and are invalid after any navigation, submit, dynamic
re-render or dialog. Re-snapshot before every ref interaction or you will click the wrong thing.

---

## Session hygiene - read this before running anything in parallel

**The default session is shared.** If two ZeroProtocol agents both use it, one navigates the
other's page out from under it and both sets of refs become garbage.

```bash
agent-browser --session zp-xss-app1 open https://target/
agent-browser --session zp-xss-app1 snapshot -i
agent-browser --session zp-xss-app1 close        # when the class is finished
```

Rules:

- **Every `zp-class-hunter` and `zp-verifier` invocation passes `--session <its own name>`, on every command.** Not just the first.
- Hold **one** session, not several. Each is a separate Chromium at roughly 340 MB.
- `close` when the class is done. An idle browser is reclaimed after a few minutes, but do not rely on that.
- Never share a session between a hunter and its verifier - the verifier must reproduce independently.

---

## Proving execution

**Use a DOM marker, never `alert()`.** Headless browsers suppress dialogs, so `alert` proves
nothing and cannot be screenshotted.

```bash
# payload sets durable, readable state
<img src=x onerror="document.title='zp-xss-91234';document.documentElement.setAttribute('data-zp','91234')">
```

```bash
agent-browser --session s1 open "https://target/search?q=<payload>"
agent-browser --session s1 eval "document.title"                       # expect zp-xss-91234
agent-browser --session s1 eval "document.documentElement.dataset.zp"  # expect 91234
agent-browser --session s1 screenshot
```

For anything multi-line or quote-heavy, pipe it instead of fighting shell quoting:

```bash
cat <<'EOF' | agent-browser --session s1 eval --stdin
({ title: document.title,
   marker: document.documentElement.dataset.zp,
   proto: Object.prototype.zpcanary ?? null,          // zp-proto-pollution
   origin: location.origin })
EOF
```

The screenshot plus the `eval` output is the evidence. Record the browser version - mXSS and
parser bugs are engine-specific.

---

## Traffic capture

`agent-browser` honours `http_proxy` / `https_proxy`, so it flows through whatever capture proxy
`zp-proxy` has running with no extra flags. **Do not pass `--proxy` yourself** when those are
set, and keep `NO_PROXY=localhost,127.0.0.1` so the CDP control channel does not loop back
through the proxy.

Without a proxy, capture directly:

```bash
agent-browser --session s1 network har start
# ... drive the flow ...
agent-browser --session s1 network har stop /tmp/zp-flow.har
agent-browser --session s1 network requests      # what actually fired
```

`network requests` is the cleanest way to prove an **exfiltration** finding: a markdown image
beaconing to your collector (`zp-llm`), a CORS read, or a script loading from a host you control
all show up as a real outbound request rather than a claim.

---

## Fallbacks

Degrade, do not fake. If `agent-browser` is unavailable:

| Fallback | Gets you | Loses |
|---|---|---|
| **Playwright** (`playwright install chromium`, then a short script) | full CDP control, eval, screenshots | the snapshot/ref workflow; more tokens per step |
| **raw Chromium** `--headless --screenshot=out.png --virtual-time-budget=8000 <url>` | a screenshot, `--dump-dom` for post-JS HTML | interaction, eval, multi-step flows |
| **Puppeteer** | same as Playwright | same |
| `lynx` / `w3m` / `links` | nothing useful here | **no JavaScript at all** - never use these to test a client-side class |

The last row matters: a text-mode browser cannot execute JavaScript, so it can neither confirm
nor refute an XSS. If nothing with a JS engine is available, the honest outcome is
`not-applicable: no browser` recorded in the coverage file - **not** a claim that the class is
clean.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| DOM marker present in `eval` output and in the screenshot | **confirmed execution** |
| payload visible in the HTML source but the marker never sets | reflection without execution - killed as XSS |
| marker sets only after you paste into devtools | **self-XSS.** Killed |
| CSP blocks the script and the marker never sets | injection is real, execution is not - report with the CSP caveat or find the bypass |
| `network requests` shows the outbound beacon | confirmed exfiltration |
| cross-origin `fetch` returns the body in a page on your own domain | confirmed CORS data theft |
| frame loads the sensitive page with no `X-Frame-Options`/`frame-ancestors` | clickjacking lead - needs a real sensitive action behind it |
| marker sets but only in your own session with your own data | self-only; state that honestly, severity drops |
| the page needs login and you used the target's real user account | **invalid.** Redo with your own test account |

---

## Never

- Navigate to a host `zp-scope check` did not clear, including via a redirect.
- Log into an account that is not yours. Register your own two test accounts.
- Screenshot another user's data. Redact before attaching anything.
- Leave sessions running, or leave stored payloads in the target - `close`, then clean up.
- Use the same session for a hunt and its independent verification.
- Drive a browser at a target faster than the program's rate limit; page loads are many requests.
- Point the browser at an out-of-scope third party to "test" something.
- Claim a class is clean when no JS engine was available.

---

## Hand off to

Execution proof -> `zp-xss`, `zp-proto-pollution`, `zp-cors`.
Rendered model output and beacons -> `zp-llm`. Traffic corpus and replay -> `zp-proxy`.
SPA routes discovered after JS -> `zp-content-discovery`, `zp-api`.
Authenticated multi-step flows -> `zp-business-logic`, `zp-authz`.
Evidence and screenshots -> `zp-triage`, then `zp-report`.

CLI reference: `vercel-labs/agent-browser` (Apache-2.0). Integration pattern cross-checked against
`usestrix/strix` (Apache-2.0), which drives the same CLI through its shell tool.
