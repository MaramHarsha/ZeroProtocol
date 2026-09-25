---
name: zp-code-audit
description: ZeroProtocol whitebox review for bug bounty - finding vulnerabilities in source you can read, then proving them remotely. Use when the target is open source, when a repository or source archive is in scope, when source was recovered via LFI, a source map or an exposed .git, or when a black-box finding needs its root cause and sibling call sites. Grep-first sink hunting, then taint tracing, then a remote PoC - because a code finding without a reachable path is not a bounty finding.
---

# zp-code-audit - source is a map, not a finding

**Phase:** 5 | **Gate:** reading source is **offline** and needs no gate. Proving the finding
against a running instance is **active** - `zp-scope check` exit 0 first.

**The bar that matters:** in a bug bounty, a vulnerable line of code is not a finding. A
*reachable* vulnerable line, demonstrated against the live target, is. Always close the loop:
sink -> reachable route -> remote proof.

---

## Procedure

**1. Orient before grepping.** Twenty minutes here saves hours.

```bash
# how requests enter, and what sits in front of them
ls -d */ ; cat README* 2>/dev/null | head -40
grep -rniE 'route|router|urlpatterns|@(Get|Post|Put|Delete|RequestMapping)|app\.(get|post)' \
  --include='*.js' --include='*.ts' --include='*.py' --include='*.rb' \
  --include='*.php' --include='*.go' --include='*.java' --include='*.cs' . | head -40
# NB: --include takes one fnmatch glob and does NOT expand braces - '*.{js,py}' silently
# matches nothing and the whole sweep returns 0 hits while exiting 0.
# where authorization is supposed to happen
grep -rniE 'middleware|before_action|@PreAuthorize|authorize|requireAuth|isAdmin|can\(|policy' . | head -30
```

Build a route -> handler -> authorization-check table. The bugs are where a row has no check.

**2. Grep for sinks, by language.** Then trace *back* to the entry point.

```bash
# command execution
grep -rnE 'exec\(|execSync|spawn\(|child_process|system\(|popen\(|shell_exec|passthru|`|Runtime\.getRuntime|ProcessBuilder|os/exec|subprocess\.(run|call|Popen)' .
# sql
grep -rnE '(query|execute|raw|exec)\s*\(\s*["'\''`].*\+|f["'\'']SELECT|\.format\(|%\s*\(|String\.format.*SELECT|\$\{.*\}.*(SELECT|INSERT|UPDATE|DELETE)' .
# deserialization
grep -rnE 'pickle\.loads|yaml\.load\(|unserialize\(|ObjectInputStream|BinaryFormatter|Marshal\.load|JSON\.parse.*reviver|node-serialize' .
# template injection
grep -rnE 'render_template_string|Template\(|new Function|eval\(|compile\(|Handlebars\.compile|twig.*createTemplate' .
# file paths
grep -rnE 'open\(|readFile|File\(|include|require\(|sendFile|path\.join\(.*req\.|os\.path\.join\(.*request' .
# ssrf
grep -rnE 'requests\.(get|post)\(|urllib|http\.get|fetch\(|HttpClient|curl_exec|Net::HTTP|axios\.' .
# crypto and randomness
grep -rnE 'Math\.random|rand\(\)|mt_rand|md5\(|sha1\(|DES|ECB|new Random\(' .
```

**3. Trace taint properly.** A sink alone means nothing; the question is whether attacker input
reaches it *without* passing a real check.

```
SOURCE   req.query / req.body / req.params / req.headers / cookies
         request.GET / request.POST / $_GET / $_POST / $_REQUEST / params[]
         a database row that an attacker previously controlled  (second-order - the good stuff)
         a file an attacker uploaded · a webhook payload · a message from a queue
   |
   v  is there validation? is it an allow-list (real) or a deny-list (usually bypassable)?
   v  is it escaped? by the right escaper for the *sink's* context?
   v  is authorization checked on this route, or only on the one next to it?
   |
SINK
```

The three highest-yield questions to ask of every candidate:

- **Is the check on the route or on the object?** Route-level authorization with an id from the
  request body is the standard IDOR shape.
- **Does the deny-list have a gap?** `if ('..' in path)` is defeated by encoding; a regex without
  anchors is defeated by a suffix.
- **Is the escaper matched to the context?** HTML-escaping a value that lands in a JS string, or
  in an attribute without quotes, does nothing.

**4. Language-specific footguns worth a targeted grep.**

| Stack | Look for |
|---|---|
| **PHP** | `extract()`, `$$var`, loose `==` on hashes, `unserialize()` on input, `include $_GET`, `preg_replace` `/e`, type juggling in auth comparisons |
| **Node/TS** | prototype pollution (`Object.assign`, `merge`, `_.set` on user input), `child_process` with a template string, regex DoS, `JSON.parse` on untrusted with a reviver, missing `await` on an auth check |
| **Python** | `yaml.load` without `SafeLoader`, `pickle`, f-string SQL, `subprocess(shell=True)`, Jinja2 `render_template_string`, Django `extra()`/`raw()`, `eval`/`exec` |
| **Java** | `ObjectInputStream`, XXE defaults in `DocumentBuilderFactory`/`SAXParser`, SpEL/OGNL evaluation, JDBC string concatenation, missing `@PreAuthorize` |
| **Go** | `fmt.Sprintf` into SQL, `os/exec` with user args, path traversal via `filepath.Join` without `Clean` checks, missing error handling that skips a check |
| **Ruby** | `Marshal.load`, `YAML.load`, `send(params[:x])`, mass assignment without `strong_parameters`, `constantize` on input |
| **C#/.NET** | `BinaryFormatter`, `XmlSerializer` with type from input, string-concatenated SQL, missing `[Authorize]` |

**5. Read the history - it is the fastest path to a finding.**

```bash
git log --oneline -S 'password' -- . | head
git log --oneline -i -E --grep='security|vuln|CVE|fix.*auth|sanitiz|escape|injection' | head -30
git log -p --all -S 'AKIA' | head -40          # secrets removed from HEAD but still in history
git diff HEAD~50 --stat | tail -20
```

A commit that fixed one call site usually left its siblings alone. A secret deleted in a later
commit is still in the history, and still live if it was never rotated.

**6. Close the loop.** Map every code finding to a live request.

```
sink -> handler -> route -> method + path + parameter -> a curl against the target
```

If you cannot reach it - dead code, an internal-only service, a feature flag that is off - say so,
and either report it as a defence-in-depth note or drop it. Unreachable code is not a bounty
finding, and claiming otherwise reads as a scanner report.

**7. When the source came from the target itself** (recovered via LFI, a source map, or an exposed
`.git`), remember: **the exposure is itself a finding**, often the bigger one. Report that first,
then the bugs it revealed. And read only what you need - do not exfiltrate the tree.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| tainted input reaches a sink, route is reachable, remote PoC works | **confirmed.** Report the PoC, use the source to explain the root cause |
| sink is real but the route requires admin you do not have | report as a privileged-user issue, lower severity, and say the precondition |
| sink is in dead code or behind a disabled flag | **killed** for bounty purposes |
| validation is an allow-list and you cannot bypass it | killed - record the attempts |
| escaper is correct for the context | killed |
| second-order: input stored now, executed later | confirmed if you can demonstrate both halves |
| a secret in git history | check whether it is still valid *without using it*; report the exposure |
| the finding is in a third-party dependency | check whether the target's usage is reachable; report as a dependency issue with the reachable path |
| static tool flagged it, you cannot trace the path | **not a finding yet.** Trace it or drop it |
| you can only show it by reading more source | you need a remote PoC. Keep going |

---

## High-value patterns

- **Route-level authorization with a body-supplied id** - the IDOR generator.
- **One fixed call site, siblings untouched** - find the fix commit, then grep for the same pattern.
- **A deny-list validator** - almost always has an encoding or normalisation gap.
- **Second-order sinks** - a stored value rendered by an admin page or a batch job. Rarely duplicated.
- **Secrets in git history** that were never rotated.
- **An internal service trusting a header** that the edge does not strip -> `zp-authz`.
- **Legacy code paths** kept for an old client, with the old authorization model -> `zp-api`.
- **The default-insecure XML parser** in Java or .NET -> `zp-xxe-lfi`.

---

## Pitfalls

- **Reporting code without a remote PoC.** The defining mistake of whitebox bounty work.
- **Dumping static-analyser output.** Triage it yourself or do not send it.
- **Ignoring reachability.** Most scanner hits are unreachable.
- **Exfiltrating the whole source tree** when you recovered it from the target.
- **Using a credential found in the source or its history.**
- **Missing the escaper-context mismatch** - the subtlest and most common real bug.
- **Reading only HEAD.** The history is where the removed secrets and the half-applied fixes live.
- **Not reporting the source exposure** when that is how you got the code.
- **Auditing a fork or a mirror** that does not match what is deployed. Check the version.

---

## Hand off to

The matching hunter for a remote PoC: `zp-sqli`, `zp-rce-ssti`, `zp-xxe-lfi`, `zp-ssrf`,
`zp-idor`, `zp-authz`, `zp-upload`, `zp-xss`.
Source recovered from the target -> report the exposure via `zp-triage` first.
Secrets in history -> `zp-js-secrets` conventions for validation-without-use.
IaC and cloud config -> `zp-cloud`. Contracts -> `zp-web3`.
