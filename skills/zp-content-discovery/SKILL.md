---
name: zp-content-discovery
description: ZeroProtocol phase 3b - find the paths, files, virtual hosts and hidden parameters that are not linked from anywhere. Use when fuzzing directories or files, running ffuf/feroxbuster/gobuster/dirsearch, hunting backup files or exposed config, discovering hidden HTTP parameters with arjun or x8, doing vhost discovery, or building a target-specific wordlist. Requires a confirmed scope, and demands soft-404 calibration before any result is believed.
---

# zp-content-discovery - what is not linked

**Phase:** 3b | **Gate:** **active.** `zp-scope check <host>` must exit 0 before any
request. Exit 1 refuse and name the pattern · 3 scope unconfirmed, stop · 4 no scope file.

The discipline that separates this from noise is **calibration**. An uncalibrated fuzz
against a soft-404 app returns a thousand "findings", none real, and you will spend an hour
proving your own tool wrong.

---

## Procedure

**1. Calibrate the negative first. Always.** Before any wordlist runs, learn what "not
found" looks like on this host.

```bash
H=target.com
for r in zzq1-nope zzq2-nope zzq3-nope; do
  curl -sk -o /tmp/$r.html -w "$r %{http_code} %{size_download}\n" "https://$H/$r"
done
```

| What you see | What it means |
|---|---|
| 404 with a stable small body | clean. Match on codes; `-ac` will behave |
| **200** on all three | soft-404. You must filter by size/words/regex, never by code |
| all three sizes identical | filter that exact size (`-fs`) |
| sizes differ slightly (path echoed) | filter by word or line count (`-fw` / `-fl`), not size |
| 403 on all three | a WAF is answering, not the app. Slow down or find the origin |

**2. Fuzz, rate-limited, with auto-calibration on.**

```bash
RPS=$(zp-scope show --json | jq -r '.rate_limit_rps // 5')
WL=~/.local/share/seclists/Discovery/Web-Content

ffuf -u "https://$H/FUZZ" -w "$WL/raft-medium-directories.txt" \
     -ac -mc 200,201,204,301,302,307,401,403,405,500 \
     -rate "$RPS" -t 10 -timeout 10 -o cd-dirs.json -of json
ffuf -u "https://$H/FUZZ" -w "$WL/raft-medium-files.txt" -ac -rate "$RPS" -e .bak,.old,.zip,.sql,.env,.json,.log,.txt
```

`-ac` (auto-calibrate) is the single most important flag in this skill. Without it every
soft-404 app produces garbage. When `-ac` is not enough, filter explicitly:
`-fs 1234` size, `-fw 57` words, `-fl 12` lines, `-fr 'Not Found'` regex.

**Fallback without ffuf** - slower, works everywhere, and you must calibrate by hand:

```bash
BASE_SIZE=$(curl -sk -o /dev/null -w '%{size_download}' "https://$H/zzq1-nope")
while read -r w; do
  read -r code size < <(curl -sk -o /dev/null -w '%{http_code} %{size_download}' "https://$H/$w")
  [ "$code" != "404" ] && [ "$size" != "$BASE_SIZE" ] && echo "$code $size /$w"
  sleep "$(awk "BEGIN{print 1/$RPS}")"
done < "$WL/raft-small-directories.txt" | tee cd-dirs.txt
```

**3. Recurse deliberately, not blindly.** Recurse into directories that returned 200/301
and look like containers (`/api/`, `/admin/`, `/static/`, `/uploads/`). Depth 2 is usually
enough; depth 4 on a wildcard estate is how you get blocked.

```bash
ffuf -u "https://$H/FUZZ" -w "$WL/raft-medium-directories.txt" -ac -recursion -recursion-depth 2 -rate "$RPS"
```

**4. Build the target's own vocabulary - this beats generic lists.**

```bash
cat surface/urls.txt surface/js.txt 2>/dev/null \
  | grep -oE '[A-Za-z0-9_-]{3,}' | tr 'A-Z' 'a-z' \
  | sort | uniq -c | sort -rn | awk '$1>1{print $2}' > cd-wordlist-target.txt
ffuf -u "https://$H/FUZZ" -w cd-wordlist-target.txt -ac -rate "$RPS"
```

An endpoint named after the company's internal project will never be in SecLists. It will
be in the JS bundle.

**5. Hidden parameters.** Undocumented parameters are where the unguarded code paths are.

```bash
arjun -u "https://$H/api/user" -m GET --stable
x8 -u "https://$H/api/user" -w "$WL/burp-parameter-names.txt" -X GET
# fallback: reflection oracle
for p in $(head -400 "$WL/burp-parameter-names.txt"); do
  curl -sk "https://$H/api/user?$p=zpcanary91234" | grep -q zpcanary91234 && echo "REFLECTS $p"
done
```

Parameters that change behaviour without appearing in the response are the interesting
ones: watch status code, size, and timing, not just reflection.
High-value names: `debug`, `test`, `admin`, `is_admin`, `role`, `user_id`, `id`, `next`,
`redirect`, `url`, `callback`, `file`, `path`, `template`, `format`, `export`, `impersonate`.

**6. Virtual hosts** - one IP, many sites, and the unlisted ones are often unprotected.

```bash
ffuf -u "https://$H/" -H "Host: FUZZ.$H" -w "$WL/../DNS/subdomains-top1million-20000.txt" \
     -ac -rate "$RPS" -fs $(curl -sk -o /dev/null -w '%{size_download}' "https://$H/")
```

**7. Backup and config exposure** - cheap, and occasionally the whole engagement.

```bash
for p in .env .env.production .git/config .git/HEAD .svn/entries .DS_Store \
         config.json appsettings.json wp-config.php.bak web.config.bak \
         backup.zip db.sql dump.sql docker-compose.yml .npmrc .aws/credentials \
         phpinfo.php server-status actuator actuator/env metrics debug/pprof; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$H/$p")
  [ "$code" = "200" ] && echo "200 /$p"
done
```

An exposed `.git/HEAD` means the whole repository is probably retrievable. Confirm
`.git/config` reads as real git config, take that as the finding, and **do not** dump the
tree unless the program asks - the exposure is the bug.

---

## Confirm or kill

| Signal | Verdict |
|---|---|
| 200 with a body distinct from the calibration baseline | real. Verify by hand with curl before it enters the queue |
| 200 with the baseline size | soft-404. Killed |
| 403 on a specific path while siblings 404 | **real and interesting** - the path exists and is protected. P1 for `zp-authz` |
| 401 on an API path | real. P1 |
| 405 Method Not Allowed | the route exists; try the other verbs |
| 301 to a login page | the route exists behind auth |
| identical 200 for every word | you are fuzzing a catch-all SPA route. Fuzz the API prefix instead |
| a hit that disappears on retry | rate limiting or a load-balanced pool. Re-verify before believing |
| `.env` / `.git/config` returning real content | confirmed exposure. Stop reading, capture, report |

**Never report a discovered path as a vulnerability by itself.** `/admin/` returning 401 is
surface, not a finding. The finding is what you do with it.

---

## High-value patterns

- **`/api/v1/` alive after `/api/v3/` shipped** - old authorization model, often no rate limit.
- **`.bak` / `.old` / `~` of a live script** - served as text instead of executed, so source and credentials leak.
- **`actuator/env`, `debug/pprof`, `/server-status`** - framework introspection left on in production.
- **A staging vhost on the production IP** - same data, no WAF, weaker auth.
- **`swagger.json` / `openapi.json`** - hands you the entire API surface; go straight to `zp-api`.
- **An upload directory that lists** - go to `zp-upload`, and check whether other users' files are readable.

---

## Pitfalls

- **Not calibrating.** The cardinal sin here. Everything downstream becomes fiction.
- **Fuzzing `hosts.txt` instead of `in-scope.txt`.**
- **Ignoring the program's rate limit** because the tool has `-t 200`. The program's number wins.
- **Recursing to depth 5** on a wildcard estate and getting the IP blocked for 15 minutes.
- **Reporting 403 paths as access-control findings** without ever bypassing anything.
- **Dumping an exposed `.git`** repository. The exposure is the finding; mass-downloading source is unnecessary and often out of scope.
- **Using a 10 GB wordlist** where the target-derived 400-word list would have found it in a minute.
- **Trusting one hit.** Re-verify by hand; load balancers and caches lie.

---

## Hand off to

Endpoints -> `zp-api`, `zp-graphql`. Parameters -> `zp-xss`, `zp-sqli`, `zp-ssrf`, `zp-idor`.
JS and source maps -> `zp-js-secrets`. Uploads -> `zp-upload`.
401/403 routes -> `zp-authz`. Exposed config or secrets -> `zp-js-secrets` for validation,
then `zp-triage`.
