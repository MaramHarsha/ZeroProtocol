---
name: zp-captcha
description: ZeroProtocol hunter for CAPTCHA and anti-automation control failure - the response omitted or empty and still accepted, a solved token replayed, a token bound to neither session nor action, a challenge on the UI path but absent from the API or mobile path, vendor sandbox keys left in production, and races in token consumption. Use when a login, signup, reset, OTP-send or search endpoint shows a challenge. Proves the control is absent and never exercises what it protected.
---

# zp-captcha - proving the gate is not there

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

The finding here is never "I got past the checkbox". It is "the control meant to make this action expensive
does not exist, and here is what that costs" - accounts minted at will, unlimited password attempts, a
scrapable price book, an SMS bill the target pays. A real report names the **protected action**, shows it
completing with **no valid response**, and shows **no other control caught it**.

## Procedure

**1. Read the provider and the exact field name off the page** - a probe aimed at a remembered field name silently tests nothing.

```bash
H=target.tld; curl -sk "https://$H/signup" -o page.html
grep -oiE '(recaptcha|hcaptcha|turnstile|arkoselabs|funcaptcha|geetest|friendlycaptcha|mtcaptcha|awswaf)[a-z./-]*' page.html | sort -u
grep -oE 'name="[a-z_-]*captcha[a-z_-]*"|(data-sitekey|sitekey|site_key|render)=.?[A-Za-z0-9_-]{16,}' page.html js/*.js 2>/dev/null | sort -u
```

| Provider | Response field | Server verifies at |
|---|---|---|
| reCAPTCHA v2/v3 | `g-recaptcha-response` | `www.google.com/recaptcha/api/siteverify` |
| hCaptcha | `h-captcha-response` | `api.hcaptcha.com/siteverify` |
| Cloudflare Turnstile | `cf-turnstile-response` | `challenges.cloudflare.com/turnstile/v0/siteverify` |
| Arkose, GeeTest, MTCaptcha | vendor-specific - read the form | vendor endpoint |
| self-hosted | usually `captcha` plus `captcha_id` | in-process, and that is where the bugs live |

**2. Diff the sitekey against the vendors' published test keys - offline, zero requests.** Google's
`6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`, hCaptcha's `10000000-ffff-ffff-ffff-000000000001` and
Turnstile's `1x00000000000000000000AA` / `1x00000000000000000000BB` (always pass),
`2x00000000000000000000AB` / `2x00000000000000000000BB` (always **block**) and
`3x00000000000000000000FF` (forces an interactive challenge) are the vendors' sandbox **sitekeys**.

One in production is a **lead, not the finding**. The sitekey is client-side; the verdict belongs to the
**secret** on the server, so a dummy sitekey can sit in front of a real secret and every token then fails -
and an always-block key breaks the form rather than opening it. It tells you which secret to suspect, and
step 3 is still what confirms. Only the always-pass dummy *secrets* make verification a no-op: Turnstile
`1x0000000000000000000000000000000AA`, hCaptcha `0x0000000000000000000000000000000000000000`, Google
`6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe`. Turnstile's `2x0000000000000000000000000000000AA` is the
always-*fail* secret and rejects everything.

**3. Baseline, then the omission ladder.** Solve the challenge once yourself in `zp-browser`, keep the
wire copy (`zp-proxy`), submit it, and **confirm the state actually changed** - without that baseline every status code below is unreadable.

```bash
EP="https://$H/api/signup"; F=g-recaptcha-response
BODY='email=zp+a1@example.com&password=Zp-Probe-9134'
probe(){ printf '%-28s ' "$1"; curl -sk -o /tmp/zp.body -w '%{http_code}  %{time_total}s\n' \
  -X POST "$EP" -H 'Content-Type: application/x-www-form-urlencoded' --data-raw "$BODY$2"; }
probe "field omitted"          ""
probe "empty, then 0/true/null" "&$F="
probe "random, right shape"    "&$F=$(head -c 400 /dev/urandom | base64 -w0 | tr -d '=+/')"
# vendor dummy response - only the one matching the field you read in step 1 means anything:
#   h-captcha-response    -> hCaptcha's test passcode        cf-turnstile-response -> XXXX.DUMMY.TOKEN.XXXX
#   g-recaptcha-response  -> no analogue; Google's test secret accepts *any* token, so the random probe
#                            above already is the sandbox-secret test
case $F in
  h-captcha-response)    D=10000000-aaaa-bbbb-cccc-000000000001 ;;
  cf-turnstile-response) D=XXXX.DUMMY.TOKEN.XXXX ;;
  *)                     D= ;;
esac
[ -n "$D" ] && probe "vendor dummy response" "&$F=$D"
```

Read `time_total` beside the code - a real `siteverify` is an outbound TLS round trip, typically 80-400 ms,
so a garbage token answered as fast as an omitted one was never verified server-side. Then re-read the
resource, because a `200` that created nothing is not a bypass.

**4. The binding ladder.** reCAPTCHA tokens expire after **two minutes**; outside that window a
failure tells you nothing.

```bash
TOK=$(cat token.txt)                        # one response you solved by hand, < 120 s old
S1="session=$SESS_A"; S2="session=$SESS_B"  # two accounts you own
send(){ printf '%-22s ' "$1"; shift; curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$@"; }
send "1st use (baseline)"   "$EP" -H "Cookie: $S1" -d "$BODY&$F=$TOK"
send "replay, same session" "$EP" -H "Cookie: $S1" -d "$BODY&$F=$TOK"
send "other session"        "$EP" -H "Cookie: $S2" -d "$BODY&$F=$TOK"
send "other action" "https://$H/api/password/forgot" -H "Cookie: $S1" -d "email=zp+a1@example.com&$F=$TOK"
```

Twice accepted means single-use is unenforced. Accepted on another action means the server asked "is this
a real solution?" and never "is it *this* action's solution?" - for reCAPTCHA v3 that is the verify
response's `action` going unread, and for every provider its `hostname` too.

**5. The path ladder - where this class actually pays.** Your **own** account and its **correct** password,
so the challenge is the only variable; then the SPA's real GraphQL mutation with no captcha argument.

```bash
for p in /login /api/login /api/v1/login /api/v2/login /mobile/login /auth/token; do
  printf '%-18s ' "$p"; curl -sk -o /dev/null -w '%{http_code}\n' -X POST "https://$H$p" \
    -H 'Content-Type: application/json' --data-raw "{\"email\":\"$ME\",\"password\":\"$MY_PW\"}"
done
```

**6. Self-hosted challenges - the answer is usually in what the server already sent.**

```bash
curl -sk -D cap.hdr "https://$H/captcha?id=1" -o cap.bin
grep -iE 'captcha|answer|set-cookie' cap.hdr | tr -d '\r'; file cap.bin; strings cap.bin | head
for i in $(seq 1 10); do curl -sk "https://$H/captcha?id=$i" | md5sum; done | sort | uniq -c
```

A reusable `captcha_id`, a finite or seeded answer set, or the answer in image metadata, a cookie or a hidden input is the same bug as no challenge at all.

**7. Reactive challenges (shown only after N failures) - bounded, and this is the line.** Your **own**
account, **one fixed deliberately-wrong literal**, a hard cap. The loop finds the threshold, never a password.

```bash
for i in $(seq 1 6); do
  r=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "https://$H/api/login" \
      -H 'Content-Type: application/json' --data-raw "{\"email\":\"$ME\",\"password\":\"wrong-on-purpose\"}")
  echo "attempt $i -> $r"; case $r in 429|403) echo "control engaged at $i"; break;; esac
done
```

**Never** swap that literal for a wordlist, that address for another user's, or that cap for a bigger one.
Challenge appears at attempt N - you have the number, stop. Whether the counter is client-keyed is **one**
further request with a fresh cookie jar, not a second loop.

**8. Races in consumption** - validated, then consumed after slow downstream work. **Two** concurrent
requests, on a disposable object you own. Where you can, race a write you already hold - an
idempotency-protected update - rather than signup, which also sends mail. If the token is only consumed
at signup, two accounts is the ceiling: delete both and say so.

```bash
python3 - <<'PY'
import urllib.request as u, urllib.error, concurrent.futures as cf
EP, TOK = "https://target.tld/api/signup", "<one freshly solved token>"
def fire(i):
    b = f"email=zp+r{i}@example.com&password=Zp-Probe-9134&g-recaptcha-response={TOK}".encode()
    try: return u.urlopen(u.Request(EP, b, {"Content-Type": "application/x-www-form-urlencoded"}), timeout=20).status
    except urllib.error.HTTPError as e: return e.code
with cf.ThreadPoolExecutor(2) as x: print(sorted(x.map(fire, range(2))))   # two, never more
PY
```

**9. Show nothing else caught it.** This separates Medium from High, and is the only place any volume is
allowed - twelve requests at the program's own rate, on a harmless read. Twelve, not twelve hundred; if the
program's rules forbid even that, say so and cap your severity.

```bash
RPS=$(zp-scope show --json | jq -r '.rate_limit_rps // 5')
for i in $(seq 1 12); do
  curl -sk -o /dev/null -D - "https://$H/api/search?q=zp$i" \
    | grep -iE '^(HTTP/|retry-after|x-ratelimit|cf-mitigated|set-cookie: *cf_clearance)' | tr -d '\r'
  sleep "$(python3 -c "print(1/$RPS)")"; done
```

**10. Stop point for this class.** You stop at **one** protected action completing without a valid response,
on your own account or object, using the fewest requests that show it. You do **not** then run the abuse the
control existed to prevent - no credential guessing from any list, no farming past the one or two disposables
you will delete, no scraping loop, no repeat sends on anything that mails, texts or bills. Delete what you
created and say so.

## Probes and payloads

| Probe | Tests | Positive looks like |
|---|---|---|
| response field deleted from the body; then `=` empty, `0`, `true`, `null`, random base64 of the right length | verification absent entirely, then presence checked but content not | baseline status **and** the state changed, with no verify latency |
| the vendor's own dummy response, matched to the field (hCaptcha `10000000-aaaa-bbbb-cccc-000000000001`, Turnstile `XXXX.DUMMY.TOKEN.XXXX`; reCAPTCHA has none) | production secret is the vendor's always-pass sandbox secret | accepted |
| sandbox sitekey in the page (step 2), or one solved token sent twice inside 120 s | which secret to suspect; single-use unenforced | offline string match - a lead step 3 must confirm; both accepted |
| token used with session B's cookie, or sent to reset / signup / invite | bound to neither session nor action; v3 `action` and `hostname` unread | accepted |
| same action on `/api/*`, `/mobile`, `/graphql`, a legacy version | control on the UI path only | no challenge, action succeeds |
| `captcha_id` re-fetched, 10 images diffed, answer resubmitted | reusable id, finite or seeded answers | duplicates, or answer in metadata |
| 2 concurrent requests sharing one token | consumption happens after the check | more than one success |
| fresh cookie jar after the reactive threshold | counter keyed to client state | the count restarts |

`curl`, `python3` and one browser session cover all of it; a scanner reporting "CAPTCHA missing" produces the first rows of the next table.

## Confirm or kill

| Evidence | Verdict |
|---|---|
| response omitted or garbage, request accepted, protected state **verifiably** changed | **confirmed - no server-side verification.** Medium by default; High only when it is the sole gate on login, OTP-send or paid compute **and** step 9 showed nothing else fires |
| one solved token accepted twice inside its validity window, in another session, or on another action | confirmed - single-use unenforced, or the token is unbound. Same ceiling; name both endpoints |
| UI path challenges, API / mobile / GraphQL path does not | confirmed, and the most commonly accepted shape. Severity from that endpoint's action |
| an always-pass sandbox **secret** live in production - leaked in a bundle, or proved by step 3 | confirmed - treat as no verification at all, and it is a one-line fix |
| a sandbox **sitekey** in the page and nothing else | a lead, not a finding. Confirm with step 3 - the server's secret decides the verdict |
| custom answer recoverable from the response, a cookie, image metadata or a finite set | confirmed. Medium - a design flaw, not a config slip |
| two concurrent requests both consume one token | confirmed race - take the write-up shape from `zp-race` |
| **you solved the challenge** - by hand, OCR, the audio track, or a paid solving service | **not a bypass. The control worked.** Killed, and a solving service is outside ZeroProtocol anyway - it proves nothing about the implementation and ships target data to a stranger |
| replay rejected with the provider's `timeout-or-duplicate` | the control is working. Killed - and check the token was under 120 s old before believing any first-use failure |
| the response was reused inside a vendor clearance window (`cf_clearance`, a short verified flag on the session) | by design. Killed |
| reCAPTCHA v3 accepted a low score, or the threshold looks generous | killed as a bug - the threshold is a product decision. Only *no verification* is reportable |
| `200` returned and nothing was created, sent or changed; the action still needs an emailed confirmation, a payment or a value you do not hold; or an edge challenge (WAF, managed challenge) still stops volume from a clean IP with no cookies | killed - you proved nothing and must re-read the resource, the challenge was never the gate, or the control lives one layer up (Low at most, and say so) |
| no challenge on a read-only or non-abusable endpoint, none anywhere and none ever claimed, or the program lists CAPTCHA and rate-limit bypass as out of scope or informative - very common | no abuse to name, or none this program will take. Killed - "you should add a CAPTCHA" is a recommendation; file only the concrete downstream abuse, if one exists |

"The CAPTCHA was bypassed" is not impact. "`POST /api/v1/users` performs no verification, so one host can
mint accounts that send mail signed by your domain" is. Dedup is brutal here - run `zp-intel dedup <program>
captcha <endpoint>` before writing a word.

## High-value patterns

- **Login** - the challenge is often the only anti-automation control, so its absence is the credential-stuffing gate removed. Prove the absence, never the stuffing.
- **Signup and invite** - account farming, then spam and phishing carrying the target's domain reputation; the same for contact, support and share-by-email forms, which are a mail relay inside the target's SPF record.
- **Password reset, OTP send and every "resend" button** - per-message cost the target pays, the classic SMS-pumping bill. Two requests to your own address is the whole proof.
- **AI inference, export, conversion and render endpoints** - per-request compute billed to the target with the challenge as the only quota. Route to `zp-llm`.
- **Price, availability, balance and gift-card lookups** - scraping and enumeration are the real product loss, and usually the program's own stated concern.
- **A legacy or mobile API kept for old clients**, and **the GraphQL mutation behind a protected REST form** - the challenge was added to the page, not the operation; likewise a challenge added after an earlier report, which usually lands only on the path that was reported. Re-test the siblings.

## Pitfalls

- **Solving the challenge and calling it a bypass.** You proved the control works.
- **Exercising what the control protected.** A wordlist, a farming loop, a scraping run or a repeated SMS send turns a valid report into unauthorized abuse.
- **Unbounded loops on anything that mails, texts, renders or bills.** Two or three, to your own
  address, serially - the only parallel request in this skill is step 8's two-request race.
- **Believing a replay result on an expired token** (two minutes for reCAPTCHA - re-solve and retest), or letting the browser or an invisible-mode widget re-solve during a replay. Diff the wire copy and confirm the field really is absent.
- **Guessing the field name** instead of reading the form, so the probe tests nothing; or testing with a real user's account, email or phone number, or leaving disposable accounts behind.
- **Claiming High without step 9** - if a rate limiter or WAF catches it, the missing challenge changes little - or treating `cf_clearance` reuse, a generous v3 threshold, or "no CAPTCHA here" as bugs.
- **Sweeping a program's whole host list for missing challenges.** Pick login, signup, reset, OTP and the costliest endpoint.

## Hand off to

New host or path -> `zp-scope` first. The one solved challenge and any browser proof -> `zp-browser`; the wire
copy of the real request -> `zp-proxy`. Session and clearance-cookie binding -> `zp-session`; reset, OTP, MFA
and takeover flows -> `zp-jwt-oauth`. Concurrency write-up -> `zp-race`; limits, quotas and trials ->
`zp-business-logic`. The unprotected paths -> `zp-api`, `zp-graphql`, `zp-mobile`; versions you
have not found -> `zp-content-discovery`. Sitekeys and leaked vendor secrets in bundles -> `zp-js-secrets`
(a leaked secret verifies tokens, it does not mint them - usually Low, and never use it); user enumeration in
the same response -> `zp-info-disclosure`; billed inference -> `zp-llm`; a self-hosted challenge component
with a version -> `zp-cve`. Then `zp-intel` for dedup, `zp-triage`, `zp-report`.

Class reference: `elementalsouls/Claude-BugHunter` (CC BY 4.0). See `NOTICE.md`.
