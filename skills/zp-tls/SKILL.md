---
name: zp-tls
description: ZeroProtocol hunter for TLS and transport-security failures - certificate hostname mismatch, expiry, broken chains, deprecated protocol versions, weak ciphers, HSTS scope and preload semantics, mixed content, mTLS edge-header bypass, and SNI or virtual-host confusion. Use when a scanner dumps TLS output, when a certificate looks wrong, when a service sits behind client certificates, or when judging whether any of it is worth filing. Most of this class is Low or N/A.
---

# zp-tls - the handshake is not the finding

**Phase:** 5 | **Gate:** **active.** `zp-scope check <target>` must exit 0 before any request.
Exit 1 refuse and name the pattern · 3 stop · 4 stop.

Almost every line a TLS scanner prints is hardening advice. The exploit for "TLS 1.0 is enabled" is
an on-path attacker you cannot be, and triage knows it. Three shapes here pay reliably: **mTLS
bypassed with a forged edge header**, **SNI or Host confusion that routes you into an app you were
never meant to reach**, and **a private key you should not be able to read**. Everything else needs
a victim, an action and a capture - or it is a line in your recon appendix.

---

## Procedure

**1. Baseline in one handshake.** `-brief` prints protocol, cipher, peer CN and the verification verdict in ten lines; add `-status` for the OCSP stapling answer.

```bash
H=target.tld; P=443
echo | openssl s_client -connect "$H:$P" -servername "$H" -brief 2>&1 | head -12
echo | openssl s_client -connect "$H:$P" -servername "$H" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

**2. Let the library decide whether the certificate actually fails** - not your eyes.

```bash
echo | openssl s_client -connect "$H:$P" -servername "$H" \
  -verify_hostname "$H" -verify_return_error -brief 2>&1 | grep -iE 'verif|error'
echo | openssl s_client -connect "$H:$P" -servername "$H" -showcerts 2>/dev/null \
  | grep -c 'BEGIN CERTIFICATE'                     # 1 = leaf only, intermediate missing
echo | openssl s_client -connect "$H:$P" -servername "$H" 2>/dev/null \
  | openssl x509 -noout -checkend 604800 >/dev/null \
  && echo "ok: more than 7d left" || echo "EXPIRES within 7d"   # rc 1 = expiring, rc 0 = fine
H=$H python3 -c '                                    # stdlib fallback, no openssl needed
import socket,ssl,os; h=os.environ["H"]
try:
  with socket.create_connection((h,443),10) as s, ssl.create_default_context().wrap_socket(s,server_hostname=h) as t: print("valid",t.version(),t.cipher()[0])
except ssl.SSLCertVerificationError as e: print("CERT VERIFY FAILS ->", e.verify_message or e)'
```

A browser interstitial is the finding here, so confirm it in a real engine (`zp-browser`) first.

**3. Protocols and ciphers - and separate a server refusal from your own client's refusal.** This
is where most TLS reports are silently wrong: OpenSSL 3.x compiles TLS 1.0/1.1 out at the default
security level, so "not supported" may be your machine talking to itself.

```bash
V='Unknown option|no protocols available|no cipher match|alert protocol version|alert handshake failure|New, TLSv[0-9.]+, Cipher is [A-Za-z0-9_-]+'
for v in ssl3 tls1 tls1_1 tls1_2 tls1_3; do printf '%-8s ' "$v"
  echo | openssl s_client -connect "$H:$P" -servername "$H" "-$v" -cipher 'ALL:@SECLEVEL=0' 2>&1 \
    | grep -m1 -oE "$V" || echo '(no match - read the raw output)'; done
for c in NULL EXPORT RC4 DES-CBC3-SHA aNULL SEED; do printf '%-12s ' "$c"   # -no_tls1_3 is mandatory here
  echo | openssl s_client -connect "$H:$P" -servername "$H" -no_tls1_3 -cipher "$c:@SECLEVEL=0" 2>&1 \
    | grep -m1 -oE "$V" || echo '(no match)'; done
```

| Output | Means |
|---|---|
| `Unknown option`, `no protocols available`, `no cipher match` | **your** OpenSSL lacks it - `-ssl3` does not even exist on 3.x. Result void; retest on a build that has it |
| `alert protocol version` (alert 70), `alert handshake failure` | the **server** refused. Genuinely disabled |
| `New, TLSv1.0, Cipher is ECDHE-RSA-DES-CBC3-SHA` | the server negotiated it. Offered, still not exploited |

`-cipher` governs TLS 1.2 and below only, so without `-no_tls1_3` a legacy-cipher probe quietly completes as `TLS_AES_256_GCM_SHA384` and you report a NULL cipher that was never negotiated.

`testssl.sh --fast --warnings batch "$H"`, `sslscan --no-colour "$H:$P"` and `python3 -m sslyze
--json_out out.json "$H:$P"` are better when installed (`zp-toolchain`) - and none turns support into impact.

**4. HSTS - read the three parts, not the header's presence.**

```bash
curl -skI "https://$H/" | grep -i 'strict-transport-security'
curl -sI  "http://$H/"  | grep -iE '^(HTTP/|location:)'          # plaintext entry point
curl -s "https://hstspreload.org/api/v2/status?domain=$H" | jq -r '.status // "unknown"'
# Guessed subdomains are NOT covered by this host's gate - funnel them through it first.
# zp-scope filter exits 3 and emits nothing on an unconfirmed scope, so this fails closed.
for s in $(printf '%s\n' www login auth api id sso pay admin | sed "s/$/.$H/" | zp-scope filter); do
  printf '%-26s ' "$s"
  curl -skI --max-time 8 "https://$s/" 2>/dev/null | grep -i 'strict-transport' || echo "-"; done
```

`max-age=0`, a max-age under a day, or a missing `includeSubDomains` while a session cookie is scoped
to `.$H`, are the only variants worth a sentence - and only next to a plaintext host serving that cookie.

**5. Mixed content - passive is noise, active is a real sink.**

```bash
curl -sk "https://$H/" | grep -oE '(src|href|action)="http://[^"]+' | sort -u
curl -skI "https://$H/" | grep -oiE 'upgrade-insecure-requests|block-all-mixed-content' \
  || echo "no CSP mixed-content directive"
```

Browsers block active mixed content outright, so `<script src="http://...">` is usually a broken page
rather than a bug. The exception that matters is a **first-party** `http://` URL the app fetches
itself - callback, webhook, SDK config, mobile API base - travelling without TLS (`zp-mobile`).

**6. mTLS - is the client certificate actually the authority?**

```bash
echo | openssl s_client -connect "$H:$P" -servername "$H" 2>&1 | grep -A4 -i 'acceptable client'
curl -sk -o /dev/null -w 'baseline %{http_code}\n' "https://$H/internal/api"
for pair in "X-SSL-Client-Verify: SUCCESS|X-SSL-Client-S-DN: CN=zp-canary" \
            "ssl-client-verify: SUCCESS|ssl-client-subject-dn: CN=zp-canary" \
            "X-Client-Verify: SUCCESS|X-Client-DN: CN=zp-canary" \
            "X-Forwarded-Client-Cert: By=spiffe://x;Hash=0;Subject=\"CN=zp-canary\"|X-Zp: 1"; do
  printf '%-28s ' "${pair%%:*}"
  curl -sk -o /dev/null -w '%{http_code}\n' "https://$H/internal/api" -H "${pair%%|*}" -H "${pair##*|}"; done
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /tmp/zp.key -out /tmp/zp.pem \
        -subj "/CN=zp-canary/O=ZeroProtocol" >/dev/null 2>&1
curl -sk --cert /tmp/zp.pem --key /tmp/zp.key -o /dev/null -w 'selfsigned-client %{http_code}\n' "https://$H/internal/api"
```

An accepted self-signed client cert means the server checks the DN fields, not the issuing CA. A
forged header that flips 403 to 200 means the terminating proxy does not strip client-supplied copies
of its own verdict header. Both are authorization bypasses - prove them with **privileged data**.

**7. SNI and virtual-host confusion.** Pin the connection to the resolved peer and vary only the
names, so you never send a packet to a host you did not resolve.

```bash
IP=$(dig +short "$H" | grep -E '^[0-9.]+$' | head -1)
echo | openssl s_client -connect "$IP:$P" -noservername 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName      # the DEFAULT vhost's certificate
for name in "$H" "internal.$H" "admin.$H" "localhost"; do printf '%-16s ' "[$name]"
  curl -sk --resolve "$name:$P:$IP" -o /dev/null -w '%{http_code} %{size_download}\n' \
       "https://$name/" --max-time 8; done
curl -sk --resolve "$H:$P:$IP" "https://$H/" -H "Host: internal.$H" -o /dev/null \
  -w 'host-override %{http_code} %{size_download}\n'
```

Every SAN entry is a hostname the operator asserted - feed the new ones to `zp-scope` before touching
them, then to `zp-recon-active`. A certificate covering a public *and* an internal name on one IP is
also how browsers coalesce HTTP/2 connections, which is what makes the final Host override
interesting rather than academic. Version-implied TLS CVEs are leads for `zp-cve`, never findings.

**8. Stop point for this class.** You stop at the handshake transcript, the certificate, the
status-code flip, or the browser interstitial. ZeroProtocol does **not** MitM a real user, ARP or DNS
spoof a network, manipulate a client clock to age out HSTS, dump memory past the one request that
confirms a leak, use a recovered private key to sign or decrypt, guess at client certificates, or
sweep a CIDR. If the only route to impact is "assume an on-path attacker", write that sentence.

---

## Probes and payloads

| Probe | Breaks | Positive looks like |
|---|---|---|
| `-verify_hostname "$H" -verify_return_error` | CN/SAN not covering the name served | `Verification error: Hostname mismatch` on a host users load |
| `-showcerts \| grep -c BEGIN` = 1, or `x509 -checkend 0` | missing intermediate (browsers fetch it via AIA; curl, Java, Go and mobile do not), or expiry | verify fails from a clean trust store while the browser is happy |
| `-tls1`/`-tls1_1`, or `-no_tls1_3 -cipher 'NULL:@SECLEVEL=0'`, both with `@SECLEVEL=0` | deprecated versions still negotiable; a NULL suite left enabled | `alert protocol version`/`alert handshake failure` = closed · `New, TLSv1.0, Cipher is ...` or `Cipher is ...-NULL-...` = open, the second being the one genuinely serious cipher result |
| `-sess_out`/`-sess_in` then `-early_data f.txt` | TLS 1.3 0-RTT accepted on a non-idempotent route | early data processed, one effect per replay |
| forged `X-SSL-Client-Verify: SUCCESS`, or a self-signed client cert via `--cert/--key` | edge does not strip its own verdict header; server validates DN fields, not the issuer | 403 becomes 200 **with privileged content**, or an authenticated response for a cert you minted |
| `--resolve` with varied SNI, `-noservername`, or `-H "Host: internal.$H"` | one terminator fronting several apps | a second certificate naming internal infrastructure, a different body size, or 200 where the public name 404s |

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| forged edge header flips 403 to 200 **and** returns privileged data or performs an action | **confirmed authorization bypass.** High. The best outcome in this class |
| self-signed or unrelated-CA client certificate accepted by an mTLS endpoint | confirmed auth bypass. High - show the privileged response, not the status code |
| SNI or Host override reaches an internal app on a shared terminator | **confirmed.** Medium to High by what the app exposes - then hunt the app itself |
| a private key, keystore or `.pfx` readable over HTTP or in a bundle, or a Heartbleed-class leak with secrets in the captured bytes | **Critical.** Do not use the key - prove the modulus matches the live cert and stop. Verify the host is genuinely unpatched; one confirming request only |
| expired, hostname-mismatched, or chain-broken cert on a **production, user-facing** endpoint | Low to Medium. Real, cheap, frequently duplicate - check `zp-intel` first, and stronger when a mobile app or webhook consumer is the victim |
| TLS 1.0/1.1/SSLv3 negotiable, or 3DES/RC4 offered, with no decrypt PoC | **hardening, not a vulnerability.** Info/Low, out of scope on most programs. A negotiated **NULL** suite is the exception - cleartext transport, Medium |
| SWEET32, BEAST, POODLE, CRIME, FREAK, DROWN or LUCKY13 claimed from a scanner line | killed until you show the precondition present *and* an exploit. In practice un-demonstrable |
| missing HSTS, short `max-age`, no `includeSubDomains` | Low/Info without an on-path capture. Name the cookie and the plaintext host or do not file |
| missing preload or CAA, no OCSP stapling, "grade B on SSL Labs", passive mixed content | **not findings.** Killed. Recon appendix at most |
| a first-party `http://` API base the server or app fetches itself | confirmed cleartext transmission. Medium - `zp-mobile`, `zp-code-audit` |
| self-signed cert on a staging, internal-only or non-prod host | killed. It is intentional |
| your own OpenSSL said `Unknown option`, `no protocols available` or `no cipher match` | **no result at all.** Retest before claiming anything |
| the cert belongs to a CDN or vendor, or the policy lists TLS/cipher/header findings as out of scope | not yours, or killed before the first handshake. Re-run `zp-scope check`, read the policy first |

---

## High-value patterns

- **An mTLS-protected admin or partner API behind nginx, HAProxy or Envoy** - the terminator forwards its verdict as a header and forgets to strip the client's copy. The one High this class reliably yields.
- **One TLS terminator, many vhosts** - a staging or admin app answering only to a name that exists in the SAN list and nowhere in DNS.
- **SAN and CT entries naming internal hosts** (`vpn-`, `jenkins-`, `-uat`, `.corp`, `.internal`) - not a finding, but the input to `zp-recon-active` and often the whole engagement.
- **A private key committed beside its cert** in an exposed `.git`, a backup archive or a JS bundle - `zp-js-secrets`, `zp-code-audit`. A forgotten host with an expired wildcard is the same story: the renewal cycle missed it, so everything else did too.
- **A mobile or webhook client that pins badly or disables verification** (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`) - the victim is concrete, so the finding survives triage.
- **0-RTT enabled in front of a payment or transfer route** - replay with material effect, and rarely checked.

---

## Pitfalls

- **Pasting a scanner's TLS section into a report,** or filing missing HSTS, CAA, preload or OCSP stapling. The defining junk submissions of this class - triage closes them on sight.
- **Trusting your own client's refusal.** OpenSSL 3.x has no `-ssl3` and no RC4 at all; `Unknown option` and `no cipher match` are your build, not their server. And a legacy-cipher probe without `-no_tls1_3` succeeds as TLS 1.3 and looks like a hit.
- **Forgetting `-servername`,** which fingerprints the default vhost and reports the wrong certificate entirely.
- **Confusing offered with exploited.** A completed handshake proves negotiation and nothing more. Equally, an mTLS bypass claimed from a status code alone - `200` on both sides means the path was never protected; show content the cert-required path denies.
- **MitM, ARP or DNS spoofing, clock manipulation, or capturing anyone else's traffic.** Out of scope everywhere, and not something ZeroProtocol does. Nor is *using* a recovered private key - matching moduli is the proof; decrypting or signing is an intrusion.
- **Sweeping a CIDR or a whole SAN list at full rate,** or testing a SAN name before `zp-scope check` allows it - a certificate asserting a hostname is not authorization to touch it. And never leave a canary cert or written file live on anything belonging to the target.

---

## Hand off to

New hostnames from SAN, CT or the default vhost -> `zp-scope`, then `zp-recon-passive`,
`zp-recon-active`, `zp-content-discovery`. mTLS and header-trust bypass -> `zp-authz`, plus
`zp-smuggling` when edge and origin disagree about a header. Reached an internal app ->
`zp-info-disclosure`, `zp-api`, `zp-graphql`. Dangling CNAME on a cert name -> `zp-takeover`.
Version-implied CVEs -> `zp-cve`. Pinning, cleartext API bases and client trust stores ->
`zp-mobile`, `zp-code-audit`, `zp-js-secrets`. Keys in object storage -> `zp-cloud`. Cookie scope and
the `Secure` flag -> `zp-session`. Interstitial and mixed-content proof -> `zp-browser`; captured
traffic -> `zp-proxy`. Missing tools -> `zp-toolchain`. Duplicate check -> `zp-intel`, then
`zp-triage` and `zp-report`.
