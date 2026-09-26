---
name: zp-recon-active
description: ZeroProtocol phase 3 - find out which of the discovered hosts are actually alive, what they run, and which are worth hunting. Use when resolving and probing a host list, port scanning, fingerprinting a technology stack, detecting a WAF or CDN, checking TLS, screenshotting, or building the ranked attack surface. Requires a confirmed scope because every step here sends packets to the target; respects the program rate limit on every request.
---

# zp-recon-active - what is really there

**Phase:** 3 | **Gate:** **active.** `zp-scope check <host>` must exit 0 before any request.
Exit 1 refuse and name the pattern that denied it · 3 scope unconfirmed, stay in
`zp-recon-passive` · 4 no scope file, stop.

```bash
# the only correct way to turn a host list into a probe list
cat surface/hosts.txt | zp-scope filter > surface/in-scope.txt
RPS=$(zp-scope show --json | jq -r '.rate_limit_rps // 5')
```

Every command below runs against `surface/in-scope.txt`, never `surface/hosts.txt`.

---

## Procedure

**1. Resolve, and detect the wildcard first.** A wildcard DNS record makes every
bruteforced name "resolve", which silently poisons the whole phase.

```bash
# wildcard test: a name that cannot exist must come back NXDOMAIN. *Any* NOERROR answer is
# a wildcard - a wildcard fronted by a CDN or an LB hands out a different, rotating address
# set per query, so "the three replies differ" is not evidence that there is no wildcard.
# Test every root in in-scope.txt and every label you intend to brute force under.
for parent in $D dev.$D staging.$D api.$D; do
  dig +noall +comments "zzq$RANDOM.$parent" | grep -q 'status: NXDOMAIN' \
    || echo "WILDCARD at $parent"
done
# For each wildcard, record the full answer *set* (CNAME target plus addresses) and filter
# results on the set, not on one address.

dnsx -l surface/in-scope.txt -silent -a -cname -resp -json -o surface/dns.jsonl
# fallback:
while read -r h; do a=$(dig +short "$h" | tail -1); [ -n "$a" ] && echo "$h $a"; done \
  < surface/in-scope.txt > surface/dns.txt
```

**2. Probe HTTP, rate-limited.** This is the artifact everything downstream reads.

```bash
httpx -l surface/in-scope.txt -silent -rate-limit "$RPS" -threads 10 \
      -status-code -title -tech-detect -server -content-length -ip -cname -tls-grab \
      -follow-redirects -json -o surface/live.jsonl

# fallback, one host at a time, politely
while read -r h; do
  for s in https http; do
    out=$(curl -sk -o /dev/null -w '%{http_code} %{size_download} %{redirect_url}' \
          --max-time 15 --connect-timeout 8 "$s://$h/" 2>/dev/null)
    [ "${out%% *}" != "000" ] && echo "$s://$h $out"
    sleep "$(echo "scale=2; 1/$RPS" | bc)"
  done
done < surface/in-scope.txt | tee surface/live.txt
```

**3. Triage the response codes - none of them is boring.**

```bash
jq -r 'select(.status_code) | "\(.status_code) \(.url) \(.title // "-") \(.tech // [] | join(","))"' \
  surface/live.jsonl | sort -n
```

| Code | What it means for the hunt |
|---|---|
| 200 | the obvious surface. Also the least likely to be forgotten by the defenders |
| 301/302 | follow it - the destination is often a different host, sometimes out of scope |
| **401/403** | **the highest-value lead here.** The route exists and is protected; a bypass is the P1, the 401 itself is not a finding. Hand to `zp-authz` |
| 404 on a host that resolves | still a live server. Content discovery belongs here |
| 500/502/503 | a stack trace, a misconfigured origin, or an unfinished deploy |
| 000 / timeout | filtered, dead, or your rate limit tripped. Distinguish before concluding |

**4. Ports, narrow then deep.** Do not full-scan a wildcard estate; scan the ports that
host something interesting.

```bash
naabu -l surface/in-scope.txt -top-ports 1000 -rate 100 -o surface/ports.txt
nmap -sV -Pn --top-ports 100 -T3 -iL surface/in-scope.txt -oN surface/nmap.txt
# fallback:
python3 - surface/in-scope.txt <<'PY'
import socket, sys
PORTS = (80,443,8000,8080,8443,8888,3000,5000,9000,9200,6379,27017,5432,3306,2375,15672)
for h in (l.strip() for l in open(sys.argv[1]) if l.strip()):
    for p in PORTS:
        s = socket.socket(); s.settimeout(1.5)
        if s.connect_ex((h, p)) == 0: print(h, p, flush=True)
        s.close()
PY
```

Ports that change the hunt: `9200` Elasticsearch, `6379` Redis, `27017` Mongo, `2375`
Docker API, `15672` RabbitMQ, `5000` registry, `9090`/`3000` metrics and dashboards. An
unauthenticated one of these is usually the highest-severity thing on the estate - confirm
read access with a single benign query and stop there.

**5. Fingerprint the stack, because it picks the hunters.**

```bash
curl -skI "https://$H/" | grep -iE 'server|x-powered-by|x-aspnet|x-generator|x-drupal|x-runtime|set-cookie'
whatweb -a 1 "https://$H/" 2>/dev/null
```

| Signal | Route to |
|---|---|
| `X-Powered-By: Express`, `__NEXT_DATA__` | `zp-js-secrets`, `zp-api`, prototype pollution |
| `Set-Cookie: JSESSIONID` | Java: `zp-xxe-lfi`, deserialization in `zp-rce-ssti` |
| `Set-Cookie: laravel_session`, `X-Powered-By: PHP` | `zp-xxe-lfi`, `zp-upload`, `zp-code-audit` |
| `Set-Cookie: csrftoken` + `sessionid` | Django: `zp-idor`, `zp-authz` |
| `/graphql` reachable | `zp-graphql` |
| `cf-ray`, `x-cache`, `via`, `x-akamai` | `zp-cache-poison`, `zp-smuggling` |
| S3/GCS/Azure URLs in responses | `zp-cloud` |
| any `Access-Control-Allow-*` | `zp-cors` |

**6. Map the WAF once per host and cache it.** It determines which encodings are worth
trying later, and it is the reason a payload "did not work".

```bash
curl -skI "https://$H/" | grep -iE 'cf-ray|cloudflare|x-sucuri|akamai|datadome|incapsula|awselb|x-amz-cf'
wafw00f "https://$H/" 2>/dev/null
# measure the real limit before planning the hunt
for i in $(seq 1 10); do curl -sk -o /dev/null -w "$i %{http_code} %{time_total}\n" "https://$H/"; done
```

If codes turn to 403/429 partway through those ten, that is your budget. Aggressive WAFs
block for 900+ seconds after a handful of requests; a block costs far more time than the
politeness would have.

**7. TLS, for scope expansion and quiet misconfigurations.**

```bash
openssl s_client -connect "$H:443" -servername "$H" </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
```

New SANs go back through `zp-scope` for an ownership decision before they are probed.

**8. Write the ranked queue.** This is the artifact that unlocks phase 5.

```bash
jq -r 'select(.status_code) | [.status_code, .url, (.tech//[]|join(","))] | @tsv' surface/live.jsonl \
  | sort -u > surface/tech.md
```

Rank as the router describes: class weight, `+5` for a parameter, `+55` if it came from a
leaked secret. A 401 on `/api/admin/` outranks a 200 on the marketing site.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| a random name answers NOERROR at all | wildcard DNS, even if each reply differs. Filter the whole answer set; your list is fiction until you do |
| host resolves but all ports closed | parked. Park it, do not claim coverage of it |
| 403 from a WAF on every path | you are fingerprinting the WAF, not the app. Find the origin or slow down |
| 200 with an identical body on every path | soft-404. Calibrate before content discovery, or every result is a false positive |
| unauthenticated Redis/Mongo/ES/Docker | probably the top finding on the estate. One benign read, evidence, stop |
| 401 on an API route | surface worth attacking, not a finding. Hand to `zp-authz` |
| redirect leaves the scope | do not follow it with a payload. Note the destination host |
| codes degrade as you scan | rate limit hit. Back off; results after that point are unreliable |

---

## Pitfalls

- **Scanning `hosts.txt` instead of `in-scope.txt`.** The single most likely way to send a packet somewhere you were not allowed to.
- **Skipping the wildcard test.** Poisons every subsequent count and wastes hours.
- **Skipping soft-404 calibration.** Content discovery then "finds" a thousand nonexistent paths.
- **Full `-p-` scans across a wildcard estate.** Loud, slow, and usually against the program's rate rules.
- **Trusting `-follow-redirects` blindly.** It will happily carry you to an out-of-scope host.
- **Treating 404 as dead.** A 404 from a live server is an invitation to `zp-content-discovery`.
- **Ignoring your own rate limit** because the tool has a `-threads` flag. The program's number wins.
- **Reporting an open port as a vulnerability.** An open port is surface. The finding is what is on it.

---

## Hand off to

Live surface -> `zp-content-discovery` (paths, params) and `zp-js-secrets` (bundles).
Stack signals -> the dispatch table in `zeroprotocol`. Version banners -> `zp-cve`.
Dangling CNAMEs -> `zp-takeover`. CDN in front -> `zp-cache-poison`, `zp-smuggling`.
New SANs or netblocks -> back to `zp-scope`.
