---
name: zp-js-secrets
description: ZeroProtocol phase 3c - mine JavaScript bundles, source maps and client-side assets for hidden endpoints, secrets and dangerous sinks. Use when analysing JS files, recovering a webpack source map, extracting API routes from a bundle, hunting hardcoded API keys or tokens, checking for dependency confusion, or looking for DOM XSS sinks and postMessage handlers. Every secret found must be validated as live before it is reported, and never used.
---

# zp-js-secrets - the client already told you everything

**Phase:** 3c | **Gate:** **active** to fetch the assets (`zp-scope check` exit 0). Analysing
an already-downloaded bundle is offline work and needs no further gate.

A modern SPA ships its own API documentation. Routes the crawler never saw, feature flags,
internal hostnames, and sometimes a live credential are all sitting in the bundle that every
visitor downloads.

---

## Procedure

**1. Collect every script.**

```bash
mkdir -p js && cd js
katana -u "https://$H/" -silent -jc -kf all -d 3 -rl "$RPS" | grep -Ei '\.m?js' | sort -u > ../js-urls.txt
# fallback: pull them out of the HTML and the archive corpus. `src=` is nearly always
# relative or root-relative, so absolutise it against the page URL - curl exits 3 on a bare
# `/static/js/main.js` and writes nothing, so the whole fallback fails silently otherwise.
curl -sk "https://$H/" | grep -oE 'src="[^"]+\.m?js[^"]*"' | cut -d'"' -f2 \
  | python3 -c 'import sys,urllib.parse as u
[print(u.urljoin(sys.argv[1], l.strip())) for l in sys.stdin if l.strip()]' "https://$H/" \
  >> ../js-urls.txt
grep -Ei '\.m?js([?#]|$)' ../surface/urls.txt >> ../js-urls.txt
sort -u ../js-urls.txt -o ../js-urls.txt

while read -r u; do
  case "$u" in http://*|https://*) ;; *) echo "skipped, not absolute: $u" >&2; continue ;; esac
  curl -sk --max-time 20 "$u" -o "$(echo "$u" | md5sum | cut -c1-12).js"
done < ../js-urls.txt
```

**2. Recover source maps - the highest-yield single step here.** A `.map` file gives you the
original, readable, commented source.

```bash
for f in *.js; do
  # strip the prefix with sed, never `cut -d= -f2`: that keeps one field, so
  # `main.js.map?v=2` becomes `main.js.map?v` and the map then looks absent
  m=$(tail -c 300 "$f" | grep -oE 'sourceMappingURL=[^[:space:]*]+' | sed 's/^sourceMappingURL=//')
  [ -n "$m" ] && echo "$f -> $m"
done
# a `data:application/json;base64,` map is already in your hands - decode it, do not fetch it
curl -sk "https://$H/static/js/main.abc123.js.map" -o main.map
# unpack every original file with stdlib only. Two things the naive version gets wrong:
# index maps put the content in `sections[].map`, and `sources` is data the target wrote -
# a single-pass .replace("../","") is not a traversal filter, so confine every write.
python3 - main.map <<'PY'
import json, os, sys
m = json.load(open(sys.argv[1]))
maps = [s["map"] for s in m["sections"]] if m.get("sections") else [m]
base, n = os.path.abspath("src"), 0
for sm in maps:
    if not sm.get("sourcesContent"):
        print("this map section carries no sourcesContent", file=sys.stderr)
    for name, src in zip(sm.get("sources", []), sm.get("sourcesContent") or []):
        if not src: continue
        p = os.path.abspath(os.path.join(base, name.split("://", 1)[-1].lstrip("/")))
        if not p.startswith(base + os.sep):
            print("skipped traversal:", name, file=sys.stderr); continue
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w", encoding="utf-8").write(src); n += 1
        print(os.path.relpath(p))
print(f"{n} original file(s) recovered", file=sys.stderr)
PY
```

Also try appending `.map` to a bundle URL even when no `sourceMappingURL` comment survives -
build pipelines often ship the map and only strip the comment.

**3. Extract endpoints and hostnames.**

```bash
cat *.js | grep -oE '"(/[a-zA-Z0-9_/.{}$-]{2,80})"' | tr -d '"' | sort -u > ../js-endpoints.txt
cat *.js | grep -oE 'https?://[a-zA-Z0-9._-]+\.[a-z]{2,}[a-zA-Z0-9._/-]*' | sort -u > ../js-hosts.txt
cat *.js | grep -oE '(fetch|axios\.[a-z]+|\$\.(get|post|ajax)|XMLHttpRequest)[^;]{0,160}' | sort -u
# with tooling - jsluice is a JS parser and fetches nothing, so give it the bundles you
# already downloaded rather than the URL list (check the flags with `jsluice --help` first):
jsluice urls *.js ; jsluice secrets *.js
```

New hostnames go through `zp-scope` for an ownership decision. New paths go to
`zp-content-discovery` and `zp-api`.

**4. Hunt secrets with high-signal patterns.** Most "secret scanner" output is noise; these
prefixes are not.

```bash
grep -nEo '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})' *.js                       # AWS access key
grep -nEo 'AIza[0-9A-Za-z_-]{35}' *.js                                      # Google API key
grep -nEo '(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}' *.js                          # GitHub token
grep -nEo 'xox[baprs]-[0-9A-Za-z-]{10,}' *.js                               # Slack token
grep -nEo 'sk_(live|test)_[0-9a-zA-Z]{24,}' *.js                            # Stripe secret key
grep -nEo 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}' *.js                   # SendGrid
grep -nEo 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' *.js  # JWT
grep -nEo '\-\-\-\-\-BEGIN [A-Z ]*PRIVATE KEY' *.js                         # private key
grep -nEiE '(api[_-]?key|secret|passwd|password|token|bearer|credential)["'\'']?\s*[:=]\s*["'\''][^"'\'']{12,}' *.js
trufflehog filesystem . --no-verification        # NEVER --only-verified: its verification step
                                                 # authenticates to the provider WITH the found
                                                 # credential, which this skill forbids below
```

**5. Decide whether each hit is live - without using it.**

| Kind | Non-destructive liveness check | Severity if live |
|---|---|---|
| Google Maps/API key | check its referrer/API restrictions, not a paid call | usually Low; High if unrestricted and billable |
| AWS `AKIA` | **do not call AWS.** Report the exposure and let the owner rotate | Critical - assume full compromise |
| Stripe `sk_live` | do not call it | Critical |
| GitHub token | do not call it | High-Critical depending on org scope |
| JWT in source | decode the payload offline (base64**url**, see below), read `exp`/`scope` | depends on claims; expired = informational |
| Firebase config | public by design - check the **rules**, not the key | the finding is open rules, not the key |
| Algolia/Sentry public keys | public by design | not a finding unless it is the admin key |

JWT segments are base64URL and unpadded, so `base64 -d` dies part-way through the claim
set and the token looks malformed. Translate the alphabet and pad it:

```bash
python3 -c "import base64,json,sys;s=sys.argv[1];print(json.loads(base64.urlsafe_b64decode(s+'='*(-len(s)%4))))" "$SEG"
```

**Never authenticate with a credential you found.** Finding it is the bug; using it is
unauthorized access. Report the exposure, the location, and the minimum proof of validity
you can obtain without exercising it - for most key types that is the key format plus where
it was served from.

**6. Find the DOM sinks while you are in here.** This is free `zp-xss` input.

```bash
# `-E` is POSIX ERE and has no lookahead: `(?!...)` makes GNU grep warn and silently match
# the wrong thing, and makes ugrep reject the whole pattern. Match a string first argument -
# that is the sink - or use `grep -nP` if PCRE is available.
grep -nE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|setTimeout\(\s*["'\''`]' *.js
grep -nE 'location\.(hash|search|href)|document\.referrer|window\.name|postMessage' *.js
grep -nE 'addEventListener\(\s*["'\'']message' *.js     # postMessage handlers
grep -nE '\.origin\s*(==|===|!=|!==)|indexOf\(.*origin|origin\.includes' *.js  # weak origin checks
```

A `message` listener with no `event.origin` check, or one that checks with `indexOf`/
`includes`, is a real finding - `https://target.com.evil.tld` passes a substring check.

**7. Dependency confusion.** Internal package names in a public manifest are claimable.

```bash
grep -hoE '"@[a-z0-9-]+/[a-z0-9._-]+"' *.js package.json 2>/dev/null | tr -d '"' | sort -u | while read -r p; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://registry.npmjs.org/$p")
  [ "$code" = "404" ] && echo "candidate - package document absent: $p"
done
# A 404 on `@scope/pkg` only says that package was never published. If the organisation
# holds `@scope`, every unpublished name under it 404s and nobody outside can publish there,
# so that 404 alone is an informative-closed report. Test the scope itself:
s=@acme
curl -s "https://registry.npmjs.org/-/v1/search?text=scope:${s#@}&size=1" | jq '.total'
```

`total: 0` - no package has ever been published under the scope - plus an organisation name
still available on npm (check it in an account you own; npm refuses to create one that
exists) is the claimable case, and so is an **unscoped** internal name that 404s. An
unpublished name under a scope the target owns is not a finding. Say in the report which
check you ran. **Report it; do not publish a package to prove it.** Claiming the name is an
attack on the build pipeline, not a PoC.

---

## Confirm or kill

| Finding | Verdict |
|---|---|
| endpoint string in JS | discovery only. Not a finding until probed and something is wrong |
| source map recovered | not itself a finding unless it exposes secrets or non-public logic |
| `sk_live`, `AKIA`, private key, verified token | **Critical.** Report immediately, do not use |
| Firebase/Algolia/Sentry public key | not a finding. Check the rules/permissions instead |
| expired or `test`-mode key | informational at best. Usually killed |
| a key that is public by design | killed. Read the vendor's docs before claiming |
| `innerHTML` from `location.hash` | a real DOM XSS lead -> `zp-xss` for browser proof |
| `message` listener with no origin check | real finding. Needs a working PoC page |
| unclaimed internal npm scope | real supply-chain finding. Report the name, claim nothing |

The dominant false positive in this skill is **a public key reported as a secret**. Read
what the key type actually authorizes before you write anything.

---

## High-value patterns

- **A `.map` in production** - gives you the commented source, the internal route table, and often the authorization logic.
- **Admin routes in the bundle of the user-facing app** - the same SPA ships both, and the server sometimes forgets to check.
- **Feature flags** (`isAdmin`, `showBilling`, `internalOnly`) - flip them client-side and see whether the API cares. If it does not, that is `zp-authz`.
- **Internal hostnames** in the bundle - free scope expansion, and a shortcut to the origin behind a CDN.
- **A hardcoded key in a mobile-shared bundle** - the same key is usually in the APK; cross-check with `zp-mobile`.

---

## Pitfalls

- **Using the credential.** The single most serious mistake available in this skill.
- **Reporting public keys as secrets.** It reads as inexperience and burns triager patience.
- **Reporting a source map as "source code disclosure"** with no impact. Find what the map *reveals*.
- **Claiming an unclaimed npm name** to prove dependency confusion. That is the attack.
- **Assuming a JS endpoint exists.** Probe it; dead code is common in bundles.
- **Ignoring `.map` because no comment points at it.** Try the `.map` URL anyway.
- **Pasting a bundle into an online beautifier.** That leaks the target's code to a third party.
- **Grepping only minified output.** Recover the map first; the readable source is where the logic is.

---

## Hand off to

Endpoints -> `zp-api`, `zp-graphql`, `zp-content-discovery`.
DOM sinks and `postMessage` -> `zp-xss`. Client-side authz flags -> `zp-authz`.
Cloud keys -> `zp-cloud` (for blast-radius reasoning only) then `zp-triage` immediately.
New hostnames -> `zp-scope`. Shared keys -> `zp-mobile` to cross-check.
