---
name: zp-takeover
description: ZeroProtocol hunter for subdomain and resource takeover. Use when a CNAME points at an unclaimed third-party service, when checking for dangling DNS, when a host returns a vendor "no such app" page, when hunting NS or MX delegation takeover, or when looking for unclaimed S3/Azure/GitHub-Pages/Heroku/Shopify resources. Claim only into an account you control, prove it with a harmless marker, and clean up immediately.
---

# zp-takeover - somebody else's dangling pointer

**Phase:** 5 | **Gate:** **active.** `zp-scope check <host>` must exit 0. Exit 1 refuse ·
3 stop · 4 stop.

A takeover is one of the few classes where the *proof* involves creating something. That
makes the ethics concrete: you may claim the resource only inside an account you own, you
prove it with a harmless marker at a path nobody will hit, and you release it the moment the
report is filed.

---

## Procedure

**1. Find the dangling pointers.**

```bash
while read -r h; do
  c=$(dig +short CNAME "$h" | head -1)
  [ -n "$c" ] && echo "$h -> $c"
done < surface/in-scope.txt | tee to-cnames.txt

# NXDOMAIN on the CNAME target is the strongest single signal
awk '{print $3}' to-cnames.txt | sed 's/\.$//' | sort -u | while read -r t; do
  dig +short "$t" | grep -q . || echo "DANGLING: $t"
done

subzy run --targets surface/in-scope.txt --hide_fails        # ~70 curated fingerprints
```

**2. Fingerprint the claim page.** A CNAME to a live service is not a takeover; the service
saying "this name is unclaimed" is.

```bash
H=sub.target.com
dig +short CNAME "$H"; curl -sk --max-time 15 "https://$H/" | head -c 400
```

| CNAME points at | Claim-page tell | Claimable |
|---|---|---|
| `*.s3.amazonaws.com` | `NoSuchBucket` | yes - create the bucket with that exact name |
| `*.github.io` | `There isn't a GitHub Pages site here` | yes - repo + CNAME file |
| `*.herokudns.com` / `herokuapp.com` | `No such app` | yes |
| `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.trafficmanager.net` | `Web App - Unavailable`, NXDOMAIN | yes |
| `*.myshopify.com` | `Sorry, this shop is currently unavailable` | yes |
| `*.fastly.net` | `Fastly error: unknown domain` | yes, via a Fastly account |
| `*.pantheonsite.io` | `The gods are wise` | yes |
| `*.wpengine.com` | `no site here` | yes |
| `*.readthedocs.io` | `unknown to Read the Docs` | yes |
| `*.surge.sh`, `*.netlify.app`, `*.vercel.app` | vendor 404 | varies - Netlify/Vercel verify ownership now |
| `*.cloudfront.net` | `Bad request` / `ERROR: The request could not be satisfied` | **usually not** - needs the distribution's alias |
| `*.elb.amazonaws.com` | vendor error | **no** - but a dangling ELB can be re-IP'd; report as a risk, not a takeover |

Fingerprints drift constantly. **Read the actual response body** rather than trusting a
tool's verdict, and re-check the vendor's current behaviour before writing a report - several
providers (Netlify, Vercel, GitHub) added ownership verification and are no longer claimable.

**3. Check the other record types.** These are rarer, higher impact, and usually unhunted.

```bash
dig NS  "$H" +short     # delegated to a nameserver on a registrar you can sign up for = full zone control
dig MX  "$H" +short     # dangling MX = inbound mail interception
dig TXT "$H" +short     # stale SPF include / domain-verification token for a dead SaaS tenant
```

An **NS takeover is the maximum-severity variant**: it hands over the entire subtree, not one
host. A dangling `MX` lets you receive password-reset mail. A stale SPF `include:` of an
expired domain lets you pass SPF for the target.

**4. Unclaimed storage, independent of CNAMEs.**

```bash
for s in dev staging test prod backup api assets static cdn media uploads logs data; do
  for pat in "$D-$s" "$s-$D" "$D.$s"; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "https://$pat.s3.amazonaws.com/")
    [ "$code" != "404" ] && echo "$code $pat.s3.amazonaws.com"
  done
done
```

`404 NoSuchBucket` on a name the target actively references = claimable. `403` = the bucket
exists and is private; that is not a takeover (see `zp-cloud`).

**5. Claim it - correctly, or not at all.**

The rules, in order:

1. The resource goes into **an account you own**, under your own identity.
2. Serve exactly one harmless marker, at an unguessable path, with no script:
   `https://sub.target.com/.zeroprotocol-poc-<random>.txt` containing your handle, the UTC
   timestamp, and the program name.
3. Never serve content at `/`, never set a cookie for the parent domain, never serve JS, and
   never accept traffic meant for real users beyond what the marker needs.
4. Screenshot the marker being served from the target's hostname. That is the entire proof.
5. File the report immediately, and **release the resource** as soon as it is acknowledged.
6. Say in the report exactly what you created, where, and that you have released it.

If you cannot claim it without collecting real user traffic, **do not claim it**. Report the
dangling record with the fingerprint evidence and let the owner verify. A DNS record plus a
vendor claim page is usually accepted on its own.

---

## Confirm or kill

| Observation | Verdict |
|---|---|
| CNAME to a vendor + that vendor's unclaimed page | **confirmed takeover.** Claim carefully or report the fingerprint |
| CNAME target is NXDOMAIN | strong lead. Confirm the service is claimable before claiming impact |
| CNAME to a live, serving app | not a takeover. Killed |
| CloudFront/ELB vendor error | usually **not** claimable. Verify before writing; most reports of this are duplicates or N/A |
| bucket returns `403` | exists and is private. Not a takeover - hand to `zp-cloud` |
| the parent zone has a wildcard `*.target.com` | your "dangling" subdomain may just be the wildcard. Re-test with a random name |
| dangling NS | **Critical.** Whole-subtree control |
| dangling MX | High - mail interception, and usually chains to account takeover |
| stale SPF include of an expirable domain | real, often under-rated. Check whether the included domain is registrable |
| you claimed it and served a marker | confirmed. File now, release after acknowledgement |

**The wildcard check is the most common false positive.** If `*.target.com` resolves, every
name "exists" and your dangling subdomain may be an illusion. Always test a random name
first.

---

## High-value patterns

- **NS delegation** to a registrar with free signup - the highest-severity form of this class.
- **A takeover on a domain that holds a cookie scoped to the parent.** `sub.target.com` under your control plus a `Domain=.target.com` session cookie is session theft, which is `zp-authz` territory and a much bigger report.
- **A takeover on a host referenced by the main app's CSP or script tags** - that is stored XSS on the main app, and you should chain it rather than report the takeover alone.
- **Dangling MX on a domain used for password resets** - direct account takeover chain.
- **Abandoned marketing subdomains** after a campaign ends - the most common real finding here.
- **A stale SaaS verification TXT** letting you re-verify the domain in a service the target still trusts.

---

## Pitfalls

- **Skipping the wildcard test** and reporting an illusion.
- **Trusting a scanner's fingerprint** after the vendor changed its behaviour. Read the body.
- **Reporting CloudFront/ELB "takeovers"** - overwhelmingly N/A or duplicate.
- **Serving anything at `/`** on a claimed host. You are now intercepting real users' requests.
- **Serving JavaScript or setting a parent-domain cookie.** That crosses from proof into attack.
- **Holding the resource** after reporting. Release it; otherwise you are the ongoing risk.
- **Claiming a resource that receives live traffic** - if users are hitting it, do not take it, report it.
- **Reporting the takeover alone** when it chains into XSS or session theft on the main domain. The chain is the report.

---

## Hand off to

Confirmed -> `zp-triage` then `zp-report` (fast: the window is open while you write).
Cookie-scope or CSP implications -> `zp-authz`, `zp-xss` to build the chain.
Private-but-existing buckets -> `zp-cloud`. New hostnames from the CNAME chain -> `zp-scope`.
