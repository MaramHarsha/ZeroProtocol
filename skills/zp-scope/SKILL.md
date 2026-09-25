---
name: zp-scope
description: ZeroProtocol phase 1 - establish and enforce the authorization boundary before any packet reaches a target. Use when a new target or program is given, when asked "is this in scope", when a scope file must be created or confirmed, when reading a HackerOne/Bugcrowd/Intigriti/YesWeHack/Immunefi program scope or policy, when a host found by recon needs an ownership decision, or when any zp-* skill reports exit code 1, 3, or 4 from zp-scope check. Owns scope.yaml, wildcard semantics, out-of-scope deny sets, rate-limit rules of engagement, and the deny-by-default gate that the rest of ZeroProtocol is built on.
---

# zp-scope - the authorization gate

**Gate:** none. This skill *is* the gate. It runs before everything else.

Scope is a check, not a promise. A model that merely *intends* to stay in scope will
drift after forty tool calls; a program that exits non-zero will not. So the boundary
lives in `scope.yaml` and is enforced by `zp-scope`, and every other skill asks it.

---

## The contract

```bash
zp-scope check https://api.target.com/v1/users
```

| Exit | Meaning | Required behaviour |
|---|---|---|
| 0 | in scope, human-confirmed | proceed |
| 1 | out of scope | refuse; name the pattern that denied it; do not retry, do not rephrase |
| 3 | scope exists, not confirmed | passive recon only; walk the user through confirmation |
| 4 | no scope file | stop; `zp-scope init` |
| 2 | usage/parse error | stop; fix the file. An error is **never** treated as allow |

Three rules that make the gate real:

1. **Deny wins over allow.** An `out_of_scope` match beats any wildcard.
2. **No rule matched means deny.** Absence of permission is not permission.
3. **Any error means deny.** Never fail open, never "assume it's probably fine".

---

## Procedure

### 1. Name the mode, in writing

Bug bounty / pentest with a signed scope / your own asset. The same behaviour is a
payable finding in one mode and noise in another, and the report shape differs. If the
request does not say, **ask once and stop**. Mixed signals default to bug bounty
discipline - the strictest - because you can soften a claim later but you cannot
un-submit a report.

### 2. Pull the scope from the platform, never from a paste

The platform API carries per-asset flags the web page renders away:
`eligible_for_bounty`, `eligible_for_submission`, `max_severity`, `instruction`, `tier`.
A human paste loses all of them.

```bash
# HackerOne, read-only, needs your username + API token
curl -s --max-time 30 -u "$H1_USER:$H1_TOKEN" \
  "https://api.hackerone.com/v1/hackers/programs/$HANDLE" \
  | jq '.relationships.structured_scopes.data[].attributes
        | {asset_type, asset_identifier, eligible_for_bounty, eligible_for_submission, max_severity, instruction}'

# bbscope aggregates every platform into one queryable store
bbscope poll h1 --user "$H1_USER" --token "$H1_TOKEN"
bbscope db get wildcards -a          # -a also derives roots from url entries
bbscope db get domains ; bbscope db get cidrs ; bbscope db get ips
bbscope db changes --limit 10        # scope added/removed over time - new assets are the best surface
```

**No-tool fallback**, public programs, hourly-refreshed, no auth:

```bash
BASE=https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data
curl -sSL --max-time 180 "$BASE/hackerone_data.json" -o /tmp/h1.json   # ~10-30 MB
jq -r --arg h "$HANDLE" '.[] | select((.handle//"" | ascii_downcase) == ($h|ascii_downcase))
   | .targets.in_scope[] | "\(.asset_type)\t\(.asset_identifier)\t\(.eligible_for_bounty)"' /tmp/h1.json
```
Immunefi is deliberately absent from that dump - use bbscope or the program page.

### 3. Read the policy before the first probe, not after

Grep the policy text for the phrases that invalidate whole hunt branches:

```
out of scope · not accepted · N/A · duplicate · under remediation · temporarily
no more than · per second · rate · phishing · social engineering · scanners
automated · brute · DoS · denial of service · safe harbor · test account
```

Extract into the scope file: required attribution header **with its real value** (never
the literal word "researcher"), account-naming rules, rate limit, banned techniques,
banned tool categories, severity exclusions, and any waiting period.

### 4. Screen the economics before spending budget

A VDP, or a ceiling under a few hundred, changes what is worth hunting: pre-filter to
chain-capable and auth-dependent classes and skip standalone header/cookie/banner/CORS
hunting entirely. One N/A on a VDP costs more reputation than the bounty could pay.

### 5. Write the file

```bash
zp-scope init --target target.com --platform hackerone --program-url https://hackerone.com/target
```

Then correct it by hand against the real program page. `init` seeds `*.target.com` and
`target.com`; the program decides whether both belong.

```bash
zp-scope add in  "*.target.com" api.target.io
zp-scope add out staging.target.com "*.dev.target.com"
zp-scope add path /api/v1/billing/charge
zp-scope add class dos volumetric-testing social-engineering
```

**Wildcard semantics as ZeroProtocol implements them:** `*.target.com` matches
`a.target.com` and `a.b.target.com`, but **not** the apex `target.com`. List the apex
separately if the program includes it. This errs toward refusing, which is the only
correct direction for a gate. Verify the apex question against the program text - do not
assume either way.

**Build the out-of-scope deny set before the first probe**, then diff it against the raw
asset list twice. Non-prod labels to check for explicitly:

```
test  uat  dev  develop  stage  staging  preprod  nonprod  qa  sandbox  sandpit  demo  internal
```

A host that survives the filter but carries a non-prod label is a **filter bug**, not an
in-scope host. Go back and fix the pattern.

### 6. Confirm - the one step a human must take

```bash
zp-scope confirm --by "your-handle" --authorization "https://hackerone.com/target"
```

`confirm` refuses if `in_scope` is empty, if authorization is blank, or if a pattern is
`*` / `0.0.0.0/0` - that is not a scope, that is the internet. **Never run `confirm` on
the user's behalf without them stating the authorization.** Ask for it, in their words,
and put their words in the file. Widening `in_scope` later clears the confirmation
automatically, because nobody signed off on the new hosts.

### 7. Ownership-triage anything recon found

Assets **named in the scope list** need no proof - the program asserted them. Assets
**derived from recon** are guilty until proven owned, and a keyword match is not proof:

| Evidence | Strength |
|---|---|
| listed in the program scope | conclusive |
| same TLS cert / SAN as a verified asset | strong |
| WHOIS/RDAP org matches, or in a verified ASN | strong |
| same IdP tenant (`login.target.com` SSO redirect) | strong |
| reverse DNS into a verified domain | moderate |
| the brand name in the hostname | **none** - shared hosting and squatters look identical |

No strong evidence means do not probe it. Ask the user or the program instead.

### 8. Rules of engagement, recorded and injected

```yaml
rate_limit_rps: 5
max_concurrency: 5
testing_window: ""
excluded_vuln_classes: [dos, volumetric-testing, social-engineering, physical, spam]
```

Measure the real limit with 5-10 probes before planning the hunt - aggressive WAFs block
for 900+ seconds after a handful of requests, and a block costs more time than the
politeness would have.

**A subagent inherits none of this.** Paste the rate limit, the attribution header with
its real value, and the banned techniques into every dispatch preamble. Global defaults
do not travel.

### 9. Connectivity precheck

```bash
while read -r h; do
  printf '%s %s %s\n' "$h" "$(dig +short "$h" | head -1)" \
    "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$h/")"
done < <(zp-scope show --json | jq -r '.in_scope[]' | grep -v '^\*')
```

If every in-scope host is NXDOMAIN or 000, **stop and ask**. You have the wrong target,
the wrong spelling, or no egress - all three are worth five seconds of asking.

### 10. Re-sync every session, re-verify at submission

Scope amends mid-engagement. Newly added assets are the highest-value surface in bug
bounty; newly removed ones make a finished report an instant N/A. Diff on every session
start and persist the delta in `notes.md`.

At submission time re-verify: the exact policy wording for the wildcard the finding sits
on, the destination host of any redirect used in the PoC, the excluded-class list, and -
for acquisitions or shared codebases - whether a second program pays more for the same
bug.

---

## Confirm or kill

| Situation | Verdict |
|---|---|
| host matches an `in_scope` pattern, file confirmed | proceed |
| host matches both an in and an out pattern | **deny** - out wins |
| host in scope, but the path is in `excluded_paths` | deny that path only |
| class is in `excluded_vuln_classes` | do not test it at all, even in scope |
| recon found it, brand name matches, nothing else | deny - get real ownership evidence |
| scope says `*.target.com`, host is `target.com` | deny until the program text settles it |
| program is a VDP and the class is a lone header issue | in scope but not worth hunting |
| user says "just test it, I own it" with no evidence | record their statement verbatim as the authorization, then proceed |

---

## Pitfalls

- **Trusting a pasted scope.** Per-asset bounty eligibility and max-severity only exist in the API.
- **Reading the policy after building the asset list.** A banned technique invalidates a branch you already planned.
- **Hunting one wildcard when the program lists siblings.** Programs list `*.target.com`, `*.target.co.uk`, `*.target.de`. Claiming "exhausted" from the flagship alone misses whole estates - and probing an *unlisted* country TLD is a policy hit.
- **Letting a subagent inherit nothing.** It will happily hammer at 50 rps.
- **Treating `403` as out of scope.** A 403 is an in-scope host telling you something exists.
- **Free-text scope.** "I think it's all their subdomains" is not a gate. Write patterns.
- **Confirming on the user's behalf.** The signature is the whole point of the signature.
- **Using found credentials.** Finding them is the bug; using them is a new and much worse problem.

---

## Hand off to

Confirmed scope -> `zp-toolchain` (what can this box do), then `zp-recon-passive`.
Unconfirmed -> `zp-recon-passive` only, and say so plainly.
Denied -> stop, and tell the user exactly which pattern denied it.
