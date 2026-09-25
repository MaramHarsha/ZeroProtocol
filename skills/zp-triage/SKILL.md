---
name: zp-triage
description: ZeroProtocol phase 7 - the kill gate every finding must pass before a report is written. Use when a finding looks confirmed, when deciding whether something is worth submitting, when scoring severity or CVSS, when checking for duplicates against program hacktivity, when a finding needs a devil's-advocate review, or when asked "is this reportable". Thirty seconds to kill a lead, thirty minutes to write a report - so this always runs first.
---

# zp-triage - kill it before you write it

**Phase:** 7 | **Gate:** none. This is desk work on evidence you already hold.

A report costs you thirty minutes and a piece of your signal. This gate costs thirty seconds.
Run it on every finding, before drafting, every time.

**KILL kills the finding, never the engagement.** Killing four leads and submitting one good
report is a successful session.

---

## The seven questions

Answer all seven, in writing, in `findings/NNN-slug.md`. Any **no** in 1-5 is a KILL.

**1. Can an attacker do this right now?**
Not "with a stolen token", not "if the admin pastes this", not "once they are on the LAN". Right
now, from the internet, as an attacker who has only what an attacker has.

**2. Against a user who took no unusual action?**
Self-XSS, "victim pastes this into the console", "victim disables their own protections",
"victim installs a malicious app" - all no.

**3. Is the harm real and nameable?**
Stolen money, leaked PII, account takeover, code execution, tenant break, data destruction. Say
*which*. "Weakens security posture" is not harm.

**4. Did you reproduce it?**
From scratch, in a clean session. Twice for High and Critical, on two independent stacks.

**5. Is it in scope - asset, class, and method?**
Re-check `zp-scope`: the host, the excluded classes, the excluded paths, and the technique. A real
finding on an out-of-scope asset is not a finding.

**6. Is it already known?**
Program hacktivity, the last disclosed reports, the CHANGELOG, the docs, the public audits, the
issue tracker. See the dedup section.

**7. Is the severity you plan to claim the severity you can prove?**
If you demonstrated a read and plan to write "full account takeover", the answer is no. Downgrade
to what the evidence supports.

Verdicts: **PASS** · **KILL** · **DOWNGRADE** (real, lower than you hoped) ·
**CHAIN-REQUIRED** (only meaningful combined with something else).

---

## Kill on sight

These never survive. Recognising them instantly is the most valuable habit in this skill.

| Pattern | Why |
|---|---|
| "Could theoretically allow…" | not exploitable = not a bug |
| "An attacker with X, Y and Z could…" | too many preconditions |
| wrong implementation, no practical impact | wrong but harmless |
| a bug in unreachable or dead code | not reachable = not a bug |
| self-XSS | requires the victim to attack themselves |
| missing security header, on its own | no demonstrated impact |
| cookie without `HttpOnly`, no XSS to pair it with | theoretical |
| source map or minified-source disclosure with no secret | no impact |
| SSRF with a DNS-only callback, nothing reachable | needs internal reach or exfil |
| open redirect on its own | needs an ATO or OAuth chain |
| clickjacking on a page with no sensitive action | no impact |
| `*` CORS on public data | no protected data exposed |
| version disclosure / banner grab | informational |
| rate limiting absent on a non-sensitive endpoint | usually N/A |
| weak TLS ciphers, no exploit | scanner output |
| user enumeration | almost always N/A; check the policy before spending time |
| "no DMARC/SPF/CAA" | out of scope on nearly every program |
| DoS, volumetric, resource exhaustion | excluded by policy, and you should not have tested it |
| a finding on a third-party SaaS the target merely uses | not the target's bug - tell them, do not report it as theirs |
| best-practice or hardening advice | not a vulnerability |
| raw scanner output you did not reproduce | not a finding |

**"Verify the data is not already public"** deserves its own line: before reporting any API
"leak", open the relevant page in a logged-out incognito browser. A surprising share of reported
data exposures are published on the target's own website.

---

## Dedup

Duplicates are the largest single cause of wasted effort in bug bounty. Spend three minutes.

```
1. Program hacktivity        every disclosed report on this program; scan titles and endpoints
2. The last ~5 disclosures   what the program's triagers have recently accepted
3. Public write-up corpora   h1-brain's 3,600+ disclosed-report database, if available, is
                             the fastest way to search by weakness type and endpoint shape
4. The target's own sources  CHANGELOG, release notes, security.txt, GitHub issues, the docs
5. Web search                "<target> <endpoint> bug bounty", "<target> <class> writeup"
6. Public audits (web3/OSS)  the finding is often listed as acknowledged or accepted risk
7. Your own submissions      have you reported this on a sibling asset already?
```

Signals it is a duplicate: the endpoint appears in a disclosed report; the program's policy
explicitly names the class as known; a fix is in an unreleased CHANGELOG entry; the code comment
says `// TODO: add authz check`; the behaviour is documented.

**If it is a duplicate, it is still worth checking one thing:** is your variant materially
different - a different endpoint, a bypass of the deployed fix, a higher impact? A bypass of a
patched issue is a **new** bug and often pays well.

---

## Severity

Score what you proved. Match the version to the platform: HackerOne uses CVSS 3.1;
Bugcrowd, Intigriti and Immunefi generally use 4.0 or their own taxonomy.

| Band | Shape |
|---|---|
| **Critical** | pre-auth RCE · full ATO without interaction · mass PII exposure · tenant break · direct theft of funds |
| **High** | authenticated RCE · ATO with light interaction · stored XSS in a privileged context · SQLi with data access · significant authz bypass |
| **Medium** | reflected XSS · CSRF on a meaningful action · IDOR on non-sensitive data · SSRF with internal reach but no data · business-logic abuse with limited gain |
| **Low** | narrow information disclosure · issues needing heavy interaction · minor logic flaws |
| **Informational** | hardening, best practice, no impact |

Sanity-check the vector against the story you will tell:

```
AV  Network unless it genuinely is not      AC  Low unless a real precondition exists
PR  None / Low / High - be honest           UI  None, or Required if a click is needed
C/I/A  only what you demonstrated
```

**Common scoring errors:** claiming `PR:None` when you used a logged-in session; claiming
`UI:None` when the victim must click; claiming `C:High` for one non-sensitive record; inflating
`A:High` on something that is not an availability issue at all.

Over-scoring gets you downgraded and remembered. Under-scoring gets you underpaid. Score
honestly and say what you did not prove.

---

## Two adversarial gates

**Browser verification** is mandatory for every client-side class - reflected, stored and DOM XSS,
prototype pollution, `postMessage`, DOM clobbering, CORS reads, clickjacking. A curl reflection is
not execution. Use a DOM marker, capture a screenshot, note the browser version.

**Devil's advocate.** Argue against your own finding, deliberately, before writing:

```
Is the data actually private?            (check logged out, incognito)
Is this the intended feature?            (read the docs and the permission model)
Does the impact match the claim?         (did I prove the last step, or assume it?)
Is the severity justified by evidence?
Would it survive a developer saying "that is by design"?
Am I relying on a precondition I have not stated?
Could this be my own tooling - a cache, a proxy, a sticky session, network noise?
Did I test against my own accounts only?
```

Verdicts: **SURVIVES** · **DOWNGRADE** · **KILLED**. When in doubt, spend ten more minutes on
evidence rather than sending a maybe.

---

## Multi-tool reproduction, for High and Critical

Two independent stacks, because cross-tool agreement is what rules out a tooling artifact:

```
curl  +  a proxy (Caido/Burp Repeater)
python requests  +  a raw socket
a browser  +  curl
```

The report's reproduction steps must be paste-into-a-shell ready. A triager who cannot reproduce
it in one attempt will close it.

---

## Output

```markdown
## Triage: <finding>
verdict:     PASS | KILL | DOWNGRADE | CHAIN-REQUIRED
severity:    Critical|High|Medium|Low  (CVSS 3.1: <vector>)
1 now?        yes/no - <why>
2 no unusual action?  yes/no
3 harm:       <named harm>
4 reproduced: <times, stacks>
5 in scope:   <asset, class, method - re-checked>
6 dedup:      <sources searched, result>
7 provable:   <what the evidence supports>
browser verified:  yes/no/NA
devil's advocate:  SURVIVES | DOWNGRADE | KILLED - <the strongest counter-argument and the answer>
chain:        <capability gained -> next link, or terminal>
```

A KILL is a finished piece of work. Record it in `coverage/` so you do not re-test it, note why,
and move on.

---

## Hand off to

PASS -> `zp-report`.
DOWNGRADE -> `zp-report` at the honest severity.
CHAIN-REQUIRED -> back to the hunters; build the chain, then re-triage. The chain is the report.
KILL -> record in `coverage/<host>/<class>.json` and return to the queue.
