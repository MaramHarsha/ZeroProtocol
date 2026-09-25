---
name: zp-report
description: ZeroProtocol phase 8 - write the vulnerability report a triager can accept without asking a question. Use when a finding has passed zp-triage, when drafting a HackerOne, Bugcrowd, Intigriti, YesWeHack or Immunefi submission, when writing reproduction steps, packaging a PoC, or preparing a disclosure email for a self-hosted program. Never submits anything - a human approves and sends every report.
---

# zp-report - write it so it cannot be misread

**Phase:** 8 | **Gate:** `zp-triage` must have returned PASS or DOWNGRADE.

**ZeroProtocol never submits.** You draft; a human reads it and sends it. That rule exists because
submission is irreversible, it is attached to the user's reputation, and a triager's first
impression of a researcher is set by their worst report.

Write for a tired triager with forty reports in the queue who has never seen your target. They
decide in the first two sentences whether this is real.

---

## The structure

```markdown
# [Class] in [exact endpoint] allows [attacker role] to [impact] [victim scope]

## Summary
One or two sentences. Impact first, mechanism second. No preamble.

## Severity
<Critical|High|Medium|Low> - CVSS 3.1 <score> (<vector>)

## Affected
- endpoint:  POST https://api.target.com/v1/orders/{id}
- parameter: id (path)
- asset:     api.target.com (in scope per <program scope section>)
- tested:    2026-09-25 14:32 UTC, from <your source IP>
- accounts:  attacker  you+zpa@example.com  (uid 10041)
             victim    you+zpb@example.com  (uid 10042)  - both registered by me

## Steps to reproduce
1. Register two accounts (or use the two above).
2. As account B, create an order. Note its id: `ord_8831`.
3. As account A, send:
   ```http
   GET /v1/orders/ord_8831 HTTP/1.1
   Host: api.target.com
   Authorization: Bearer <ACCOUNT_A_TOKEN>
   ```
4. Account B's full order, including their name, address and last4, is returned.

## Evidence
<the request and response, redacted - see below>

## Impact
What an attacker gains, in the target's own business terms. Be concrete and be bounded:
say what you proved and what follows from it, and do not extrapolate past the evidence.

## Remediation
One or two sentences of the actual fix. Not a lecture.

## Notes
- No data belonging to real users was accessed; both accounts are mine.
- <cleanup performed: files deleted, webhooks removed, test objects destroyed>
- <anything you did NOT do, and why: "I did not use the retrieved credential.">
```

---

## The title formula

```
[Bug Class] in [Exact Endpoint] allows [attacker role] to [impact] [victim scope]
```

| Weak | Strong |
|---|---|
| "IDOR vulnerability found" | "IDOR in GET /v1/orders/{id} allows any authenticated user to read any other customer's order and shipping address" |
| "XSS on your website" | "Stored XSS in the display-name field executes for every viewer of /team, enabling session theft" |
| "Critical security issue!!!" | "Pre-auth RCE via SSTI in the invoice-template parameter of POST /invoices/preview" |

The title is the only part guaranteed to be read. Put the endpoint and the impact in it.

---

## Writing rules

- **Impact first.** Sentence one says what an attacker gets, not what technology is involved.
- **Exact HTTP.** Full requests and responses. A triager pastes them.
- **Under ~600 words** for the body. Length reads as padding, not rigour.
- **Plain declarative sentences.** No "malicious actor", no "leveraging this attack vector", no "as we all know".
- **No emoji, no ASCII art, no urgency theatre.** "CRITICAL!!!" reads as inexperience.
- **One finding per report.** Two bugs in one report get partially triaged and partially paid.
- **Except a chain** - a chain is one finding. Show the links in order, with each step's evidence.
- **State your uncertainty.** "I could not determine whether this also affects X" builds trust. Overclaiming destroys it.
- **Never criticise the developers.** The finding is the point.

---

## Redaction

Redact at capture time, not at write time.

| Remove | Keep |
|---|---|
| your session cookies and bearer tokens | trace ids, request ids, correlation headers |
| other users' PII (even from your own test accounts, trim to what proves it) | response shapes and field names |
| full API keys and secrets - first 4 chars and the format only | where the secret was found, and its type |
| internal IPs beyond the one that proves reach | the one internal host that proves the finding |
| full database or file dumps | the single record or line that proves access |

`***REDACTED***` inline is fine and expected. A report containing a live credential is a report
that has made the problem worse.

---

## Per-platform notes

| Platform | CVSS | Notes |
|---|---|---|
| **HackerOne** | 3.1 | markdown; attachments supported; weakness type from their taxonomy; the severity you set is a proposal, not a decision |
| **Bugcrowd** | VRT + 4.0 | map to the Vulnerability Rating Taxonomy explicitly - it drives the payout |
| **Intigriti** | 4.0 / their matrix | they want business impact spelled out |
| **YesWeHack** | 4.0 | often requests a video PoC for complex chains |
| **Immunefi** | their impact scale | a **runnable fork PoC is mandatory**; quantify funds at risk |
| **Self-hosted / security.txt** | your judgement | email to the `security.txt` contact; expect no triage process and be patient; state a disclosure timeline politely |

For a self-hosted or VDP disclosure, add: what you tested, when, that you stopped at proof, and
that you will not disclose publicly without agreement. Many of these are run by one overworked
engineer; a calm, complete, non-threatening email gets fixed faster.

---

## PoC packaging

| Finding type | The right PoC |
|---|---|
| any HTTP finding | copy-pasteable `curl`, or a raw HTTP request |
| XSS, CORS, `postMessage`, clickjacking | a **self-contained HTML file** plus a screenshot, hosted on your own domain |
| a chain | a numbered sequence, each step with its request and response |
| race condition | the script, plus the observed hit rate ("3 of 5 attempts") |
| smart contract | a Foundry test that pins the fork block and prints the loss |
| mobile | the exact app version and build, the `adb` command, a screenshot |
| blind (SSRF/XXE/RCE) | the collector log entry with the timestamp, plus the payload |

Keep it minimal: the shortest thing that reproduces. A 300-line script gets skimmed; three curl
commands get run.

Video only when the flow genuinely needs it (multi-step UI, a race, a mobile interaction). Keep it
under two minutes, no narration required, and never make it the *only* evidence - a triager cannot
copy-paste a video.

---

## Timing

- **Critical, and especially anything exploited in the wild:** file the same hour. Polish costs less than the exposure window.
- **Everything else:** file the same day you confirm it. Scope changes and duplicates arrive fast.
- **Re-test after the fix.** A bypass of the deployed patch is a new bug, and it is often the easiest high-value report you will write.
- **While waiting on triage,** keep escalating the chain rather than nudging. Do not ping for status inside the program's stated SLA.

---

## After submission

```
record it        .zeroprotocol/submissions.md: date, finding, platform, id, state, bounty
record the outcome too   N/A and duplicate outcomes are the data that improves your class priors
memory           write what the program paid for and what it rejected into your memory notes -
                 class priors are the part of bug bounty that compounds across engagements
retest the fix   a patch bypass is a new bug
do not disclose  no public write-up, no tweet, no screenshot, until the program agrees
```

---

## Never

- **Submit without a human reading it.** The rule this skill exists to enforce.
- Include a live credential, session token, or another user's PII.
- Report two unrelated bugs in one report.
- Claim impact you did not demonstrate.
- Threaten disclosure, mention a deadline aggressively, or ask about the bounty amount in the initial report.
- Ask for a bounty on a VDP.
- Report the same finding to two programs for the same asset without saying so.
- Disclose publicly before the program agrees - it is the fastest way to lose a bounty and a reputation.
- Send raw scanner output.
- Leave your test artifacts on the target: delete uploaded files, remove webhooks, release claimed resources, destroy test objects, and **say in the report that you did**.

---

## Hand off to

Drafted -> **the user**, for review and submission. Present the draft, say plainly that you have
not sent it, and name anything you are unsure about.
Duplicate or N/A comes back -> `zp-triage` to learn from it, then the queue.
Fix shipped -> re-test for a patch bypass with the original hunter skill.
