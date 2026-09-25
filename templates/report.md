# [Bug Class] in [exact endpoint] allows [attacker role] to [impact] [victim scope]

## Summary
<One or two sentences. Impact first, mechanism second. No preamble.>

## Severity
<Critical|High|Medium|Low> - CVSS 3.1 <score> (<AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N>)

<!-- HackerOne: CVSS 3.1. Bugcrowd: map to the VRT. Intigriti/YesWeHack/Immunefi: 4.0 or their
     own scale. Score only what you demonstrated. -->

## Affected
- endpoint:  <METHOD https://host/path>
- parameter: <name (location)>
- asset:     <host> (in scope per <program scope section>)
- tested:    <YYYY-MM-DD HH:MM UTC>, from <your source IP>
- accounts:  attacker  <you+zpa@example.com>  (uid <...>)
             victim    <you+zpb@example.com>  (uid <...>)  - both registered by me

## Steps to reproduce
1. <setup: accounts, an object to target>
2. <the request, as raw HTTP or a curl a triager can paste>
   ```http
   GET /v1/orders/<id> HTTP/1.1
   Host: <host>
   Authorization: Bearer <ATTACKER_TOKEN>
   ```
3. <what comes back, and why that is wrong>

## Evidence
<request and response, redacted: no session cookies, no other users' PII, secrets as first-4 + format>

## Impact
<What an attacker gains, in the target's business terms. Bounded by what you proved.>

## Remediation
<One or two sentences of the actual fix.>

## Notes
- No data belonging to real users was accessed; both accounts are mine.
- Cleanup: <files deleted / webhooks removed / test objects destroyed / resource released>
- Not done: <e.g. "I did not use the retrieved credential." / "I stopped at verification.">
