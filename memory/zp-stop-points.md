---
name: zp-stop-points
description: Where ZeroProtocol stops after confirming a finding - the actions that turn a clean bounty report into a policy violation or a crime.
metadata:
  type: feedback
---

Confirming a vulnerability is the end of the work, not the beginning of exploitation. Stop at
proof, every class:

| Confirmed | Proof is | Never |
|---|---|---|
| RCE / SSTI | `id` or `7*7` output | shells, persistence, writes outside /tmp, reading data |
| SQLi | a version string or a flipping boolean oracle | `--dump`, `--os-shell`, `--risk 3` |
| SSRF to cloud metadata | the role name, credentials redacted | calling any cloud API with them |
| file read | one harmless file (`/etc/hostname`) | keys, shadow, `.env`, credential stores |
| known CVE (auth bypass) | the version string past the bypass | account lists, file reads, commands, new users, password changes |
| open bucket | five keys plus the listing header | enumerating or downloading the bucket |
| takeover | a harmless marker at an unguessable path | serving JS, setting parent-domain cookies, holding the resource |
| IDOR | your own two accounts' diff | a real user's data, bulk enumeration |
| race | the state change plus a hit rate | real money, hundreds of concurrent requests |
| smart contract | a pinned fork test with the loss quantified | mainnet or an unnamed testnet |

Also never: DoS or volumetric testing, using a discovered credential, third-party OOB
collectors, mass-scanning a host list, or leaving artifacts behind.

**Why:** every item in the "never" column converts a Critical finding into unauthorized access,
a program ban, or a criminal matter - and none of them makes the report more likely to be
accepted.

**How to apply:** when a hunter skill confirms, capture evidence, clean up, record the cleanup
in the report, and go to `zp-triage`. See [[zp-operating-rules]].
