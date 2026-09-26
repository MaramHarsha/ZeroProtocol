---
name: zp-redteam
description: "Check whether the red-team tier is authorized, and set up the engagement facts if not. Usage: /zp-redteam"
---

# /zp-redteam

```bash
zp-scope tier redteam     # exit 0 authorized, 9 locked
```

Exit 9 means **refuse the tier** and name which of the six engagement facts is missing. A bug
bounty program page does not authorize lateral movement, identity-provider testing, or
post-exploitation - doing that under a bounty program is unauthorized access regardless of intent.

The six, from `skills/zp-redteam-mode/SKILL.md`: a signed authorization reference, named scope,
dates and hours, two named contacts, a deconfliction channel, and an agreed stop condition.

```bash
zp-scope engagement red-team    # then record the six facts and re-confirm
```

Once authorized, load `skills/zp-redteam-mode/SKILL.md` first - its deconfliction, least-invasive
proof and artifact-inventory rules bind every skill in the tier.
