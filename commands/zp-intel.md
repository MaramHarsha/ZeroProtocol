---
name: zp-intel
description: "Prior art - what gets found and paid on a program, and whether a finding is a duplicate. Usage: /zp-intel shopify | /zp-intel dedup shopify idor orders"
---

# /zp-intel

Load `skills/zp-intel/SKILL.md`. Arguments: **$ARGUMENTS**

```bash
zp-intel program <handle>          # priors: what gets found and paid here
zp-intel class <class>             # how accepted reports of a class were framed
zp-intel dedup <program> <terms>   # exit 8 == likely duplicate
zp-intel update                    # refresh the index (first run fetches it)
```

Read the priors for the pattern, not the instance: a class appearing repeatedly means the codebase
has a *habit* of it, so hunt the siblings nobody reported and check whether shipped fixes hold.

A program with no disclosed reports is **not** evidence it is unpicked. Most programs never
disclose.
