---
name: zp-class
description: "Hunt one vulnerability class against one host, with the depth floor enforced. Usage: /zp-class idor api.target.com"
---

# /zp-class

Hunt exactly one class against one host: **$ARGUMENTS**.

Load the matching `skills/zp-<class>/SKILL.md` and follow it. Check `zp-scope check` yourself
first, and read the rules of engagement - if the class is in `excluded_vuln_classes`, stop.

Meet the depth floor before writing "exhausted": the variant matrix built before the first
request, a benign and a known-bad baseline, the encoding ladder walked and then stacked, auth
states rotated, and partially-firing payloads replayed on sibling endpoints. Minimum 25 distinct
attempts on a P1 surface.

Write `coverage/<host>/<class>.json` either way. Stop at the proof point the skill defines.

For a wide sweep, dispatch the `zp-class-hunter` agent per (host, class) pair instead - one host
and one class each, and give every invocation its own `--session` if it needs a browser.
