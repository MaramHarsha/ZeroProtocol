---
name: zp-report
description: "Draft a submission-ready report from a verified finding. Never submits. Usage: /zp-report"
---

# /zp-report

Load `skills/zp-report/SKILL.md` and `templates/report.md`.

Preconditions - refuse and say which is missing: `zp-triage` returned PASS or DOWNGRADE, and the
finding has been independently verified.

Write it for a tired triager with forty reports queued who has never seen this target. Impact in
sentence one. Exact HTTP they can paste. Under ~600 words. Redact at capture time - no session
cookies, no other users' PII, secrets as first-4-plus-format.

Draft to `.zeroprotocol/findings/NNN-slug.md`, then present it and state plainly that you have
**not** sent it. A human approves and submits every report.

For a clean-room draft, dispatch `zp-report-drafter` - it has no network tools, so it cannot
re-test or send anything.
