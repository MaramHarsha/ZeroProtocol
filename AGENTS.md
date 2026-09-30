# ZeroProtocol

Authorized bug-bounty and web-security work. 68 skills behind one router skill, seven helper
programs, and a prior-art library of 138,400 public write-ups.

This file is the portable instruction set. Codex, OpenCode and any other agent that reads
`AGENTS.md` gets the operating rules here; Claude Code gets the same content from `CLAUDE.md`.

## Scope: authorized testing only

A bug bounty program you are enrolled in, an engagement with a signed scope, or an asset you
own. Nothing else. The gate below is what makes that mechanical rather than aspirational.

## The three laws

**1. No packet leaves without a confirmed scope.** `zp-scope` is a program, not a promise.
Before anything touches a target:

```bash
zp-scope check "https://target.example.com/path"
```

| Exit | Meaning | What you do |
|---|---|---|
| 0 | in scope, human-confirmed | proceed |
| 1 | out of scope | refuse, name the denying pattern, do not retry |
| 3 | not confirmed yet | **passive recon only**; take the user through `zp-scope confirm` |
| 4 | no scope file | stop; run `zp-scope init` |

Any error is a deny. Never hand-roll the check. Never reuse an allow for a different host.
Only a human runs `zp-scope confirm`, with their authorization in their own words — never do it
on their behalf. Passive recon (certificate transparency, archives, search engines) is permitted
while unconfirmed, because it queries third parties rather than the target.

**2. No theoretical findings.** Can an attacker do this right now, against a user who took no
unusual action, causing nameable harm? "Could theoretically", self-XSS, dead code, lone missing
headers and DNS-only SSRF callbacks are killed on sight.

**3. Evidence before claim.** Reproduce before calling anything confirmed; two independent
stacks for High and Critical; redact at capture time, not as cleanup.

## Start here

Load the `zeroprotocol` skill. It owns the phase pipeline — scope gate, passive recon, surface
map, ranked class hunt, proof, triage, report — and routes to the other 67 skills. Do not
improvise a pipeline of your own.

If your tool lists skills, ask for `zeroprotocol`. If it does not, read
`skills/zeroprotocol/SKILL.md` directly and follow its phases.

## Helper programs

All seven are stdlib Python or POSIX shell and work in any agent that can run a shell:

```bash
zp-scope check <url>            # the gate. 0 allow · 1 deny · 3 unconfirmed · 4 no scope file
zp-doctor                       # what works on this box, and how it degrades
zp-init <target>                # scaffold .zeroprotocol/
zp-corpus search <terms>        # 138,400 public write-ups: find one, then FETCH its url
zp-intel priors --sort trend    # measured class base rates; dedup; program priors
zp-reports                      # exploit and CVE corpus tooling
zp-memory-seed                  # seed the operating notes into a project memory dir
```

`zp-corpus` holds titles and source links only, never body text. A search result is a reading
list, not an answer: fetch the URL of anything relevant and read it at the source.

## Never

- Send a packet to a host that `zp-scope check` did not clear.
- Test a class the program excludes (DoS, volumetric, social engineering, physical, spam).
- Use a real user's data as proof. Register two of your own accounts instead.
- Exfiltrate more than the minimum that proves the issue — one record, not the table.
- Leave a shell, a file, a user, or a webhook behind. Clean up and record the cleanup.
- Auto-submit a report, auto-purge a cache, auto-send mail, or use a credential you found.
- Claim "exhausted" on the strength of one payload, or on an auxiliary tool's silence.

**A human approves every submission, every time.**

## Working on this repository

See `CLAUDE.md` for the authoring rules — skill shape, the router's dispatch table, the
520-line skill budget, and `python3 scripts/validate_skills.py`, which must pass before any
commit.
