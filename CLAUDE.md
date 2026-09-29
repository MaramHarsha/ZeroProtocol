# ZeroProtocol

This repository is **ZeroProtocol**: a unified skill pack for authorized bug-bounty and
web-security work. Sixty-seven `zp-*` skills behind one router skill, plus seven helper
programs that make the authorization boundary mechanical instead of aspirational.

## If the user just cloned this and said "check this" / "set this up" / "install this"

Do this, in order:

1. Run `./install.sh`. It symlinks `skills/` into `~/.claude/skills/`, seeds the
   operating-discipline notes into the project memory directory, adds a marker-delimited
   block to `~/.claude/CLAUDE.md`, and links `bin/zp-*` onto PATH. It is idempotent and
   backs up anything it would displace. `./install.sh --remove` undoes all of it.
2. Run `python3 scripts/validate_skills.py` and `bin/zp-doctor` and report what came back
   — especially which capabilities are running on fallbacks, because that changes what
   the user can actually do today.
3. Tell them the skills load automatically in **new** sessions, and that for the session
   they are in right now you can work from `skills/zeroprotocol/SKILL.md` directly.
4. Ask for a target, and say plainly that ZeroProtocol will not send a packet until a
   scope file is confirmed.

Do **not** start scanning anything during setup.

## If the user gives a target

Load `skills/zeroprotocol/SKILL.md` and follow its phases. It routes to the other
skills; do not improvise a pipeline of your own.

The short version of what that skill enforces:

- **Phase 1 is a gate, not a formality.** `zp-scope check <target>` returns 0 allow,
  1 deny, 3 unconfirmed, 4 no scope file. Obey it. An error is a deny. Never
  hand-roll the check, never reuse a previous allow for a different host.
- **Passive recon is allowed while the scope is unconfirmed** — it queries third parties,
  not the target. Anything that touches the target is not.
- **Only a human confirms a scope.** Ask for the authorization in their words and record
  their words. Never run `zp-scope confirm` on their behalf on your own initiative.
- **No theoretical findings**, and **never auto-submit** a report.

## Working on this repo (editing the skills themselves)

- One skill per directory: `skills/<name>/SKILL.md`, frontmatter `name` matching the
  directory exactly, and a `description` written in the third person that names the
  trigger phrases a user would actually type.
- `skills/zeroprotocol/SKILL.md` is the style exemplar and the only router. New hunter
  skills must be added to its dispatch table and skill index, or nothing will reach them.
- Keep a skill under ~500 lines. Density over completeness: a table beats a paragraph.
  Push long payload catalogues into `skills/<name>/reference/`.
- Every skill that sends traffic states its gate in the header and repeats the exit-code
  contract. That repetition is deliberate — a skill may be loaded without the router.
- Run `python3 scripts/validate_skills.py` before committing. It is also wired into
  `install.sh`.
- Reference corpus (54 upstream bug-bounty skill repos, read-only, not a submodule) lives
  at `../Bug-Bounty-Skills` on the authoring machine. It is not required to use this pack.

## Repository layout

```
skills/            68 skills: zeroprotocol (router) + 67 zp-*
.claude/agents/    5 agents, each carrying the scope contract
bin/zp-scope       the authorization gate - exit codes are the contract
bin/zp-doctor      toolchain survey: what works, what degrades, how it degrades
bin/zp-init        scaffold a .zeroprotocol/ engagement workspace
memory/            notes seeded into the user's memory dir by install.sh
templates/         scope.yaml, finding, report skeletons
scripts/           validate_skills.py
```
