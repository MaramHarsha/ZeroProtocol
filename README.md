<p align="center">
  <img src="assets/zeroprotocol-banner.png" alt="ZeroProtocol — built for bug bounty hunting and web security research" width="100%">
</p>

# ZeroProtocol

One protocol for authorized bug-bounty and web-security work, as **67 Claude Code skills**,
**5 agents**, **15 slash commands** and six helper programs. Clone it, ask Claude to check it, give it a target.

The authorization boundary is a program, not a promise: every skill that sends traffic calls
`zp-scope check` and obeys the exit code, so an out-of-scope host is refused mechanically rather
than remembered politely.

```
you:     hunt https://app.example.com
claude:  phase 0  mode?  -> bug bounty
         phase 1  scope  -> .zeroprotocol/scope.yaml written, NOT confirmed
                            passive recon starts; active testing stays locked
         you:     zp-scope confirm --by me --authorization https://hackerone.com/example
         phase 2  passive recon   CT logs, archives, JS bundles, GitHub
         phase 3  active recon    live hosts, tech, content discovery
         phase 4  rank            queue.md: P1 / P2 / blocked / chain-pending
         phase 5  hunt            routed to the class that matches the surface
         phase 6  prove           two stacks, redacted evidence, browser for client-side
         phase 7  triage          the seven questions; most leads die here, correctly
         phase 8  report          drafted for YOU to send. Never auto-submitted.
```

## Install

```bash
git clone https://github.com/MaramHarsha/ZeroProtocol
cd ZeroProtocol
./install.sh
```

Then open Claude Code in any directory and say `hunt <your authorized target>`.

`install.sh` symlinks `skills/` into `~/.claude/skills/` so the skills load in every session,
seeds the operating-discipline notes into the project memory directory, adds a marker-delimited
block to `~/.claude/CLAUDE.md`, and links `bin/zp-*` onto your PATH. It is idempotent, it backs
up anything it would displace, and `./install.sh --remove` undoes all of it.

```
./install.sh --copy           copy instead of symlink (survives deleting this clone)
./install.sh --dry-run        print every action, change nothing
./install.sh --no-global-md   skip the ~/.claude/CLAUDE.md block
./install.sh --remove         clean uninstall
```

Or just open Claude Code in this directory and say **"check this"** — `CLAUDE.md` tells Claude
what to do.

## The 67 skills

| | |
|---|---|
| **router** | `zeroprotocol` — owns the pipeline, the ranking, and the dispatch table |
| **gate & setup** | `zp-scope` `zp-toolchain` `zp-proxy` |
| **recon** | `zp-recon-passive` `zp-recon-active` `zp-content-discovery` `zp-js-secrets` `zp-takeover` |
| **injection** | `zp-xss` `zp-sqli` `zp-rce-ssti` `zp-xxe-lfi` `zp-upload` `zp-proto-pollution` |
| **access control** | `zp-idor` `zp-authz` `zp-jwt-oauth` |
| **server-side logic** | `zp-ssrf` `zp-smuggling` `zp-cache-poison` `zp-race` `zp-business-logic` |
| **interfaces** | `zp-api` `zp-graphql` `zp-cors` |
| **platforms** | `zp-cloud` `zp-mobile` `zp-web3` `zp-code-audit` |
| **AI systems** | `zp-llm` `zp-agentic` |
| **known CVEs** | `zp-cve-2026-41940` — cPanel/WHM pre-auth bypass · `zp-cve-lightrag` — three LightRAG advisories |
| **output** | `zp-triage` `zp-report` |

Each one carries its gate, an executable procedure, real commands with a documented fallback for
every tool it likes, payload tables, a **confirm-or-kill** section, the escalation paths, and the
pitfalls that make reports get closed.

## The five agents

| Agent | Runs | Network |
|---|---|---|
| `zp-recon-sweep` | passive fan-out over third-party sources | never touches the target |
| `zp-surface-probe` | probes and ranks one host | gated |
| `zp-class-hunter` | one vuln class, one host, isolated context | gated |
| `zp-verifier` | tries to **refute** a finding; defaults to REFUTED when unsure | read-only |
| `zp-report-drafter` | drafts the report from evidence on disk | **no network tools** |

Each re-checks `zp-scope` itself, because a subagent inherits none of the session's discipline.
The validator enforces that: an agent with network-capable tools and no gate is a hard error.

## The six helper programs

```bash
zp-scope check https://api.target.com/v1   # 0 allow · 1 deny · 3 unconfirmed · 4 no scope file
zp-doctor                                  # what works on this box, and how it degrades
zp-init target.com                         # scaffold .zeroprotocol/
zp-intel priors --sort trend               # measured base rates; dedup and program priors
zp-reports                                 # the exploit and CVE corpus tooling
zp-memory-seed                             # seed the operating notes into this project's memory
```

`zp-scope` is the keystone. `init` writes the contract, `confirm` requires a human to state their
authorization, `check` is what the skills call, and `filter` is the funnel you pipe a host list
through before anything touches it. Widening `in_scope` clears the confirmation automatically,
because nobody signed off on the new hosts.

`zp-doctor` exists because ZeroProtocol is built to **degrade, never to fail**. It has no
required tooling beyond `python3 curl dig git openssl jq`; everything else has a documented
fallback, and where there is no honest fallback (`nuclei`) the skills say the capability is
unavailable rather than substituting a weaker check and calling it coverage.

## Calibrated on the disclosure record

The pack does not only carry technique; it carries **measurement**. `intel/class-priors.csv` holds
base rates for 68 weakness classes, derived from 12,768 labelled publicly disclosed HackerOne
reports across 379 programs, 2013-2026.

```bash
zp-intel priors --sort trend    # which classes the field is currently paying for
zp-intel priors --gaps          # families this pack deliberately does not cover
```

It changes two decisions. The **queue** ranks by likelihood as well as impact — access control
went from 3.3% of labelled disclosures in 2014-2020 to 11.0% in 2023-2026, the largest rise of any
class, while CSRF fell 5.0% → 1.7% and clickjacking 1.4% → 0.1%. And the **kill gate** gets
calibrated: `Insufficient Logging` has 24 disclosed reports and zero disclosed bounties; stored XSS
discloses a bounty 19 points more often than reflected, so a reflected finding is worth ten more
minutes hunting its stored sibling.

Read as a prior, never a verdict. Disclosure is not a census, the bounty rate is a lower bound
because amounts are often withheld, and severity is the disclosure's own label. Method and the
full list of limits are in [`intel/README.md`](intel/README.md). No report text is vendored —
only counts and public links.

## What it will not do

ZeroProtocol is for programs you are enrolled in, engagements with a signed scope, and assets you
own. It is deliberately missing the other half of the usual toolkit:

- It will not send a packet to a host a confirmed scope file does not allow.
- It will not test an excluded class — DoS, volumetric, social engineering, physical, spam.
- It stops at **proof**. `id` output, not a shell. A version string, not a database dump. One
  bucket key, not the bucket. A fork test, not a mainnet transaction.
- It will not use a credential it discovers. Finding it is the bug.
- It will not mass-scan a host list.
- It will not submit a report. You read it and you send it.

Those limits are not timidity. Every one of them is the line between a Critical finding that gets
paid and an incident the program's lawyers handle — and none of them makes a report less likely
to be accepted.

## Acknowledgements

ZeroProtocol is a rewrite, not a repackage — but it was written by studying a lot of excellent
public work, and some of it requires attribution. **[NOTICE.md](NOTICE.md) records every source,
its licence, and exactly what was used.**

The load-bearing ones: **[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)**
(MIT / CC BY 4.0) — the per-class skill shape here descends from its `hunt-*` skills;
**[usestrix/strix](https://github.com/usestrix/strix)** (Apache-2.0) — the AI, business-logic and
semantic-confusion classes; **[vercel-labs/agent-browser](https://github.com/vercel-labs/agent-browser)**
(Apache-2.0) — the browser layer; **[sw33tLie/bbscope](https://github.com/sw33tLie/bbscope)**,
**[caido/skills](https://github.com/caido/skills)**,
**[PatrikFehrenbach/h1-brain](https://github.com/PatrikFehrenbach/h1-brain)** and
**[uphiago/recon-skills](https://github.com/uphiago/recon-skills)**.

## License

MIT — see [LICENSE](LICENSE). Authorized testing only; see [SECURITY.md](SECURITY.md).
