# Notice and attribution

ZeroProtocol is released under the [MIT License](LICENSE). It is an original rewrite, not a
repackage — the phase gates, the mechanically-enforced scope contract, the per-class stop points,
the degradation contract and the agent tier are its own. But it was written by studying a large
body of public work, and several of those projects require attribution. This file records who,
what, and under which licence.

If you think something here is mis-attributed or under-attributed, please open an issue. Getting
this right matters more to us than being brief.

## Directly attributed sources

| Project | Licence | How ZeroProtocol uses it |
|---|---|---|
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | MIT (code) / **CC BY 4.0** (skill content) | **Foundational.** The per-class skill shape ZeroProtocol uses — context-to-payload mapping, the unique numeric canary, the confirm-or-kill section, high-value-target framing — was derived from studying its `hunt-*` skills. Several later classes were written against its skill text as the primary reference. |
| [usestrix/strix](https://github.com/usestrix/strix) | Apache-2.0 | Reference for `zp-llm`, `zp-agentic`, `zp-business-logic`, `zp-proto-pollution`, `zp-semantic-confusion`. The "name the invariant and verify it outside the transcript" framing and the effective-authority map come from its skill library. Its `agent_browser` integration pattern informed `zp-browser`. |
| [vercel-labs/agent-browser](https://github.com/vercel-labs/agent-browser) | Apache-2.0 | The browser CLI `zp-browser` drives. Per its own guidance, ZeroProtocol does **not** vendor its skill text; `zp-browser` defers to `agent-browser skills get core` at runtime so instructions match the installed version. |
| [sw33tLie/bbscope](https://github.com/sw33tLie/bbscope) | Apache-2.0 | Program-scope retrieval commands and per-platform scope semantics in `zp-scope`. |
| [caido/skills](https://github.com/caido/skills) | MIT | Proxy-driven testing workflow in `zp-proxy`. |
| [PatrikFehrenbach/h1-brain](https://github.com/PatrikFehrenbach/h1-brain) | MIT | The disclosed-report-corpus approach to duplicate checking, which `zp-intel` implements independently. |
| [uphiago/recon-skills](https://github.com/uphiago/recon-skills) | MIT | Recon methodology and the engagement-mode / budget framing in the `zeroprotocol` router. |
| [yaklang/hack-skills](https://github.com/yaklang/hack-skills), [snailsploit/claude-red](https://github.com/snailsploit/claude-red) | MIT | Consulted across several vulnerability classes. |

## Data and corpora

| Corpus | Licence | Status |
|---|---|---|
| CISA Known Exploited Vulnerabilities | public domain (US Gov) | **committed** — `reports/kev/` |
| [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT | fetched by `zp-reports sync nuclei` |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | GPL-2.0 | fetched by `zp-reports sync exploitdb` |
| [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | CC0-1.0 | fetched by `zp-reports sync poc` |
| [trickest/cve](https://github.com/trickest/cve) | MIT | fetched by `zp-reports sync trickest` |
| [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) | **no licence stated** | **not redistributed.** `zp-intel update` fetches it to your machine on first use. See below. |

### Why the HackerOne index is fetched rather than shipped

That dataset carries no licence, so no permission to redistribute it has been granted. Rather
than assume, ZeroProtocol fetches it at install time into a gitignored path. You get identical
functionality; nobody's compilation gets re-hosted without permission.

The same reasoning applies to HackerOne report bodies, which are the copyrighted work of the
researchers who wrote them. `zp-reports read <id>` fetches a single report for you to read.
Nothing bulk-scrapes or re-hosts them.

## Deliberately not used

**[trailofbits/skills](https://github.com/trailofbits/skills)** is licensed **CC BY-SA 4.0**.
ShareAlike would require derivative works to carry the same licence, which conflicts with
ZeroProtocol's MIT licence. It was cloned into the local reference corpus during research but
**no ZeroProtocol content is derived from it**, and it is not listed as a source. It is excellent
work and worth reading directly.

If you contribute to ZeroProtocol, please do not import CC BY-SA or copyleft-licensed content
without raising it first — see `CONTRIBUTING` guidance in `CLAUDE.md`.

## A note on the reference corpus

During development, 56 public bug-bounty and offensive-security skill repositories (~18,000
`SKILL.md` files) were cloned locally for study. That corpus is **not** part of this repository
and is not redistributed. Where a specific project shaped specific content, it is credited above
and in the relevant skill's closing line.
