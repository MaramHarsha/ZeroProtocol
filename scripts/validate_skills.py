#!/usr/bin/env python3
"""Validate the ZeroProtocol skill pack.

Checks the things that actually break a skill at runtime: malformed frontmatter, a
`name` that does not match its directory (Claude Code resolves by directory, so a
mismatch silently orphans the skill), a description too thin to route on, a body long
enough to bloat every session that loads it, and cross-references to zp-* skills that do
not exist.

    python3 scripts/validate_skills.py            # full report
    python3 scripts/validate_skills.py --quiet    # exit code only
    python3 scripts/validate_skills.py --strict    # warnings are failures

Exit 0 clean, 1 errors found.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS = REPO / "skills"

MAX_LINES = 520          # Claude Code starts warning around here
MIN_DESC = 120           # a description shorter than this routes badly
MAX_DESC = 1400
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# The router must be able to reach every hunter, or the hunter is dead weight.
ROUTER = "zeroprotocol"


def parse_frontmatter(text: str):
    """Return (dict, body, error).

    Claude Code parses this block as real YAML, so we must too. When PyYAML is
    available we use it and surface its exact error; otherwise we fall back to the
    flat `key: value` reader below, plus an explicit check for the one construct
    that silently broke two skills: an unquoted value containing ": ", which YAML
    reads as a nested mapping ("mapping values are not allowed in this context").
    """
    if not text.startswith("---"):
        return None, text, "no YAML frontmatter (file must start with ---)"
    end = text.find("\n---", 3)
    if end == -1:
        return None, text, "frontmatter is not terminated by a --- line"
    raw = text[3:end].strip("\n")
    body = text[end + 4:]

    try:
        import yaml
    except ImportError:
        yaml = None

    if yaml is not None:
        try:
            loaded = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)
            where = f" at line {mark.line + 1} column {mark.column + 1}" if mark else ""
            return None, body, (f"frontmatter is not valid YAML{where}: "
                                f"{getattr(e, 'problem', e)}. A value containing ': ' "
                                f"must be quoted or rephrased")
        if not isinstance(loaded, dict):
            return None, body, "frontmatter must be a mapping of key: value"
        return {k: ("" if v is None else v) for k, v in loaded.items()}, body, None

    for line in raw.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$", line)
        if m and m.group(2) and m.group(2)[0] not in "\"'" and re.search(r":\s", m.group(2)):
            return None, body, (f"{m.group(1)}: unquoted value contains ': ', which YAML reads "
                                f"as a nested mapping - quote it or rephrase")
    meta, key = {}, None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$", line)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            meta[key] = val
        elif key and (line.startswith(" ") or line.startswith("\t")):
            meta[key] = (meta[key] + " " + line.strip()).strip()
        else:
            return None, body, f"cannot parse frontmatter line: {line!r}"
    return meta, body, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args()

    if not SKILLS.is_dir():
        print("no skills/ directory", file=sys.stderr)
        return 1

    dirs = sorted(d for d in SKILLS.iterdir() if d.is_dir())
    errors: list[str] = []
    warns: list[str] = []
    names: set[str] = set()
    referenced: set[str] = set()
    rows = []

    for d in dirs:
        sk = d / "SKILL.md"
        rel = sk.relative_to(REPO)
        if not sk.is_file():
            errors.append(f"{d.name}: no SKILL.md")
            continue
        text = sk.read_text(encoding="utf-8")
        nlines = text.count("\n") + 1
        meta, body, err = parse_frontmatter(text)
        if err:
            errors.append(f"{rel}: {err}")
            continue

        name = meta.get("name", "")
        desc = meta.get("description", "")

        if not name:
            errors.append(f"{rel}: frontmatter has no `name`")
        elif name != d.name:
            errors.append(f"{rel}: name is {name!r} but the directory is {d.name!r} "
                          "- Claude Code resolves by directory, so this skill would be orphaned")
        elif not NAME_RE.match(name):
            errors.append(f"{rel}: name {name!r} must be lowercase kebab-case")
        else:
            names.add(name)

        if not desc:
            errors.append(f"{rel}: frontmatter has no `description` - the router cannot fire it")
        else:
            if len(desc) < MIN_DESC:
                warns.append(f"{rel}: description is {len(desc)} chars; under {MIN_DESC} "
                             "routes unreliably - name the phrases a user would type")
            if len(desc) > MAX_DESC:
                warns.append(f"{rel}: description is {len(desc)} chars, over {MAX_DESC}")
            low = desc.lower()
            # "Use before ...", "Use at ...", "Use to ..." are all valid trigger phrasings;
            # matching only "use when" flagged good descriptions as bad.
            if not any(w in low for w in ("use when", "use whenever", "use before", "use at",
                                          "use to", "use for", "use after", "fires")):
                warns.append(f"{rel}: description never says WHEN to use it")
            if name != ROUTER and "zeroprotocol" not in low:
                warns.append(f"{rel}: description does not mention ZeroProtocol")

        for extra in set(meta) - {"name", "description", "allowed-tools", "license",
                                  "version", "phase", "gate"}:
            warns.append(f"{rel}: frontmatter key {extra!r} is not honoured by Claude Code")

        if nlines > MAX_LINES:
            warns.append(f"{rel}: {nlines} lines, over {MAX_LINES} - move payload "
                         "catalogues into reference/")

        if name != ROUTER:
            head = body[:1200]
            if not re.search(r"\*\*Gate:\*\*|^## Gate", head, re.M):
                warns.append(f"{rel}: no **Gate:** line near the top - a skill can be "
                             "loaded without the router, so it must state its own gate")

        # Only a backticked token counts as a skill reference. Bare `zp-`-prefixed
        # strings are everywhere in these skills as payload canaries and marker names
        # (zp-canary-91234, zp-exec-91234), and they are not cross-references.
        referenced.update(re.findall(r"`(zp-[a-z0-9-]+)`", text))
        rows.append((d.name, nlines, len(desc)))

    # bin/zp-* and scripts/zp-*.py are helper PROGRAMS, and .claude/agents/zp-*.md are AGENTS -
    # none of them are skills, so a mention of one is not a dangling skill reference.
    helpers = {p.name for p in (REPO / "bin").glob("zp-*")} if (REPO / "bin").is_dir() else set()
    helpers |= {p.stem for p in SKILLS.rglob("scripts/zp-*.py")}
    helpers |= {p.stem for p in (REPO / ".claude" / "agents").glob("zp-*.md")}
    referenced -= helpers

    # every hunter must be reachable from the router
    router_file = SKILLS / ROUTER / "SKILL.md"
    if router_file.is_file():
        router_text = router_file.read_text(encoding="utf-8")
        for n in sorted(names):
            if n == ROUTER:
                continue
            if n not in router_text:
                errors.append(f"skills/{ROUTER}/SKILL.md: does not reference {n} "
                              "- nothing would ever route to it")
    else:
        errors.append(f"skills/{ROUTER}/SKILL.md is missing - there is no router")

    for ref in sorted(referenced - names):
        errors.append(f"dangling reference to {ref!r}: no skills/{ref}/ directory exists")

    # ---- agents ---------------------------------------------------------- #
    agent_rows = []
    agents_dir = REPO / ".claude" / "agents"
    if agents_dir.is_dir():
        for af in sorted(agents_dir.glob("zp-*.md")):
            rel = af.relative_to(REPO)
            text = af.read_text(encoding="utf-8")
            meta, body, err = parse_frontmatter(text)
            if err:
                errors.append(f"{rel}: {err}")
                continue
            name = meta.get("name", "")
            desc = meta.get("description", "")
            tools = meta.get("tools", "")

            if name != af.stem:
                errors.append(f"{rel}: name is {name!r} but the file is {af.stem!r}.md")
            if not desc:
                errors.append(f"{rel}: no `description` - nothing would ever select this agent")
            elif len(desc) < MIN_DESC:
                warns.append(f"{rel}: description is {len(desc)} chars; under {MIN_DESC} "
                             "selects unreliably")
            if not tools:
                warns.append(f"{rel}: no `tools` - it will inherit the full tool set")

            # The rule that matters: an agent that can send traffic must carry the gate,
            # because a subagent inherits none of the session's discipline.
            can_reach_network = any(t in tools for t in ("Bash", "WebFetch", "WebSearch")) or not tools
            if can_reach_network and "zp-scope check" not in body:
                errors.append(
                    f"{rel}: has network-capable tools ({tools or 'inherited: all'}) but never "
                    "states `zp-scope check` - a subagent inherits nothing, so it would hunt "
                    "without a gate")
            # The contract may be a table, a `0` proceed · `1` refuse list, or prose. Look for
            # all four exit codes as standalone tokens in the window after the gate command,
            # rather than matching one phrasing.
            if can_reach_network:
                i = body.find("zp-scope check")
                window = body[i:i + 1800] if i != -1 else ""
                missing = [c for c in "0134" if not re.search(rf"(?<![\w.]){c}(?![\w.])", window)]
                if missing:
                    warns.append(f"{rel}: gate section does not state exit code(s) "
                                 f"{', '.join(missing)} - spell out the full 0/1/3/4 contract")
            agent_rows.append((af.stem, text.count("\n") + 1, len(desc), tools or "inherited"))

    if not args.quiet:
        print(f"ZeroProtocol skill pack: {len(rows)} skills\n")
        w = max((len(r[0]) for r in rows), default=10)
        for n, nl, dl in rows:
            print(f"  {n:<{w}}  {nl:>4} lines  desc {dl:>4}")
        total = sum(r[1] for r in rows)
        print(f"\n  {total} lines of skill content across {len(rows)} skills")
        if agent_rows:
            print(f"\n  {len(agent_rows)} agents")
            aw = max(len(r[0]) for r in agent_rows)
            for n, nl, dl, tl in agent_rows:
                print(f"    {n:<{aw}}  {nl:>4} lines  desc {dl:>4}  tools: {tl}")
        if warns:
            print(f"\n{len(warns)} warning(s):")
            for x in warns:
                print(f"  ! {x}")
        if errors:
            print(f"\n{len(errors)} error(s):")
            for x in errors:
                print(f"  X {x}")
        if not errors and not warns:
            print("\nclean")

    if errors:
        return 1
    return 1 if (args.strict and warns) else 0


if __name__ == "__main__":
    sys.exit(main())
