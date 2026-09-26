#!/usr/bin/env bash
#
# ZeroProtocol installer.
#
# Links the ZeroProtocol skills into your Claude config so they load in every
# session, seeds the operating-discipline memory notes, and puts the zp-* helper
# programs on your PATH.
#
#   ./install.sh                  link skills, seed memory, wire PATH
#   ./install.sh --copy           copy instead of symlink (survives deleting this clone)
#   ./install.sh --remove         clean uninstall, restores anything it backed up
#   ./install.sh --dry-run        print every action, change nothing
#   ./install.sh --no-memory      skip the memory seed
#   ./install.sh --no-global-md   skip the ~/.claude/CLAUDE.md block
#   ./install.sh --project DIR    also seed memory for that project directory
#   ./install.sh --claude-dir DIR install into a different Claude config root
#
# Idempotent: re-running relinks and re-seeds without duplicating anything.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
BIN_DIR="${ZP_BIN_DIR:-$HOME/.local/bin}"
MODE=link
DO_MEMORY=1
DO_GLOBAL_MD=1
DRY=0
EXTRA_PROJECTS=()
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

BEGIN_MARK="<!-- ZEROPROTOCOL:BEGIN - managed by install.sh, do not edit inside -->"
END_MARK="<!-- ZEROPROTOCOL:END -->"

while [ $# -gt 0 ]; do
  case "$1" in
    --copy)         MODE=copy ;;
    --remove|--uninstall) MODE=remove ;;
    --dry-run|-n)   DRY=1 ;;
    --no-memory)    DO_MEMORY=0 ;;
    --no-global-md) DO_GLOBAL_MD=0 ;;
    --project)      EXTRA_PROJECTS+=("${2:?--project needs a directory}"); shift ;;
    --claude-dir)   CLAUDE_DIR="${2:?--claude-dir needs a directory}"; shift ;;
    --bin-dir)      BIN_DIR="${2:?--bin-dir needs a directory}"; shift ;;
    -h|--help)      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

SKILLS_SRC="$REPO/skills"
SKILLS_DST="$CLAUDE_DIR/skills"
BACKUP_DIR="$CLAUDE_DIR/zeroprotocol-backups/$STAMP"

say()  { printf '%s\n' "$*"; }
step() { printf '  %s\n' "$*"; }
run()  { if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else eval "$@"; fi; }

# Claude Code derives a project's memory directory from its path by replacing
# every non-alphanumeric character with a dash.
project_slug() { printf '%s' "$1" | sed 's/[^a-zA-Z0-9]/-/g'; }

# --------------------------------------------------------------------------- #
# sanity
# --------------------------------------------------------------------------- #
[ -d "$SKILLS_SRC" ] || { echo "install.sh: no skills/ directory beside this script" >&2; exit 1; }
mapfile -t SKILL_DIRS < <(find "$SKILLS_SRC" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
[ "${#SKILL_DIRS[@]}" -gt 0 ] || { echo "install.sh: skills/ is empty" >&2; exit 1; }

say ""
say "ZeroProtocol"
say "  repo         $REPO"
say "  claude dir   $CLAUDE_DIR"
say "  skills       ${#SKILL_DIRS[@]}"
say "  mode         $MODE$([ "$DRY" = 1 ] && echo ' (dry run)')"
say ""

# --------------------------------------------------------------------------- #
# uninstall
# --------------------------------------------------------------------------- #
if [ "$MODE" = remove ]; then
  say "Removing ZeroProtocol"
  for s in "${SKILL_DIRS[@]}"; do
    d="$SKILLS_DST/$s"
    if [ -L "$d" ]; then
      tgt="$(readlink "$d")"
      case "$tgt" in
        "$SKILLS_SRC"/*) run "rm -f '$d'"; step "unlinked $s" ;;
        *) step "left $s alone (symlink points outside this repo)" ;;
      esac
    elif [ -d "$d" ] && [ -f "$d/.zeroprotocol-installed" ]; then
      run "rm -rf '$d'"; step "removed copied $s"
    elif [ -e "$d" ]; then
      step "left $s alone (not installed by ZeroProtocol)"
    fi
  done

  for a in "$REPO"/.claude/agents/zp-*.md; do
    [ -f "$a" ] || continue
    d="$CLAUDE_DIR/agents/$(basename "$a")"
    if [ -L "$d" ] && [ "$(readlink "$d")" = "$a" ]; then
      run "rm -f '$d'"; step "unlinked agent $(basename "${a%.md}")"
    elif [ -f "$d" ] && cmp -s "$a" "$d"; then
      run "rm -f '$d'"; step "removed copied agent $(basename "${a%.md}")"
    fi
  done

  for c in "$REPO"/commands/zp-*.md; do
    [ -f "$c" ] || continue
    d="$CLAUDE_DIR/commands/$(basename "$c")"
    if [ -L "$d" ] && [ "$(readlink "$d")" = "$c" ]; then
      run "rm -f '$d'"; step "unlinked /$(basename "${c%.md}")"
    elif [ -f "$d" ] && cmp -s "$c" "$d"; then
      run "rm -f '$d'"; step "removed copied /$(basename "${c%.md}")"
    fi
  done

  # restore the newest backup, if any
  newest="$(find "$CLAUDE_DIR/zeroprotocol-backups" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1 || true)"
  if [ -n "$newest" ] && [ -d "$newest" ]; then
    while IFS= read -r b; do
      n="$(basename "$b")"
      [ -e "$SKILLS_DST/$n" ] || { run "cp -a '$b' '$SKILLS_DST/$n'"; step "restored pre-existing $n"; }
    done < <(find "$newest" -mindepth 1 -maxdepth 1 2>/dev/null)
  fi

  GLOBAL_MD="$CLAUDE_DIR/CLAUDE.md"
  if [ -f "$GLOBAL_MD" ] && grep -qF "$BEGIN_MARK" "$GLOBAL_MD" 2>/dev/null; then
    if [ "$DRY" = 1 ]; then
      step "[dry-run] strip ZeroProtocol block from $GLOBAL_MD"
    else
      python3 - "$GLOBAL_MD" "$BEGIN_MARK" "$END_MARK" <<'PY'
import re, sys
p, b, e = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(p, encoding="utf-8").read()
t = re.sub(re.escape(b) + r".*?" + re.escape(e) + r"\n?", "", t, flags=re.S)
open(p, "w", encoding="utf-8").write(t.rstrip() + "\n" if t.strip() else "")
PY
      step "stripped the ZeroProtocol block from CLAUDE.md"
    fi
  fi

  for b in "$BIN_DIR"/zp-*; do
    [ -L "$b" ] || continue
    case "$(readlink "$b")" in "$REPO"/bin/*) run "rm -f '$b'"; step "unlinked $(basename "$b")" ;; esac
  done

  say ""
  say "Removed. Memory notes were left in place - they are yours now."
  say "To drop them too: rm ~/.claude/projects/*/memory/zp-*.md"
  exit 0
fi

# --------------------------------------------------------------------------- #
# 1. skills
# --------------------------------------------------------------------------- #
say "1. Skills -> $SKILLS_DST"
run "mkdir -p '$SKILLS_DST'"
backed_up=0
for s in "${SKILL_DIRS[@]}"; do
  src="$SKILLS_SRC/$s"
  dst="$SKILLS_DST/$s"

  if [ -L "$dst" ]; then
    if [ "$(readlink "$dst")" = "$src" ]; then step "ok   $s"; continue; fi
    run "rm -f '$dst'"
  elif [ -e "$dst" ]; then
    # something real is already there and it is not ours - keep it safe
    if [ ! -f "$dst/.zeroprotocol-installed" ]; then
      run "mkdir -p '$BACKUP_DIR'"
      run "mv '$dst' '$BACKUP_DIR/$s'"
      backed_up=$((backed_up + 1))
      step "backed up an existing $s"
    else
      run "rm -rf '$dst'"
    fi
  fi

  if [ "$MODE" = copy ]; then
    run "cp -a '$src' '$dst'"
    run "touch '$dst/.zeroprotocol-installed'"
    step "copied $s"
  else
    run "ln -s '$src' '$dst'"
    step "linked $s"
  fi
done
[ "$backed_up" -gt 0 ] && step "backups in $BACKUP_DIR (outside skills/, so they never load as duplicates)"

# --------------------------------------------------------------------------- #
# 1b. agents
# --------------------------------------------------------------------------- #
AGENTS_SRC="$REPO/.claude/agents"
AGENTS_DST="$CLAUDE_DIR/agents"
if [ -d "$AGENTS_SRC" ]; then
  say ""
  say "1b. Agents -> $AGENTS_DST"
  run "mkdir -p '$AGENTS_DST'"
  for a in "$AGENTS_SRC"/zp-*.md; do
    [ -f "$a" ] || continue
    n="$(basename "$a")"
    dst="$AGENTS_DST/$n"
    if [ -L "$dst" ] && [ "$(readlink "$dst")" = "$a" ]; then
      step "ok   ${n%.md}"; continue
    fi
    if [ -e "$dst" ] && [ ! -L "$dst" ]; then
      run "mkdir -p '$BACKUP_DIR/agents'"
      run "mv '$dst' '$BACKUP_DIR/agents/$n'"
      step "backed up an existing ${n%.md}"
    fi
    if [ "$MODE" = copy ]; then
      run "cp -f '$a' '$dst'"; step "copied ${n%.md}"
    else
      run "ln -sfn '$a' '$dst'"; step "linked ${n%.md}"
    fi
  done
fi

# --------------------------------------------------------------------------- #
# 1c. slash commands
# --------------------------------------------------------------------------- #
CMDS_SRC="$REPO/commands"
CMDS_DST="$CLAUDE_DIR/commands"
if [ -d "$CMDS_SRC" ]; then
  say ""
  say "1c. Commands -> $CMDS_DST"
  run "mkdir -p '$CMDS_DST'"
  for c in "$CMDS_SRC"/zp-*.md; do
    [ -f "$c" ] || continue
    n="$(basename "$c")"; dst="$CMDS_DST/$n"
    if [ -L "$dst" ] && [ "$(readlink "$dst")" = "$c" ]; then step "ok   /${n%.md}"; continue; fi
    if [ -e "$dst" ] && [ ! -L "$dst" ]; then
      run "mkdir -p '$BACKUP_DIR/commands'"; run "mv '$dst' '$BACKUP_DIR/commands/$n'"
      step "backed up an existing /${n%.md}"
    fi
    if [ "$MODE" = copy ]; then run "cp -f '$c' '$dst'"; step "copied /${n%.md}"
    else run "ln -sfn '$c' '$dst'"; step "linked /${n%.md}"; fi
  done
fi

# --------------------------------------------------------------------------- #
# 2. helper programs on PATH
# --------------------------------------------------------------------------- #
say ""
say "2. Helpers"
run "chmod +x '$REPO'/bin/zp-*"
if [ -d "$BIN_DIR" ] && [ -w "$BIN_DIR" ]; then
  for b in "$REPO"/bin/zp-*; do
    n="$(basename "$b")"
    run "ln -sfn '$b' '$BIN_DIR/$n'"
  done
  step "linked into $BIN_DIR"
  case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) step "NOTE $BIN_DIR is not on your PATH - add:"
       step "     export PATH=\"$BIN_DIR:\$PATH\"" ;;
  esac
else
  step "$BIN_DIR not available - add this to your shell profile:"
  step "     export PATH=\"$REPO/bin:\$PATH\""
fi

# --------------------------------------------------------------------------- #
# 3. global instructions block
# --------------------------------------------------------------------------- #
if [ "$DO_GLOBAL_MD" = 1 ]; then
  say ""
  say "3. Operating rules -> $CLAUDE_DIR/CLAUDE.md"
  GLOBAL_MD="$CLAUDE_DIR/CLAUDE.md"
  BLOCK="$(cat <<EOF
$BEGIN_MARK
## ZeroProtocol

Authorized security testing is governed by the \`zeroprotocol\` skill. When a target is
handed over (URL, domain, wildcard, program handle, IP, APK, or repo) for testing,
hunting, recon, or audit, load that skill first and follow its phases.

Three rules that hold even if no skill is loaded:

1. **No packet without a confirmed scope.** Run \`zp-scope check <target>\` and obey the
   exit code (0 allow, 1 deny, 3 unconfirmed, 4 no scope file). An error is a deny.
   Passive recon against third-party sources is allowed while unconfirmed; anything that
   touches the target is not.
2. **No theoretical findings.** Impact reproducible now, against a user who did nothing
   unusual, or it is not a finding.
3. **Never auto-submit.** A human approves every report, every time.

Installed from: $REPO
$END_MARK
EOF
)"
  if [ "$DRY" = 1 ]; then
    step "[dry-run] write the ZeroProtocol block"
  else
    mkdir -p "$CLAUDE_DIR"
    touch "$GLOBAL_MD"
    if grep -qF "$BEGIN_MARK" "$GLOBAL_MD"; then
      BLOCK="$BLOCK" python3 - "$GLOBAL_MD" "$BEGIN_MARK" "$END_MARK" <<'PY'
import os, re, sys
p, b, e = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(p, encoding="utf-8").read()
t = re.sub(re.escape(b) + r".*?" + re.escape(e), os.environ["BLOCK"], t, flags=re.S)
open(p, "w", encoding="utf-8").write(t)
PY
      step "refreshed the existing block (nothing else in CLAUDE.md was touched)"
    else
      printf '\n%s\n' "$BLOCK" >> "$GLOBAL_MD"
      step "appended the block"
    fi
  fi
fi

# --------------------------------------------------------------------------- #
# 4. memory seed
# --------------------------------------------------------------------------- #
if [ "$DO_MEMORY" = 1 ] && [ -d "$REPO/memory" ]; then
  say ""
  say "4. Memory notes"
  targets=("$REPO" "$PWD")
  for e in ${EXTRA_PROJECTS+"${EXTRA_PROJECTS[@]}"}; do targets+=("$(cd "$e" 2>/dev/null && pwd || echo "$e")"); done
  # de-duplicate
  mapfile -t targets < <(printf '%s\n' "${targets[@]}" | awk '!seen[$0]++')
  for proj in "${targets[@]}"; do
    slug="$(project_slug "$proj")"
    mem="$CLAUDE_DIR/projects/$slug/memory"
    if [ "$DRY" = 1 ]; then
      step "[dry-run] seed $mem"
      continue
    fi
    # zp-memory-seed owns the path resolution and the MEMORY.md merge, so the logic
    # lives in exactly one place and the user can re-run it for any directory later.
    CLAUDE_CONFIG_DIR="$CLAUDE_DIR" python3 "$REPO/bin/zp-memory-seed" "$proj" \
      | sed 's/^/    /'
  done
  step "these load automatically for those project directories"
fi

# --------------------------------------------------------------------------- #
# 5. verify
# --------------------------------------------------------------------------- #
say ""
say "5. Check"
if [ "$DRY" = 1 ]; then
  step "[dry-run] skipped"
else
  if python3 "$REPO/scripts/validate_skills.py" --quiet 2>/dev/null; then
    step "all ${#SKILL_DIRS[@]} skills valid"
  else
    step "validator reported problems - run: python3 scripts/validate_skills.py"
  fi
  linked=0
  for s in "${SKILL_DIRS[@]}"; do [ -e "$SKILLS_DST/$s/SKILL.md" ] && linked=$((linked + 1)); done
  step "$linked/${#SKILL_DIRS[@]} readable at $SKILLS_DST"
  "$REPO/bin/zp-doctor" >/dev/null 2>&1 && step "toolchain: core tools present" \
    || step "toolchain: a core tool is missing - run zp-doctor"
fi

say ""
say "Done."
say ""
say "  Skills load in NEW Claude Code sessions. To use them in the session you are in"
say "  right now, just say: read skills/zeroprotocol/SKILL.md and follow it."
say ""
say "  Then give a target:      hunt https://your-authorized-target.com"
say "  Check the toolchain:     zp-doctor"
say "  Set up authorization:    zp-scope init --target <host> && zp-scope confirm --by you --authorization <url>"
say ""
say "  ZeroProtocol only tests what a confirmed scope file allows. That is deliberate."
say ""
