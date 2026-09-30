#!/usr/bin/env bash
#
# ZeroProtocol installer for hosts other than Claude Code.
#
# The 68 skills need no conversion: `skills/<name>/SKILL.md` with `name` and `description`
# frontmatter is exactly the format Claude Code, Codex, OpenCode and Agent Plugins 1.0 all
# read. This script points each host's skill directory at them, wires the zp-* helper programs
# onto PATH, and installs the portable AGENTS.md instruction file.
#
#   ./install-portable.sh --host codex        ~/.agents/skills + ~/.codex/AGENTS.md
#   ./install-portable.sh --host opencode     ~/.config/opencode/{skills,agents,commands}
#   ./install-portable.sh --host hermes       ~/.hermes/skills
#   ./install-portable.sh --host agents       ~/.agents/skills only (Codex + OpenCode both read it)
#   ./install-portable.sh --host all          every host above
#
#   --copy         copy instead of symlink (survives deleting this clone)
#   --dry-run, -n  print every action, change nothing
#   --remove       remove what this script installed
#   --prefix DIR   install under DIR instead of $HOME (for sandboxed testing)
#   --bin-dir DIR  where to link the zp-* programs (default ~/.local/bin)
#
# For Claude Code use ./install.sh instead - it also seeds memory notes and the CLAUDE.md block.
# Idempotent: re-running relinks without duplicating anything.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$HOME"
BIN_DIR="${ZP_BIN_DIR:-$HOME/.local/bin}"
MODE=link
DRY=0
HOSTS=()
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

BEGIN_MARK="<!-- ZEROPROTOCOL:BEGIN - managed by install-portable.sh, do not edit inside -->"
END_MARK="<!-- ZEROPROTOCOL:END -->"

while [ $# -gt 0 ]; do
  case "$1" in
    --host)     HOSTS+=("${2:?--host needs codex|opencode|hermes|agents|all}"); shift ;;
    --copy)     MODE=copy ;;
    --remove|--uninstall) MODE=remove ;;
    --dry-run|-n) DRY=1 ;;
    --prefix)   PREFIX="${2:?--prefix needs a directory}"; shift ;;
    --bin-dir)  BIN_DIR="${2:?--bin-dir needs a directory}"; shift ;;
    -h|--help)  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install-portable.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ "${#HOSTS[@]}" -eq 0 ]; then
  echo "install-portable.sh: --host is required (codex|opencode|hermes|agents|all)" >&2
  echo "                     for Claude Code use ./install.sh" >&2
  exit 2
fi
for h in "${HOSTS[@]}"; do
  case "$h" in
    codex|opencode|hermes|agents|all) ;;
    claude) echo "install-portable.sh: use ./install.sh for Claude Code" >&2; exit 2 ;;
    *) echo "install-portable.sh: unknown host '$h'" >&2; exit 2 ;;
  esac
done
case " ${HOSTS[*]} " in *" all "*) HOSTS=(agents codex opencode hermes) ;; esac

say()  { printf '%s\n' "$*"; }
step() { printf '  %s\n' "$*"; }
run()  { if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else eval "$@"; fi; }

SKILL_DIRS=()
for d in "$REPO"/skills/*/; do
  [ -f "$d/SKILL.md" ] && SKILL_DIRS+=("$(basename "$d")")
done
[ "${#SKILL_DIRS[@]}" -gt 0 ] || { echo "install-portable.sh: no skills found in $REPO/skills" >&2; exit 1; }

# Link (or copy) every skill directory into one destination.
link_skills() {
  local dst="$1" label="$2" n=0
  say "$label -> $dst"
  run "mkdir -p '$dst'"
  for s in "${SKILL_DIRS[@]}"; do
    local src="$REPO/skills/$s" target="$dst/$s"
    if [ -e "$target" ] || [ -L "$target" ]; then
      # Only ever replace something we put there ourselves.
      if [ -L "$target" ] && [ "$(readlink "$target" 2>/dev/null || true)" = "$src" ]; then
        n=$((n + 1)); continue
      fi
      if [ -L "$target" ]; then
        run "rm -f '$target'"
      else
        local bak="$dst/.zeroprotocol-backup-$STAMP"
        run "mkdir -p '$bak'"
        run "mv '$target' '$bak/$s'"
        step "backed up pre-existing $s -> $bak/$s"
      fi
    fi
    if [ "$MODE" = copy ]; then run "cp -a '$src' '$target'"; else run "ln -s '$src' '$target'"; fi
    n=$((n + 1))
  done
  step "$n skills"
}

link_dir_of_md() {
  local src="$1" dst="$2" label="$3" n=0
  [ -d "$src" ] || { step "$label: nothing to install ($src missing)"; return 0; }
  say "$label -> $dst"
  run "mkdir -p '$dst'"
  for f in "$src"/*.md; do
    [ -f "$f" ] || continue
    local b target; b="$(basename "$f")"; target="$dst/$b"
    if [ -L "$target" ]; then run "rm -f '$target'"; fi
    if [ "$MODE" = copy ]; then run "cp -a '$f' '$target'"; else run "ln -sf '$f' '$target'"; fi
    n=$((n + 1))
  done
  step "$n files"
}

# Write the AGENTS.md instruction block between markers, leaving anything else in the file.
install_agents_md() {
  local file="$1"
  run "mkdir -p '$(dirname "$file")'"
  if [ "$DRY" = 1 ]; then printf '  [dry-run] write ZeroProtocol block into %s\n' "$file"; return 0; fi
  local body tmp
  body="$(cat "$REPO/AGENTS.md")"
  tmp="$(mktemp)"
  if [ -f "$file" ] && grep -qF "$BEGIN_MARK" "$file"; then
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
      index($0,b){skip=1} !skip{print} index($0,e){skip=0}' "$file" > "$tmp"
  elif [ -f "$file" ]; then
    cat "$file" > "$tmp"
  fi
  { [ -s "$tmp" ] && printf '\n'; printf '%s\n%s\n%s\n' "$BEGIN_MARK" "$body" "$END_MARK"; } >> "$tmp"
  mv "$tmp" "$file"
  step "instruction block written to $file"
}

remove_skills() {
  local dst="$1" n=0
  [ -d "$dst" ] || return 0
  for s in "${SKILL_DIRS[@]}"; do
    local t="$dst/$s"
    if [ -L "$t" ] && [ "$(readlink "$t" 2>/dev/null || true)" = "$REPO/skills/$s" ]; then
      run "rm -f '$t'"; n=$((n + 1))
    elif [ -d "$t" ] && [ -f "$t/SKILL.md" ] && grep -q "ZeroProtocol" "$t/SKILL.md" 2>/dev/null; then
      run "rm -rf '$t'"; n=$((n + 1))
    fi
  done
  [ "$n" -gt 0 ] && step "removed $n skills from $dst"
  return 0
}

strip_agents_md() {
  local file="$1"
  [ -f "$file" ] || return 0
  grep -qF "$BEGIN_MARK" "$file" || return 0
  if [ "$DRY" = 1 ]; then printf '  [dry-run] strip ZeroProtocol block from %s\n' "$file"; return 0; fi
  local tmp; tmp="$(mktemp)"
  awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
    index($0,b){skip=1} !skip{print} index($0,e){skip=0}' "$file" > "$tmp"
  mv "$tmp" "$file"
  step "stripped block from $file"
}

wire_bin() {
  say "helper programs -> $BIN_DIR"
  run "mkdir -p '$BIN_DIR'"
  run "chmod +x '$REPO'/bin/zp-*"
  local n=0
  for b in "$REPO"/bin/zp-*; do
    [ -f "$b" ] || continue
    run "ln -sf '$b' '$BIN_DIR/$(basename "$b")'"
    n=$((n + 1))
  done
  step "$n programs"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) step "NOTE: $BIN_DIR is not on PATH - add it, or zp-scope will not resolve" ;;
  esac
}

unwire_bin() {
  for b in "$REPO"/bin/zp-*; do
    [ -f "$b" ] || continue
    local t="$BIN_DIR/$(basename "$b")"
    [ -L "$t" ] && run "rm -f '$t'"
  done
  return 0
}

AGENTS_SKILLS="$PREFIX/.agents/skills"
CODEX_MD="$PREFIX/.codex/AGENTS.md"
OC_ROOT="${XDG_CONFIG_HOME:-$PREFIX/.config}/opencode"
HERMES_SKILLS="$PREFIX/.hermes/skills"

say ""
say "ZeroProtocol -> ${HOSTS[*]}   (${#SKILL_DIRS[@]} skills, mode: $MODE)"
say ""

if [ "$MODE" = remove ]; then
  for h in "${HOSTS[@]}"; do
    case "$h" in
      agents|codex) remove_skills "$AGENTS_SKILLS"; [ "$h" = codex ] && strip_agents_md "$CODEX_MD" ;;
      opencode)
        remove_skills "$OC_ROOT/skills"
        for f in "$OC_ROOT"/agents/zp-*.md "$OC_ROOT"/commands/zp-*.md; do
          [ -L "$f" ] && run "rm -f '$f'"
        done
        strip_agents_md "$OC_ROOT/AGENTS.md" ;;
      hermes) remove_skills "$HERMES_SKILLS" ;;
    esac
  done
  unwire_bin
  say ""
  say "Removed. The clone at $REPO is untouched."
  exit 0
fi

for h in "${HOSTS[@]}"; do
  case "$h" in
    agents)
      link_skills "$AGENTS_SKILLS" "skills (portable ~/.agents path, read by Codex and OpenCode)" ;;
    codex)
      link_skills "$AGENTS_SKILLS" "skills (Codex reads \$HOME/.agents/skills)"
      install_agents_md "$CODEX_MD"
      step "invoke a skill in Codex with \$zeroprotocol" ;;
    opencode)
      link_skills "$OC_ROOT/skills" "skills (OpenCode)"
      link_dir_of_md "$REPO/adapters/opencode/agents" "$OC_ROOT/agents" "agents (OpenCode)"
      link_dir_of_md "$REPO/adapters/opencode/commands" "$OC_ROOT/commands" "commands (OpenCode)"
      install_agents_md "$OC_ROOT/AGENTS.md" ;;
    hermes)
      link_skills "$HERMES_SKILLS" "skills (Hermes)"
      step "or install the whole repo as an Agent Plugins 1.0 package:"
      step "  hermes plugins install MaramHarsha/ZeroProtocol" ;;
  esac
  say ""
done

wire_bin

say ""
say "Next:"
step "zp-doctor                      what works on this box, and how it degrades"
step "zp-scope init <target>         write a scope file - a HUMAN confirms it"
step "then ask your agent to load the 'zeroprotocol' skill and give it a target"
say ""
say "Nothing touches a target until 'zp-scope check' exits 0."
