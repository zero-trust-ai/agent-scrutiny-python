#!/usr/bin/env bash
#
# rename-to-zensical.sh
#
# Renames Markdown doc filenames to Zensical's lowercase-kebab convention
# (e.g. docs/THREAT-MODEL.md -> docs/threat-model.md).
#
# This is collision-aware on purpose. In this repo many lowercase files
# ALREADY exist next to their uppercase twins and have diverged, so a blind
# `git mv` would clobber the newer canonical content. This script only moves
# files whose target does not already exist, and REPORTS everything else for
# manual reconciliation.
#
# Usage:
#   ./rename-to-zensical.sh            # dry run — shows what would happen
#   ./rename-to-zensical.sh --apply    # actually perform the safe renames
#
set -euo pipefail

APPLY=false
[[ "${1:-}" == "--apply" ]] && APPLY=true

# Must be inside a git work tree; operate from the repo root.
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "error: not inside a git repository" >&2
  exit 1
}
cd "$(git rev-parse --show-toplevel)"

# GitHub-special files at the repo ROOT that stay uppercase by convention.
keep_root_regex='^(README|LICENSE|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY|CHANGELOG|NOTICE|AUTHORS)(\..*)?$'

# Authoritative, case-exact list of tracked files (reliable on case-insensitive
# filesystems, unlike a plain `-e` test).
mapfile -t ALL < <(git ls-files)
is_tracked() { printf '%s\n' "${ALL[@]}" | grep -Fxq "$1"; }

moved=()        # safe renames
diverged=()     # target exists with DIFFERENT content — manual merge needed
identical=()    # target exists with identical content — redundant duplicate
root_dupe=()    # root-level legacy copy of a docs/ page
kept=()         # intentionally left as-is

while IFS= read -r f; do
  dir=$(dirname "$f")
  base=$(basename "$f")
  lower=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')

  # Already lowercase? Nothing to do.
  [[ "$base" == "$lower" ]] && continue

  # Leave GitHub-special files at the repo root alone.
  if [[ "$dir" == "." && "$base" =~ $keep_root_regex ]]; then
    kept+=("$f  (GitHub convention)")
    continue
  fi

  if [[ "$dir" == "." ]]; then
    target="$lower"
  else
    target="$dir/$lower"
  fi

  # A root-level doc that duplicates an existing docs/ page is a consolidation
  # decision, not an in-place rename. Flag it; don't move it to root/lowercase.
  if [[ "$dir" == "." ]] && is_tracked "docs/$lower"; then
    root_dupe+=("$f  ->  docs/$lower already exists")
    continue
  fi

  # Target already tracked as a genuinely different file? Don't clobber.
  if is_tracked "$target" && [[ "$target" != "$f" ]]; then
    if [[ -f "$f" && -f "$target" ]] && cmp -s "$f" "$target"; then
      identical+=("$f  ==  $target")
    else
      diverged+=("$f  !=  $target")
    fi
    continue
  fi

  # Safe to rename. Use a two-step move so a case-only change works even on
  # case-insensitive filesystems (macOS/Windows).
  moved+=("$f  ->  $target")
  if $APPLY; then
    tmp="$f.zensical-rename.tmp"
    git mv "$f" "$tmp"
    git mv "$tmp" "$target"
  fi
done < <(git ls-files | grep -iE '\.md$' | sort)

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
hr() { printf '%s\n' "------------------------------------------------------------"; }

echo
$APPLY && echo "MODE: APPLY (changes staged via git mv)" \
        || echo "MODE: DRY RUN (no changes — re-run with --apply to execute)"
hr

printf 'Renamed (%d):\n' "${#moved[@]}"
((${#moved[@]})) && printf '  %s\n' "${moved[@]}" || echo "  (none)"
echo

printf 'Diverged duplicates — MANUAL MERGE then delete the uppercase copy (%d):\n' "${#diverged[@]}"
((${#diverged[@]})) && printf '  %s\n' "${diverged[@]}" || echo "  (none)"
echo

printf 'Identical duplicates — safe to remove the uppercase copy (%d):\n' "${#identical[@]}"
((${#identical[@]})) && printf '  git rm %s\n' "${identical[@]%% ==*}" || echo "  (none)"
echo

printf 'Root-level legacy copies of docs/ pages — reconcile then delete (%d):\n' "${#root_dupe[@]}"
((${#root_dupe[@]})) && printf '  %s\n' "${root_dupe[@]}" || echo "  (none)"
echo

printf 'Left as-is (%d):\n' "${#kept[@]}"
((${#kept[@]})) && printf '  %s\n' "${kept[@]}" || echo "  (none)"
hr

if $APPLY && ((${#moved[@]})); then
  echo "Next: review with 'git status', then commit:"
  echo "  git commit -m 'docs: rename files to Zensical lowercase convention'"
fi
