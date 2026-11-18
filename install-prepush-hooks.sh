#!/usr/bin/env bash
# install-prepush-hooks.sh — install the npm-ws infection gate as a LOCAL git
# pre-push hook into every git repo under a set of roots. v1.0 (2026-11-18)
#
# WHY THIS EXISTS: pushing .github/workflows/* needs a workflow-scope PAT we
# don't have, so CI-side gating is staged (npm-ws-gate.yml). Local pre-push
# hooks need no GitHub scopes — they block any PUSH carrying markers from this
# machine right now, including forged/accidental pushes from infected trees.
#
# What the hook does: on every `git push`, runs the gate (content union +
# payload filenames + tasks.json triggers + gitignore tamper + package.json
# hijack) over the commits being pushed (pickaxe vs the remote-tracking base
# when available, else working tree). Exit 1 = push BLOCKED.
#
# Usage: ./install-prepush-hooks.sh [--roots DIR1 DIR2 ...] [--dry-run]
# Default roots: ~/src ~/Documents ~/.zcode/workspace
#
# Skip flag for a single push (audited escapes): git push --no-verify

set -u -o pipefail

GATE_SRC="/Users/navidrashik/Documents/popular-travels-audit/npm-ws-ci-gate.sh"
DRY_RUN=0
ROOTS=("$HOME/src" "$HOME/Documents" "$HOME/.zcode/workspace")

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --roots) shift; ROOTS=(); while [ $# -gt 0 ] && [ "${1:-}" != "--dry-run" ]; do ROOTS+=("$1"); shift; done ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
done

[ -x "$GATE_SRC" ] || chmod +x "$GATE_SRC"
[ -f "$GATE_SRC" ] || { echo "gate script missing: $GATE_SRC" >&2; exit 2; }

# Stable home for the hook copy so every repo references ONE audited script.
HOOK_DIR="$HOME/.git-hooks/npm-ws"
mkdir -p "$HOOK_DIR"
cp "$GATE_SRC" "$HOOK_DIR/npm-ws-ci-gate.sh"
chmod +x "$HOOK_DIR/npm-ws-ci-gate.sh"
GATE="$HOOK_DIR/npm-ws-ci-gate.sh"

HOOK_BODY='#!/bin/sh
# npm-ws infection gate (pre-push) — installed by install-prepush-hooks.sh
# Escapes: git push --no-verify (audited exception only)
GATE="$HOME/.git-hooks/npm-ws/npm-ws-ci-gate.sh"
[ -x "$GATE" ] || exit 0   # gate missing → fail-open for availability; reinstall to re-arm
# Scan the push refspec range when derivable, else the working tree
BASE=""
while read -r local_ref local_sha remote_ref remote_sha; do
  [ "$local_sha" = "0000000000000000000000000000000000000000" ] && continue
  if [ "$remote_sha" != "0000000000000000000000000000000000000000" ] \
     && git cat-file -e "$remote_sha" 2>/dev/null; then
    BASE="$remote_sha"
  fi
done
if [ -n "$BASE" ]; then
  exec "$GATE" . --base "$BASE"
else
  exec "$GATE" .
fi'

# Snippet appended into EXISTING hooks (chains after e.g. the review-kit shim)
GATE_SNIPPET='# --- npm-ws infection gate (installed by install-prepush-hooks.sh) ---
"$HOME/.git-hooks/npm-ws/npm-ws-ci-gate.sh" . || exit 1
# --- end npm-ws infection gate ---'

INSTALLED=0; SKIPPED=0; CHAINED=0
for root in "${ROOTS[@]}"; do
  [ -d "$root" ] || continue
  while IFS= read -r -d '' gitdir; do
    # worktrees: .git is a file pointing at the real gitdir — get common hooks dir
    worktree_git_dir="$gitdir"
    if [ -f "$gitdir" ]; then
      real=$(sed -n 's/^gitdir: //p' "$gitdir")
      common=$(git --git-dir="$real" rev-parse --git-common-dir 2>/dev/null)
      [ -n "$common" ] && gitdir="$common"
    fi
    hooks="$gitdir/hooks"
    [ -d "$hooks" ] || mkdir -p "$hooks"
    target="$hooks/pre-push"
    if [ -f "$target" ] && grep -q "npm-ws infection gate" "$target" 2>/dev/null; then
      SKIPPED=$((SKIPPED+1)); continue   # already gated (idempotent)
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      if [ -f "$target" ]; then echo "WOULD CHAIN gate into: $target"; else echo "WOULD INSTALL: $target"; fi
    elif [ -f "$target" ]; then
      # CHAIN: existing hook (e.g. review-kit shim) keeps its semantics; the
      # npm-ws gate runs after it — its exit 1 refusal still blocks the push.
      printf '\n%s\n' "$GATE_SNIPPET" >> "$target"
      chmod +x "$target"
      CHAINED=$((CHAINED+1))
    else
      printf '%s\n' "$HOOK_BODY" > "$target"
      chmod +x "$target"
      INSTALLED=$((INSTALLED+1))
    fi
  done < <(find "$root" -name '.git' \( -type d -o -type f \) -print0 2>/dev/null \
           | while IFS= read -r -d '' p; do dirname "$p"; done | sort -u | while IFS= read -r d; do printf '%s\0' "$d/.git"; done)
done

echo
echo "done: $INSTALLED installed, $CHAINED chained into existing hooks, $SKIPPED already gated."
[ "$DRY_RUN" -eq 1 ] && echo "(dry-run — nothing written)"
echo "Gate copy: $GATE ; test: cd <repo> && $GATE ."
