#!/usr/bin/env bash
# npm-ws-ci-gate.sh — CI/CD infection gate for the npm-ws / PolinRider campaign
# v1.0 (2026-11-18) — companion to npm-ws-remediate.sh v2.2 / npm-ws-agent-instructions.md v2.2
#
# Runs the FULL extended marker union + payload-file + persistence-trigger +
# gitignore-tamper + package.json-hijack checks against a repo working tree
# (CI checkout) and, with --base, against every changed commit vs a base ref
# (pickaxe) so pushes carrying payloads are blocked at the gate.
#
# Usage:
#   npm-ws-ci-gate.sh [REPO_DIR] [--base BASE_REF] [--verbose] [--quiet]
#
# Exit codes (gate semantics — never report as clean what was not scanned):
#   0 = scanned, CLEAN            1 = FINDINGS (block the build/push)
#   2 = setup/usage gap
#
# Designed for: GitHub Actions (see npm-ws-gate.yml), local pre-push hooks
# (see install-prepush-hooks.sh), and ad-hoc terminal use. Read-only: it never
# modifies the repo, never runs npm/npx, never needs network.

set -u -o pipefail

REPO_DIR="."
BASE_REF=""
VERBOSE=0
QUIET=0

say()  { [ "$QUIET" -eq 0 ] && echo "$@" >&2 || true; }
diag() { [ "$VERBOSE" -eq 1 ] && echo "[diag] $*" >&2 || true; }

while [ $# -gt 0 ]; do
  case "$1" in
    --base)   BASE_REF="${2:?--base needs a ref}"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    --quiet)   QUIET=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) if [ -d "$1" ]; then REPO_DIR="$1"; else echo "unknown arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

[ -d "$REPO_DIR/.git" ] || [ -f "$REPO_DIR/.git" ] || { echo "not a git repo: $REPO_DIR" >&2; exit 2; }
command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
command -v grep >/dev/null || { echo "grep not found" >&2; exit 2; }

# ── Signatures (mirror npm-ws-remediate.sh v2.2 — keep the two in sync) ──────
# Full marker union: npm hook, variant-1/2/3 caches, family-B C2-resolver
# loader, family-C live loader (R-dash), font loader, bare dead-drop value.
CONTENT_RE='npm-ws|M260630A|parseInt\(0x|VcIjEMuK|oUjdMfbQcGFkunf|var module = \{ exports|global\[.!.]=.9-4349.|var _\$_1e42=|var n=2667686|Tgw\(2509\)|uG\$O_YLJZRJdet|daIQfX|EWKyMvkJkykfdVCH|bx = .-11381-2.|-11381-2'
# Payload FILENAMES (hidden droppers; parse with FULL ls-tree entries only)
PAYNAME_RE='(^|/)init$|\.orc$|\.vscode/tasks\.json$|^config\.bat$'
# Camouflaged persistence trigger inside .vscode/tasks.json (font-exec)
TASKTRIG_RE='node[^"]*\.(ttf|woff2?|otf)|fonts/[^"]*\.(ttf|woff2?|otf)'
# .gitignore tamper that un-hides .env / .vscode (secret-steal prep)
GITIGNORE_RE='^[[:space:]]*!\.env[[:space:]]*$|^[[:space:]]*!\.vscode([[:space:]/]|$)'
# package.json script hijack
PKGHIJACK_RE='"(dev|build|start|predev|prebuild|postinstall)"[[:space:]]*:[[:space:]]*"[^"]*node init'

cd "$REPO_DIR" || exit 2
REPO_DIR="$(pwd)"
REPO_NAME="$(basename "$REPO_DIR")"

FINDINGS=0
FAIL() { FINDINGS=$((FINDINGS+1)); say "❌ [$REPO_NAME] $*"; }
OK()   { diag "✓ $*"; }

# ── 1. Working-tree content scan (raw bytes — never -I: payloads hide behind
#       binary NAMES like fa-solid-600.ttf while being text) ──────────────────
# NOTE: git grep does NOT support --binary-files=text — the portable flag is
# -a/--text (plain grep(1) DOES support --binary-files=text). Field lesson
# from the 2026-11-18 audit: exit-129 on the wrong flag silently yields zero
# hits, which reads as clean. Any zero-hit verdict must assert the scan ran.
git grep -anE "$CONTENT_RE" -- . 2>/dev/null > /tmp/.npm-ws-gate-$$-content
GATE_GREP_RC=$?
if [ $GATE_GREP_RC -gt 1 ]; then
  echo "setup gap: git grep failed (rc=$GATE_GREP_RC) — no content verdict possible" >&2
  rm -f /tmp/.npm-ws-gate-$$-content; exit 2
fi
if [ -s /tmp/.npm-ws-gate-$$-content ]; then
  N=$(wc -l < /tmp/.npm-ws-gate-$$-content | tr -d ' ')
  FAIL "content markers: $N hit(s) in working tree (see report)"
  [ "$VERBOSE" -eq 1 ] && sed 's/^/    /' /tmp/.npm-ws-gate-$$-content >&2
  cp /tmp/.npm-ws-gate-$$-content "${TMPDIR:-/tmp}/npm-ws-gate-$REPO_NAME-content.txt"
fi
rm -f /tmp/.npm-ws-gate-$$-content

# ── 2. Payload-named files: init/.orc/config.bat (tasks.json is NOT listed
#       here — its existence is not evidence; step 3 reads its contents).
#       `init` name alone is NOT proof (legit vendored packaging, e.g. Odoo
#       debian/init, was a documented false positive) → flag a payload-named
#       file only when its CONTENT matches markers or it is dropper-sized
#       (>8 KB; the campaign droppers were ~32 KB, Odoo's init ~3.4 KB). ──────
while IFS= read -r pf; do
  [ -f "$pf" ] || continue
  if grep -qaE "$CONTENT_RE" "$pf" 2>/dev/null; then
    FAIL "payload file with marker content: $pf"
  elif [ "$(wc -c < "$pf")" -gt 8192 ]; then
    FAIL "dropper-sized payload-named file: $pf ($(wc -c < "$pf") B)"
  else
    diag "benign small payload-named file, no markers: $pf"
  fi
done < <(find . -type f \( -name init -o -name '*.orc' -o -name 'config.bat' \) \
  -not -path './.git/*' 2>/dev/null)

# ── 3. Every tracked .vscode/tasks.json → persistence-trigger inspection ────
while IFS= read -r tf; do
  [ -f "$tf" ] || continue
  if grep -qE "$TASKTRIG_RE" "$tf" 2>/dev/null; then
    FAIL "persistence trigger in $tf (font/exec runOptions)"
  elif grep -qE '"isBackground"[[:space:]]*:[[:space:]]*true' "$tf" 2>/dev/null \
       && grep -qE '"reveal"[[:space:]]*:[[:space:]]*"never"' "$tf" 2>/dev/null; then
    FAIL "suspicious hidden background task in $tf (isBackground+reveal never)"
  fi
done < <(git ls-files -z | tr '\0' '\n' | grep -E '(^|/)\.vscode/tasks\.json$' || true)

# ── 4. .gitignore tamper (un-ignore .env / .vscode) ──────────────────────────
if [ -f .gitignore ] && grep -qE "$GITIGNORE_RE" .gitignore; then
  FAIL ".gitignore un-ignores .env/.vscode (secret-steal prep): $(grep -nE "$GITIGNORE_RE" .gitignore | head -3 | tr '\n' ';')"
fi

# ── 5. package.json script hijack ("node init && …") ─────────────────────────
for pj in $(git ls-files 2>/dev/null | grep -E '(^|/)package\.json$' || true); do
  [ -f "$pj" ] || continue
  if grep -qE "$PKGHIJACK_RE" "$pj" 2>/dev/null; then
    FAIL "package.json script hijack in $pj"
  fi
done

# ── 6. Optional: pickaxe every commit in the diff vs --base (CI push gate) ───
if [ -n "$BASE_REF" ]; then
  if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
    echo "setup gap: --base ref not found: $BASE_REF" >&2; exit 2
  fi
  for M in 'npm-ws' 'M260630A' 'parseInt(0x' 'VcIjEMuK' 'oUjdMfbQcGFkunf' \
           "global\['!'\]='9-4349'" '_\$_1e42=' 'Tgw(2509' 'uG\$O_YLJZRJdet' \
           'daIQfX' 'EWKyMvkJkykfdVCH' "-11381-2"; do
    HITS=$(git log "$BASE_REF"..HEAD --oneline -S"$M" --pickaxe-regex 2>/dev/null | head -20)
    if [ -n "$HITS" ]; then
      FAIL "pickaxe: marker '$M' introduced by commits vs $BASE_REF: $(echo "$HITS" | tr '\n' ';')"
    fi
  done
  # payload files added anywhere in the diff
  ADDED=$(git diff --name-only --diff-filter=A "$BASE_REF"..HEAD 2>/dev/null \
          | grep -E "$PAYNAME_RE" || true)
  [ -n "$ADDED" ] && FAIL "payload-named files ADDED vs $BASE_REF: $ADDED"
fi

if [ "$FINDINGS" -eq 0 ]; then
  say "✅ [$REPO_NAME] npm-ws gate CLEAN"
  exit 0
fi
say "🚨 [$REPO_NAME] npm-ws gate: $FINDINGS finding class(es) — DO NOT MERGE/BUILD/PUSH"
exit 1
