#!/usr/bin/env bash
# Idempotent installer for the bounty pipeline.
# Usage: ./install.sh [target-dir]
# Default target: $BOUNTY_PIPELINE_DIR, or ~/bounty-pipeline
#
# From a fresh machine, clone this repo first, then run install.sh from it:
#   git clone https://github.com/hackbot1x-del/bug-bounty-bots.git ~/bounty-pipeline \
#     && bash ~/bounty-pipeline/install.sh
#
# Copies the pipeline scripts, clones or updates arkadiyt/bounty-targets-data,
# and checks that Python 3.10+ plus the standard library modules we use are
# present. No pip packages are required.
#
# Optional environment:
#   GITHUB_TOKEN / GH_TOKEN  — higher GitHub API budget for PoC trust tags
#   NVD_API_KEY / NIST_API_KEY — faster NVD CVE fetches (otherwise rate-limited)
#   BOUNTY_PIPELINE_DIR — default install / data directory
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-${BOUNTY_PIPELINE_DIR:-$HOME/bounty-pipeline}}"
# Expand a leading tilde even when quoted by the caller.
TARGET="${TARGET/#\~/$HOME}"

mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"

SCRIPTS=(
  paths.py
  watch.py
  cve-poc-feed.py
  cve-program-match.py
  privilege.py
  poc_trust.py
  vuln_types.py
  rank-findings.py
  daily-digest.py
  install.sh
)

echo "Installing bounty pipeline into $TARGET"

copied=0
skipped=0
for f in "${SCRIPTS[@]}"; do
  if [[ ! -f "$SRC/$f" ]]; then
    echo "Missing source file: $SRC/$f" >&2
    exit 1
  fi
  if [[ "$SRC/$f" -ef "$TARGET/$f" ]]; then
    skipped=$((skipped + 1))
    continue
  fi
  cp -f "$SRC/$f" "$TARGET/$f"
  copied=$((copied + 1))
done
chmod +x "$TARGET/install.sh" \
  "$TARGET/watch.py" \
  "$TARGET/cve-poc-feed.py" \
  "$TARGET/cve-program-match.py" \
  "$TARGET/daily-digest.py" \
  "$TARGET/rank-findings.py"
echo "  scripts: copied $copied, already in place $skipped"
mkdir -p "$TARGET/state"

# --- toolchain checks -------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but was not found on PATH." >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git is required but was not found on PATH." >&2
  exit 1
fi

python3 - "$TARGET" <<'PY'
import importlib
import sys

if sys.version_info < (3, 10):
    sys.stderr.write(
        f"Python 3.10+ is required; found {sys.version.split()[0]}\n"
    )
    sys.exit(1)

# Stdlib only — fail clearly if a module is somehow missing.
required = [
    "argparse",
    "collections",
    "dataclasses",
    "datetime",
    "functools",
    "json",
    "os",
    "pathlib",
    "re",
    "subprocess",
    "sys",
    "time",
    "typing",
    "urllib.error",
    "urllib.parse",
    "urllib.request",
    "zoneinfo",
]
missing = []
for name in required:
    try:
        importlib.import_module(name)
    except ImportError:
        missing.append(name)
if missing:
    sys.stderr.write("Missing Python standard-library modules: " + ", ".join(missing) + "\n")
    sys.exit(1)
print(f"  python: {sys.version.split()[0]} (stdlib only; no pip packages required)")
PY

# --- public program-scope clone --------------------------------------------
REPO="$TARGET/bounty-targets-data"
if [[ -d "$REPO/.git" ]]; then
  echo "  updating bounty-targets-data in $REPO"
  git -C "$REPO" pull --ff-only
else
  if [[ -e "$REPO" ]]; then
    echo "Refusing to clone: $REPO exists but is not a git repository." >&2
    exit 1
  fi
  echo "  cloning https://github.com/arkadiyt/bounty-targets-data into $REPO"
  # Full clone so watch.py can diff 24–72h of program/scope history.
  git clone --single-branch \
    https://github.com/arkadiyt/bounty-targets-data.git "$REPO"
fi

echo
echo "Install complete."
echo "Data directory: $TARGET"
echo
echo "Run the daily digest:"
echo "  python3 \"$TARGET/daily-digest.py\""
echo "Run the 1-10 ranking (generates digest data itself if the cache is empty):"
echo "  python3 \"$TARGET/rank-findings.py\""
echo
echo "Optional: export GITHUB_TOKEN for a higher GitHub API budget when tagging PoCs."
echo "Optional: export NVD_API_KEY to speed up CVE fetches."
echo "The nomi-sec/PoC-in-GitHub index is cloned automatically on the first digest or ranking run."
