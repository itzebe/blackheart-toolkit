#!/usr/bin/env bash
# Verify that a *fresh* clone can bootstrap and use the engine toolchain without
# anything from the sandbox that wrote this mission.
#
# It clones the repository into a throwaway directory, installs the pinned
# toolchain into an isolated BLACKHEART_HOME, runs doctor, and runs one real
# engine against the adversarial harness. Every step is checked; a failure is
# reported with the step name and a non-zero exit.
#
# Usage:
#   scripts/verify_clean_install.sh                 # clone the current branch
#   scripts/verify_clean_install.sh --ref main      # clone a specific ref
#   scripts/verify_clean_install.sh --skip-engines  # bootstrap/doctor only
#   scripts/verify_clean_install.sh --keep          # keep the clone for inspection
#
# Nothing here needs a credential. It is safe to run on a machine that already
# has a toolchain: the clone installs into its own BLACKHEART_HOME.

set -uo pipefail

REF=""
SKIP_ENGINES=0
KEEP=0
REPO_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --skip-engines) SKIP_ENGINES=1; shift ;;
    --keep) KEEP=1; shift ;;
    --repo) REPO_URL="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

STEP=""
FAILED=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
step() { STEP="$1"; printf '\n== %s\n' "$1"; }
run() {  # run <description> <command...>
  local desc="$1"; shift
  if "$@" >/tmp/bh-verify-step.log 2>&1; then
    pass "$desc"
  else
    fail "$desc"
    sed 's/^/      /' /tmp/bh-verify-step.log | tail -20
  fi
}

# --------------------------------------------------------------------------- #
# Locate the repository we are verifying
# --------------------------------------------------------------------------- #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -z "$REPO_URL" ]; then
  REPO_URL="$(git -C "$SOURCE_REPO" remote get-url origin 2>/dev/null || true)"
fi
if [ -z "$REF" ]; then
  REF="$(git -C "$SOURCE_REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
fi

echo "BLACKHEART clean-install verification"
echo "  repository : ${REPO_URL:-<local>}"
echo "  ref        : $REF"
echo "  source     : $SOURCE_REPO"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/blackheart-clean-XXXXXX")"
export BLACKHEART_HOME="$WORKDIR/home/.blackheart"
CLONE="$WORKDIR/blackheart"
cleanup() {
  if [ "$KEEP" = 1 ]; then
    echo
    echo "kept: $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# 1. Fresh clone
# --------------------------------------------------------------------------- #
step "fresh clone"
if [ -n "$REPO_URL" ] && git clone --quiet --depth 1 --branch "$REF" "$REPO_URL" "$CLONE" 2>/tmp/bh-clone.log; then
  pass "cloned $REF"
else
  # Fall back to a local copy so the script is usable before the branch is pushed.
  mkdir -p "$CLONE"
  ( cd "$SOURCE_REPO" && tar -cf - --exclude=.git --exclude=node_modules . ) | ( cd "$CLONE" && tar -xf - )
  pass "copied the working tree (no remote clone available)"
fi
cd "$CLONE" || { fail "cannot enter the clone"; exit 1; }

# --------------------------------------------------------------------------- #
# 2. Bootstrap + doctor
# --------------------------------------------------------------------------- #
step "bootstrap and doctor"
run "python package imports" python3 -c "import blackheart; print(blackheart.__name__)"
run "toolchain manifest parses" python3 -c \
  "from blackheart.engines.toolchain import load_manifest; print(len(load_manifest()['engines']), 'engines')"

if [ "$SKIP_ENGINES" = 0 ]; then
  run "engines bootstrap" python3 -m blackheart engines bootstrap
  # doctor is allowed to fail only if a prerequisite (forge/solc) is genuinely
  # absent; it must still report every engine rather than guessing.
  if python3 -m blackheart engines doctor >/tmp/bh-doctor.log 2>&1; then
    pass "engines doctor (all pinned tools present)"
  else
    if grep -qi "forge\|solc" /tmp/bh-doctor.log; then
      printf '  \033[33mSKIP\033[0m engines doctor: a compiler prerequisite is absent on this host\n'
      sed 's/^/      /' /tmp/bh-doctor.log | tail -8
    else
      fail "engines doctor"
      sed 's/^/      /' /tmp/bh-doctor.log | tail -20
    fi
  fi
fi

# --------------------------------------------------------------------------- #
# 3. Deterministic tests (no binaries required)
# --------------------------------------------------------------------------- #
step "deterministic tests"
run "engine toolchain + dedup + adapters" \
  python3 -m pytest tests/test_engine_toolchain.py tests/test_engine_dedup.py \
                   tests/test_solidity_engines.py -q

# --------------------------------------------------------------------------- #
# 4. One real engine execution
# --------------------------------------------------------------------------- #
if [ "$SKIP_ENGINES" = 0 ]; then
  step "real engine execution"
  RUNDIR="$WORKDIR/run"
  mkdir -p "$RUNDIR"
  if python3 -m blackheart engines run --target harnesses/adversarial \
       --engines slither --allow-local --workdir "$RUNDIR" >/tmp/bh-run.log 2>&1; then
    if [ -f "$RUNDIR/engines-run.json" ]; then
      pass "slither ran and wrote engines-run.json"
      python3 - "$RUNDIR/engines-run.json" <<'PY'
import json, sys
run = json.load(open(sys.argv[1]))
confirmed = [c for c in run["clusters"] if c["disposition"] == "CONFIRMED"]
assert not confirmed, f"engines self-promoted {len(confirmed)} findings"
print(f"      {len(run['clusters'])} clusters, 0 confirmed -- the gate holds")
PY
    else
      fail "run produced no engines-run.json"
    fi
  else
    fail "engines run (see /tmp/bh-run.log)"
    tail -20 /tmp/bh-run.log | sed 's/^/      /'
  fi

  step "the run did not mutate the target"
  if [ -z "$(git status --porcelain -- harnesses/ 2>/dev/null)" ]; then
    pass "harnesses/ is unchanged"
  else
    fail "an engine wrote into the analysed project:"
    git status --porcelain -- harnesses/ | sed 's/^/      /'
  fi
fi

# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #
echo
if [ "$FAILED" = 0 ]; then
  printf '\033[32mCLEAN INSTALL VERIFIED\033[0m\n'
  exit 0
fi
printf '\033[31mCLEAN INSTALL FAILED\033[0m (step: %s)\n' "$STEP"
exit 1
