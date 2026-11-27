#!/usr/bin/env bash
# Vendor the external, independently-maintained target for the mission-03 EVM
# harness: Damn Vulnerable DeFi v4.1.0, and build both the vulnerable upstream
# bytecode and the differential *control* contracts.
#
# Target (public, third-party, deliberately vulnerable -- a standard educational
# suite, NOT a production protocol):
#   https://github.com/tinchoabbate/damn-vulnerable-defi  @ tag v4.1.0
#     -> commit 64fddf9f96de2782f8868898d68673acb295119c
#
# Everything vendored/built here is git-ignored and re-created by this script.
# Idempotent: re-running reuses the existing checkout. No paid service, no key,
# no network beyond the two public git remotes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"
DVDF="$VENDOR/dvdf"

DVDF_REPO="https://github.com/tinchoabbate/damn-vulnerable-defi.git"
DVDF_PIN="v4.1.0"
DVDF_COMMIT="64fddf9f96de2782f8868898d68673acb295119c"

export PATH="${PATH}:/home/openhands/.foundry/bin"

if [ ! -d "$DVDF/.git" ]; then
  mkdir -p "$VENDOR"
  echo "  fetching $DVDF_REPO @ $DVDF_PIN -> $DVDF"
  git clone --quiet --recurse-submodules --branch "$DVDF_PIN" "$DVDF_REPO" "$DVDF"
else
  echo "  present: $DVDF"
fi

# Enforce the pin unconditionally, not only on first clone: a checkout left on a
# different revision (by a previous run, a manual edit, or a default-branch pull)
# must not silently change the bytecode the cases were validated against.
echo "  checking out pin $DVDF_PIN"
git -C "$DVDF" fetch --quiet origin "$DVDF_PIN" 2>/dev/null || true
git -C "$DVDF" checkout --quiet --force "$DVDF_PIN"
DVDF_HEAD="$(git -C "$DVDF" rev-parse HEAD)"
if [ "$DVDF_HEAD" != "$DVDF_COMMIT" ]; then
  echo "  ERROR: HEAD is $DVDF_HEAD, expected pin $DVDF_PIN ($DVDF_COMMIT)" >&2
  exit 1
fi
echo "  DVDF at $DVDF_HEAD ($DVDF_PIN)"

# lib/ submodules carry the challenge dependencies (openzeppelin, solmate, ...).
# Sync them to the *pinned commit's* recorded revisions so a later checkout of the
# default branch cannot silently drift the dependency versions.
echo "  syncing DVDF submodules to the pinned commit"
git -C "$DVDF" submodule update --init --recursive --quiet

echo "  building vulnerable upstream bytecode"
(cd "$DVDF" && forge build --quiet)

# The controls reuse the vendored tree's dependency remappings, but their lib/ is
# one level up; rewrite the `lib/` prefix to point into the vendor tree. Generated
# (not committed) so it can never drift from the vendored dependencies.
sed 's#=lib/#=../vendor/dvdf/lib/#g' "$DVDF/remappings.txt" > "$HERE/controls/remappings.txt"

echo "  building differential control contracts"
(cd "$HERE/controls" && forge build --quiet)

echo "dvdf-external ready: $DVDF (pin $DVDF_PIN) + controls"
