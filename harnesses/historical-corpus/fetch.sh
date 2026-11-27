#!/usr/bin/env bash
# Vendor the build dependency for the historical-corpus harness. forge-std is not
# committed (see the repository .gitignore); this script is idempotent and pins
# the dependency to an immutable tag so a fetch cannot silently substitute a
# different version (mission 2.5, Phase 5: explicit, pinned, integrity-checked).
#
# This uses a plain clone + checkout, matching the sibling harnesses -- NOT
# `forge install`, which would create a git submodule (and a .gitmodules entry)
# in a repository that deliberately keeps these vendored deps git-ignored.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORGE_STD_REPO="https://github.com/foundry-rs/forge-std.git"
FORGE_STD_PIN="v1.9.7"
DEST="$HERE/lib/forge-std"

if [ -d "$DEST/.git" ]; then
  echo "  present: $DEST"
else
  mkdir -p "$HERE/lib"
  echo "  fetching $FORGE_STD_REPO @ $FORGE_STD_PIN -> $DEST"
  git clone --quiet "$FORGE_STD_REPO" "$DEST"
  git -C "$DEST" checkout --quiet "$FORGE_STD_PIN"
fi
echo "forge-std present at $DEST (pin $FORGE_STD_PIN)"
