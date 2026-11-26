#!/usr/bin/env bash
# Re-creates the vendored Resupply source tree (git-ignored).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"
REPO="https://github.com/resupplyfi/resupply.git"
PIN="${RESUPPLY_COMMIT:-bd47cb72a1}"
if [ ! -d "$VENDOR/.git" ]; then
  git clone "$REPO" "$VENDOR"
fi
cd "$VENDOR"
git fetch --all --tags
git checkout "$PIN"
git submodule update --init --recursive
npm install --no-audit --no-fund
