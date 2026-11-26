#!/usr/bin/env bash
# Re-create the harness's only dependency. The tests fork live Polygon state, so no
# target source is vendored: the contracts under test are the deployed ones.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORGE_STD_PIN="${FORGE_STD_PIN:-v1.9.7}"
if [ ! -d "$HERE/lib/forge-std/.git" ]; then
  git clone --quiet https://github.com/foundry-rs/forge-std "$HERE/lib/forge-std"
fi
git -C "$HERE/lib/forge-std" fetch --quiet --tags origin
git -C "$HERE/lib/forge-std" checkout --quiet --force "$FORGE_STD_PIN"
echo "forge-std at $(git -C "$HERE/lib/forge-std" rev-parse --short HEAD)"
