#!/usr/bin/env bash
# Fetch the full upstream Damn Vulnerable DeFi challenge set into a gitignored
# path for extended exploit training. The bundled, self-contained fixture in
# harnesses/dvdf/ is used by the engine and its tests; this script is optional.
#
# Local-only: the challenges run in Foundry's in-process EVM. No network, no funds.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-$ROOT/research/private/dvdf-full}"
VERSION="${DVDF_VERSION:-v4.1.0}"
REPO="https://github.com/tinchoabbate/damn-vulnerable-defi"

if [ -d "$DEST/.git" ]; then
  echo "already cloned at $DEST"
else
  mkdir -p "$(dirname "$DEST")"
  git clone --depth 1 --branch "$VERSION" "$REPO" "$DEST"
fi

cd "$DEST"
echo "DVDF $(git describe --tags 2>/dev/null || git rev-parse --short HEAD) at $DEST"
echo "run a challenge, e.g.:  cd $DEST && forge test --match-path 'test/unstoppable/*' -vv"
