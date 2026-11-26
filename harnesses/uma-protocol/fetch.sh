#!/usr/bin/env bash
# Re-create the vendored, git-ignored UMA source this harness tests against, and
# the harness's Foundry dependencies, so the adversarial tests run against the
# real pinned upstream code rather than a model.
#
# Targets (public, in-scope for the UMA bug bounty):
#   https://github.com/UMAprotocol/protocol        OOv3, DVM/VotingV2, Store
#   https://github.com/UMAprotocol/managed-oracle  managed OOv2 (missions 01/03)
#
# Licence: the UMA protocol source is AGPL-3.0-only. It is used here only as a
# locally built, git-ignored test target -- never redistributed, never deployed.
# The harness's own tests (test/) and build config (foundry.toml) are committed.
#
# Idempotent: re-running reuses existing checkouts and re-enforces the pins.
# No paid service, no API key.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"
MANAGED="$HERE/vendor-managed-oracle"

UMA_REPO="https://github.com/UMAprotocol/protocol.git"
UMA_PIN="${UMA_PROTOCOL_PIN:-00e962161d9c123de16e3c86c0500a530eaa319b}"
MANAGED_REPO="https://github.com/UMAprotocol/managed-oracle.git"
MANAGED_PIN="${UMA_MANAGED_PIN:-24a5930ba82bb9a91fb3251d8d7ff243b5d95a7a}"
FORGE_STD_PIN="${FORGE_STD_PIN:-15b2df92a05d4d2f76a06653872fefb287e0e01c}"
OZ_PIN="${OZ_PIN:-dc44c9f1a4c3b10af99492eed84f83ed244203f6}"

export PATH="${PATH}:${HOME}/.foundry/bin"

fetch_pin() {  # <repo-url> <dest-dir> <pin>
  local url="$1" dest="$2" pin="$3"
  if [ ! -d "$dest/.git" ]; then
    echo "  cloning $url"
    git clone --quiet "$url" "$dest"
  fi
  # Enforce the pin on every run: a checkout left on another revision must not
  # silently change the bytecode the tests were validated against.
  git -C "$dest" fetch --quiet origin "$pin" 2>/dev/null || git -C "$dest" fetch --quiet --tags origin
  git -C "$dest" checkout --quiet --force "$pin"
  local head
  head="$(git -C "$dest" rev-parse HEAD)"
  if [ "$head" != "$pin" ]; then
    echo "ERROR: $dest at $head, expected $pin" >&2
    exit 1
  fi
  echo "  $dest @ $head"
}

echo "fetch: UMA protocol @ $UMA_PIN"
fetch_pin "$UMA_REPO" "$VENDOR" "$UMA_PIN"

# The OOv3 tests import the in-scope source via ../../src/; copy the three
# needed subtrees out of the pinned checkout (src/ is git-ignored).
echo "fetch: materialising in-scope source into src/"
CORE="$VENDOR/packages/core/contracts"
rm -rf "$HERE/src"
mkdir -p "$HERE/src"
cp -r "$CORE/common" "$CORE/data-verification-mechanism" "$CORE/optimistic-oracle-v3" "$HERE/src/"

echo "fetch: Foundry dependencies @ pins"
mkdir -p "$HERE/lib"
fetch_pin "https://github.com/foundry-rs/forge-std.git" "$HERE/lib/forge-std" "$FORGE_STD_PIN"
fetch_pin "https://github.com/OpenZeppelin/openzeppelin-contracts.git" \
  "$HERE/lib/openzeppelin-contracts" "$OZ_PIN"

echo "fetch: managed-oracle @ $MANAGED_PIN"
fetch_pin "$MANAGED_REPO" "$MANAGED" "$MANAGED_PIN"

echo "fetch: building the harness"
(cd "$HERE" && forge build --quiet)
echo "fetch: done -> run 'forge test' in $HERE"
