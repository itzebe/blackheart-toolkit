#!/usr/bin/env bash
# Vendor the second external, independently-maintained target for the mission-04
# EVM harness: OpenZeppelin Ethernaut, and build both the vulnerable upstream
# contracts and the differential *control* contracts.
#
# Target (public, third-party, deliberately vulnerable -- a standard
# security-education CTF, NOT a production protocol):
#   https://github.com/OpenZeppelin/ethernaut  @ commit
#   d05643a40aa98c45d66247c69ffceab8f44dd8cb
#
# Everything vendored/built here is git-ignored and re-created by this script.
# Idempotent: re-running reuses the existing checkout. No paid service, no key,
# no network beyond the two public git remotes.
#
# Licence note: Ethernaut is AGPL-3.0. It is used here only as a locally-built,
# git-ignored test target (never redistributed, never deployed); our differential
# controls in controls/ are independent MIT-licensed re-implementations.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"
ETHERNAUT="$VENDOR/ethernaut"
CONTRACTS="$ETHERNAUT/contracts"

ETHERNAUT_REPO="https://github.com/OpenZeppelin/ethernaut.git"
ETHERNAUT_PIN="d05643a40aa98c45d66247c69ffceab8f44dd8cb"

export PATH="${PATH}:/home/openhands/.foundry/bin"

if [ ! -d "$ETHERNAUT/.git" ]; then
  mkdir -p "$VENDOR"
  echo "  fetching $ETHERNAUT_REPO -> $ETHERNAUT"
  git clone --quiet "$ETHERNAUT_REPO" "$ETHERNAUT"
else
  echo "  present: $ETHERNAUT"
fi

# Enforce the pin unconditionally, not only on first clone: a checkout left on a
# different revision (by a previous run, a manual edit, or a default-branch pull)
# must not silently change the bytecode the cases were validated against.
echo "  checking out pin $ETHERNAUT_PIN"
git -C "$ETHERNAUT" fetch --quiet origin "$ETHERNAUT_PIN" 2>/dev/null || true
git -C "$ETHERNAUT" checkout --quiet --force "$ETHERNAUT_PIN"
HEAD="$(git -C "$ETHERNAUT" rev-parse HEAD)"
if [ "$HEAD" != "$ETHERNAUT_PIN" ]; then
  echo "  ERROR: HEAD is $HEAD, expected pin $ETHERNAUT_PIN" >&2
  exit 1
fi
echo "  Ethernaut at $HEAD"

# Sync submodules to the *pinned commit's* recorded revisions (not the default
# branch's), so a later checkout of the default branch cannot silently drift the
# dependency versions the cases were validated against.
echo "  syncing Ethernaut submodules to the pinned commit"
git -C "$ETHERNAUT" submodule update --init --recursive --quiet

echo "  building vulnerable upstream contracts"
(cd "$CONTRACTS" && forge build --quiet)

echo "  building differential control contracts"
(cd "$HERE/controls" && forge build --quiet)

echo "ethernaut-external ready: $ETHERNAUT (pin $ETHERNAUT_PIN) + controls"
