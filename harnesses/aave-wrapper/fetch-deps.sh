#!/usr/bin/env bash
# Fetch everything needed to compile the real Aave aToken wrapper harness.
#
# Nothing fetched here is committed to the repository. The wrapper source is
# BUSL-1.1 (source-available, not open source) and is treated as
# target-confidential; the dependencies are large third-party trees. All of it
# is git-ignored. Every revision is pinned so the harness is reproducible.
#
# Requires: git and forge (Foundry). Network access to github.com.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# --- pinned revisions -------------------------------------------------------
WRAPPER_REPO="https://github.com/0xTwyne/aave-v3-aToken-wrapper.git"
WRAPPER_REV="797be33"          # tag 1.0.1
FORGE_STD_REV="v1.9.0"
AAVE_ORIGIN_REV="d7919c0204cb26856fbd087b2e1c6d62a8916e3a"
EVC_REV="a7d3c29ef7e4964736e47675e0588630d6afbfd7"

fetch() { # url dir rev
  local url="$1" dir="$2" rev="$3"
  if [ -d "$dir/.git" ]; then echo "  present: $dir"; return; fi
  echo "  fetching $url @ $rev -> $dir"
  git clone --quiet "$url" "$dir"
  git -C "$dir" checkout --quiet "$rev"
}

echo "[aave-wrapper] fetching the real wrapper source (BUSL-1.1, not committed)"
fetch "$WRAPPER_REPO" lib/aave-wrapper-src "$WRAPPER_REV"

echo "[aave-wrapper] fetching pinned dependencies"
fetch https://github.com/foundry-rs/forge-std  lib/forge-std  "$FORGE_STD_REV"
fetch https://github.com/aave-dao/aave-v3-origin lib/aave-v3-origin "$AAVE_ORIGIN_REV"
fetch https://github.com/euler-xyz/ethereum-vault-connector \
      lib/ethereum-vault-connector "$EVC_REV"

echo "[aave-wrapper] initialising nested submodules (OpenZeppelin, solidity-utils)"
git -C lib/aave-v3-origin submodule update --init --recursive --quiet
git -C lib/ethereum-vault-connector submodule update --init --recursive --quiet

echo "[aave-wrapper] placing the wrapper source under src/ (git-ignored)"
mkdir -p src
cp lib/aave-wrapper-src/src/*.sol src/

echo "[aave-wrapper] done. Run: forge test"
