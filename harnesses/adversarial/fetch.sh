#!/usr/bin/env bash
# Fetch the dependencies the adversarial harness needs to compile.
#
# Nothing fetched here is committed: harnesses/*/lib/ is git-ignored (see
# .gitignore) and re-created by this script, so the repository stays small and
# no third-party tree is vendored. The revision is pinned so a counterexample
# stays reproducible across sandboxes.
#
# Without this step the project cannot resolve `forge-std/Test.sol`, so forge,
# halmos, echidna and medusa all fail to compile the harness and every live
# engine test would report a *toolchain* failure that looks like a clean scan.
#
# Requires: git. Network access to github.com on first run only.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

FORGE_STD_REV="v1.9.0"   # same pin as harnesses/aave-wrapper/fetch-deps.sh

if [ -d "lib/forge-std/.git" ]; then
  echo "forge-std already present at lib/forge-std"
else
  mkdir -p lib
  git clone --quiet --depth 1 --branch "$FORGE_STD_REV" \
    https://github.com/foundry-rs/forge-std.git lib/forge-std
  echo "installed forge-std $FORGE_STD_REV into lib/forge-std"
fi
