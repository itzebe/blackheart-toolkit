#!/usr/bin/env bash
# Vendor the third external, independently-maintained target for the mission-08
# EVM harness: Euler V1 (euler-legacy-xyz/euler-contracts), and build the
# vulnerable upstream protocol, our integration glue, and the differential
# *control* (a patched EToken).
#
# Target (public, third-party, real production protocol -- the V1 lending system
# that was exploited in March 2023; the flaw exercised here was fixed on-chain by
# governance and is reproduced only as a local, git-ignored test target):
#   https://github.com/euler-legacy-xyz/euler-contracts  @ commit
#   24da0f2de98d984b0007133b2c251e7fbbda4115
#
# Everything vendored/built here is git-ignored and re-created by this script.
# Idempotent: re-running reuses the existing checkout. No paid service, no key,
# no network beyond the public git remotes and npm.
#
# Licence note: Euler V1 is GPL-2.0-or-later. It is used here only as a
# locally-built, git-ignored test target (never redistributed, never deployed);
# our differential control in controls/ is a minimal patched copy of the affected
# module, compiled against the same source.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"
EULER="$VENDOR/euler-contracts"

EULER_REPO="https://github.com/euler-legacy-xyz/euler-contracts.git"
EULER_PIN="24da0f2de98d984b0007133b2c251e7fbbda4115"

export PATH="${PATH}:/home/openhands/.foundry/bin"

if [ ! -d "$EULER/.git" ]; then
  mkdir -p "$VENDOR"
  echo "  fetching $EULER_REPO -> $EULER"
  git clone --quiet "$EULER_REPO" "$EULER"
else
  echo "  present: $EULER"
fi

# Enforce the pin unconditionally, not only on first clone: a checkout left on a
# different revision must not silently change the bytecode the cases were
# validated against.
echo "  checking out pin $EULER_PIN"
git -C "$EULER" fetch --quiet origin "$EULER_PIN" 2>/dev/null || true
git -C "$EULER" checkout --quiet --force "$EULER_PIN"
HEAD="$(git -C "$EULER" rev-parse HEAD)"
if [ "$HEAD" != "$EULER_PIN" ]; then
  echo "  ERROR: HEAD is $HEAD, expected pin $EULER_PIN" >&2
  exit 1
fi
echo "  Euler V1 at $HEAD"

# npm deps: the vendored contracts import hardhat/console.sol (in Base.sol and the
# test helpers); the Foundry build resolves that through the node_modules tree.
echo "  installing npm deps (for the hardhat/console import shim)"
if [ ! -d "$EULER/node_modules" ]; then
  (cd "$EULER" && npm install --silent --no-audit --no-fund)
fi

# Foundry build config for the vendored tree. Generated (not committed) so it can
# never drift from the vendored dependencies. Mirrors the upstream Hardhat config
# (solc 0.8.10, optimizer on, runs 1000000) so the bytecode the engine exercises
# matches the production compilation.
cat > "$EULER/foundry.toml" <<'TOML'
[profile.default]
src = "contracts"
out = "out"
optimizer = true
optimizer_runs = 1000000
bytecode_hash = "none"
evm_version = "london"
remappings = ["hardhat/=node_modules/hardhat/"]
TOML

echo "  building vulnerable upstream contracts"
(cd "$EULER" && forge build --quiet)

# The harness tests need forge-std; its lib/ is git-ignored like every harness.
if [ ! -d "$HERE/lib/forge-std" ]; then
  echo "  installing forge-std into the harness"
  (cd "$HERE" && forge install foundry-rs/forge-std --no-commit --quiet)
fi

# Harness remappings: the vendored Euler source plus forge-std. Generated so the
# paths always match the layout created above.
cat > "$HERE/remappings.txt" <<'REMAP'
euler/=vendor/euler-contracts/contracts/
hardhat/=vendor/euler-contracts/node_modules/hardhat/
forge-std/=lib/forge-std/src/
REMAP

echo "  building integration glue (Bootstrap + MockERC20)"
(cd "$HERE" && forge build --quiet)

# The controls reuse the vendored Euler source one level up; rewrite the remapping
# prefixes accordingly. Generated (not committed) so it cannot drift.
cat > "$HERE/controls/remappings.txt" <<'REMAP'
euler/=../vendor/euler-contracts/contracts/
hardhat/=../vendor/euler-contracts/node_modules/hardhat/
REMAP

echo "  building differential control contracts"
(cd "$HERE/controls" && forge build --quiet)

echo "euler-v1 ready: $EULER (pin $EULER_PIN) + harness + controls"
