#!/usr/bin/env bash
# Vendor the real, in-scope Hyperliquid bridge source and its pinned dependencies
# so adversarial and invariant tests run against the actual audited contract.
#
# Target (public, source-available, real mainnet code):
#   https://github.com/hyperliquid-dex/contracts  -> Bridge2.sol, Signature.sol
#   Deployed (legacy Arbitrum USDC bridge):
#     https://arbiscan.io/address/0x2df1c51e09aecf9cacb7bc98cb1742757f163df7
#
# Everything vendored here is git-ignored and re-created by this script.
# Idempotent: re-running reuses an existing checkout. No paid service, no API key.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"

HL_REPO="https://github.com/hyperliquid-dex/contracts.git"
HL_PIN="d7e66aa751ffbd19bfd2b90fd5d9a3d8f32d99ee"
OZ_REPO="https://github.com/OpenZeppelin/openzeppelin-contracts.git"
OZ_PIN="v4.9.6"
NITRO_REPO="https://github.com/OffchainLabs/nitro-contracts.git"
NITRO_PIN="v1.2.1"
FORGE_STD_REPO="https://github.com/foundry-rs/forge-std.git"
FORGE_STD_PIN="v1.9.6"

fetch() { # url dir rev
  local url="$1" dir="$2" rev="$3"
  if [ -d "$dir/.git" ]; then echo "  present: $dir"; return; fi
  echo "  fetching $url @ $rev -> $dir"
  git clone --quiet "$url" "$dir"
  git -C "$dir" checkout --quiet "$rev"
}

mkdir -p "$VENDOR/lib" "$VENDOR/src"
echo "[hyperliquid-bridge] fetching the real bridge source"
fetch "$HL_REPO" "$VENDOR/hl-contracts" "$HL_PIN"
cp "$VENDOR/hl-contracts/Bridge2.sol" "$VENDOR/hl-contracts/Signature.sol" "$VENDOR/src/"

echo "[hyperliquid-bridge] fetching pinned dependencies"
fetch "$OZ_REPO" "$VENDOR/lib/openzeppelin-contracts" "$OZ_PIN"
fetch "$NITRO_REPO" "$VENDOR/lib/nitro-contracts" "$NITRO_PIN"
fetch "$FORGE_STD_REPO" "$VENDOR/lib/forge-std" "$FORGE_STD_PIN"

# remappings.txt is git-ignored (it points at vendored paths), so generate it here.
cat > "$HERE/remappings.txt" <<'EOF'
@openzeppelin/contracts/=vendor/lib/openzeppelin-contracts/contracts/
@arbitrum/nitro-contracts/=vendor/lib/nitro-contracts/
forge-std/=vendor/lib/forge-std/src/
EOF

echo "[hyperliquid-bridge] done -> $VENDOR"
echo "[hyperliquid-bridge] bridge revision $(git -C "$VENDOR/hl-contracts" rev-parse HEAD)"
