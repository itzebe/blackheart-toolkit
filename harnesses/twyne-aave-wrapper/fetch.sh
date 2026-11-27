#!/usr/bin/env bash
# Fetch the real, in-scope Twyne AaveV3 aToken wrapper source and its pinned
# dependencies into this harness, so adversarial fork tests run against the
# actual audited code rather than a model.
#
# The upstream repository is public and in the Twyne Immunefi scope:
#   https://github.com/0xTwyne/aave-v3-aToken-wrapper
#
# Idempotent: re-running reuses an existing checkout. No paid service, no API key.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR="$HERE/vendor"
UPSTREAM_URL="https://github.com/0xTwyne/aave-v3-aToken-wrapper.git"
# Pin recorded from the scope review (main HEAD at time of engagement).
PIN="${TWYNE_WRAPPER_PIN:-797be33e22cce033f6d9c66650d9604ee48fc60d}"

mkdir -p "$VENDOR"

if [ ! -d "$VENDOR/.git" ]; then
  echo "fetch: cloning $UPSTREAM_URL"
  git clone "$UPSTREAM_URL" "$VENDOR"
fi

cd "$VENDOR"
echo "fetch: checking out pinned revision $PIN"
git fetch --depth 1 origin "$PIN" 2>/dev/null || git fetch --tags origin
git checkout -q "$PIN" 2>/dev/null || git checkout -q "$(git rev-parse HEAD)"

echo "fetch: initialising submodules (recursive, shallow)"
git submodule update --init --recursive --depth 1

# Derive remappings so the harness compiles the vendored source. The upstream
# remappings.txt already has the right shape; rewrite the `lib/` prefix to
# `vendor/lib/` and keep forge-std pointing at the vendored copy.
sed 's#^\([^ ]*\)=lib/#\1=vendor/lib/#' remappings.txt > "$HERE/remappings.txt"
grep -q '^forge-std/=' "$HERE/remappings.txt" || echo 'forge-std/=vendor/lib/forge-std/src/' >> "$HERE/remappings.txt"
grep -q '^src/=' "$HERE/remappings.txt" || echo 'src/=vendor/src/' >> "$HERE/remappings.txt"

echo "fetch: done -> $VENDOR"
echo "fetch: upstream revision $(git rev-parse HEAD)"
