#!/usr/bin/env bash
# Vendors the exact sources this harness compiles against. Nothing is modified.
set -euo pipefail
cd "$(dirname "$0")"
UMA_COMMIT=f87253a
OZ_TAG=v4.9.6
mkdir -p vendor
if [ ! -d vendor/protocol ]; then
  git clone --depth 1 https://github.com/UMAprotocol/protocol.git vendor/protocol
  git -C vendor/protocol fetch --depth 1 origin "$UMA_COMMIT" && git -C vendor/protocol checkout -q FETCH_HEAD
fi
if [ ! -d vendor/openzeppelin ]; then
  curl -sSL "https://github.com/OpenZeppelin/openzeppelin-contracts/archive/refs/tags/$OZ_TAG.tar.gz" \
    | tar xz -C vendor && mv "vendor/openzeppelin-contracts-${OZ_TAG#v}" vendor/openzeppelin
fi
echo "vendored: $(git -C vendor/protocol rev-parse --short HEAD), oz $OZ_TAG"
