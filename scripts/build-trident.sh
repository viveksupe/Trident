#!/usr/bin/env bash
# Build the trident shim binary into bin/trident.
#
# CGO_ENABLED=0: the sqlite driver is modernc.org/sqlite (pure Go), so the
# shim links statically with no libc dependency — no cross-compile toolchain
# needed. Nothing else in the repo builds this binary; scripts/deploy.sh
# calls this script when bin/trident is missing.
#
# For the shim image (images/trident/Dockerfile COPYs a `trident` file from
# the build context), build the same way at the repo root:
#   CGO_ENABLED=0 go build -o trident ./cmd/trident
set -euo pipefail
cd "$(dirname "$0")/.."

command -v go >/dev/null 2>&1 || { echo "build-trident: go not found on PATH" >&2; exit 1; }

mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/trident ./cmd/trident
echo "built bin/trident ($(du -h bin/trident | awk '{print $1}'))"
