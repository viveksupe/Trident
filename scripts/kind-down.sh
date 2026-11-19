#!/usr/bin/env bash
# Tear down the kind-based substrate dev cluster.
set -euo pipefail
SUBSTRATE_SRC="${SUBSTRATE_SRC:?SUBSTRATE_SRC=/path/to/substrate checkout is required}"
cd "$SUBSTRATE_SRC"
./hack/delete-kind-cluster.sh
