#!/usr/bin/env bash
# Bring up a substrate install per the quickstart (kind), prerequisite: go, kubectl, docker.
# Mirrors the substrate README quickstart; ATE_INSTALL_KIND targets the kind cluster.
set -euo pipefail
SUBSTRATE_SRC="${SUBSTRATE_SRC:?SUBSTRATE_SRC=/path/to/substrate checkout is required}"
cd "$SUBSTRATE_SRC"

if ! kind get clusters 2>/dev/null | grep -q "substrate"; then
  echo "==> creating kind cluster + local registry"
  ./hack/create-kind-cluster.sh
fi
export ATE_INSTALL_KIND=true
echo "==> deploying substrate"
go run ./cmd/ate-setup deploy ate-system --credential-provider='{"name":"k8s.io"}' \
  --ingress-allowed-spiffe-ids='spiffe://cluster.local/ns/ate-system/sa/atenet-client'

echo "==> installing kubectl-ate (if needed)"
if ! command -v kubectl-ate >/dev/null 2>&1; then
  go install ./cmd/kubectl-ate
fi

cat <<'EOF'

Substrate is up. Now build the shim + actor image and run:
  TRI_BACKEND=substrate KUBECONFIG=... bin/trident bootstrap -image <digest>
Then scripts/deploy.sh (or serve out-of-cluster for development).
EOF
