#!/usr/bin/env bash
# Deploy trident to an existing substrate cluster.
#
# Steps:
#  1. (optional) build & push the actor image
#  2. bootstrap the ActorTemplate + golden snapshot via the shim binary
#  3. apply WorkerPool + shim RBAC + Deployment
#  4. print the Open WebUI settings
set -euo pipefail
cd "$(dirname "$0")/.."

VALUES="${VALUES:-manifest/values.sh}"
if [[ -f "${VALUES}" ]]; then
  # shellcheck disable=SC1090
  source "${VALUES}"
else
  echo "values file ${VALUES} not found; export the manifest/values.sh.example values" >&2
fi
: "${OCI_REPO:?set OCI_REPO in manifest/values.sh}"
: "${TRI_API_KEY:?set TRI_API_KEY}"
export ATESPACE="${ATESPACE:-ots-webui}"
export ATE_SYSTEM_NAMESPACE="${ATE_SYSTEM_NAMESPACE:-ate-system}"
TRI_NAMESPACE="${TRI_NAMESPACE:-trident}"
ACTOR_IMAGE="${ACTOR_IMAGE:-}"

if [[ -z "${ACTOR_IMAGE}" ]]; then
  echo "==> building actor image"
  ACTOR_IMAGE="$(scripts/build-actor-image.sh | grep 'digest:' | awk '{print $2}')"
  echo "    ${ACTOR_IMAGE}"
fi
TRI_IMAGE="${TRI_IMAGE:-trident:dev}"

# 1. Worker pool (Kubernetes CRD, not the ate API).
echo "==> applying worker pool"
export WORKERPOOL_NAMESPACE="${TRI_NAMESPACE}"
export WORKERPOOL_REPLICAS="${WORKERPOOL_REPLICAS:-3}"
export WORKERPOOL_CPU="${WORKERPOOL_CPU:-2}"
export WORKERPOOL_MEMORY="${WORKERPOOL_MEMORY:-4608Mi}"
kubectl label namespace "${WORKERPOOL_NAMESPACE}" ate.dev/api-access=true --overwrite
envsubst < manifest/workers/workerpool.yaml.tmpl | kubectl apply -f -

# 2. RBAC + shim secret.
echo "==> applying shim RBAC"
export TRI_NAMESPACE
envsubst < manifest/trident/sa-rbac.yaml | kubectl apply -f -

# 3. Boot the template (golden snapshot build; idempotent).
echo "==> bootstrapping ActorTemplate (waits for golden snapshot)"
if [[ "${TRI_IMAGE}" == *":latest" || -n "${KUBECONFIG:-}" ]]; then
  "${TRI_BIN:-$PWD/bin/trident}" bootstrap -image "${ACTOR_IMAGE}"
else
  echo "no kubeconfig for the shim binary to connect; run: trident bootstrap -image ${ACTOR_IMAGE}" >&2
  exit 1
fi

# 4. Shim Deployment.
echo "==> deploying trident"
export ACTOR_PORT="${ACTOR_PORT:-8000}"
export IDLE_TTL="${IDLE_TTL:-10m}"
export MAX_AGE="${MAX_AGE:-168h}"
export FEATURES_JSON="${FEATURES_JSON}"
export EGRESS_HOSTS="${EGRESS_HOSTS}"
envsubst < manifest/trident/deployment.yaml | kubectl apply -f -

cat <<EOF

Done. Point Open WebUI at:
  Admin Settings -> Integrations -> Open Terminal
  URL:  the trident Service from step 4 (or its ingress/NodePort URL)
  Key:  the value of TRI_API_KEY

Remember: actor images are digest-pinned; replacing the ActorTemplate (new
image) cold-boots every chat actor. Deploy image bumps in a maintenance window.
EOF
