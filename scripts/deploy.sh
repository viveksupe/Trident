#!/usr/bin/env bash
# Deploy trident to an existing substrate cluster.
#
# Steps:
#  1. (optional) build & push the actor image
#  2. apply WorkerPool (creates the namespace) then label it for api access
#  3. bootstrap the ActorTemplate + golden snapshot via the shim binary
#  4. apply shim RBAC + Deployment
#  5. print the Open WebUI settings
set -euo pipefail
cd "$(dirname "$0")/.."

VALUES="${VALUES:-manifest/values.sh}"
if [[ -f "${VALUES}" ]]; then
  # shellcheck disable=SC1090
  source "${VALUES}"
else
  echo "values file ${VALUES} not found; export the manifest/values.sh.example values" >&2
  exit 1
fi
: "${OCI_REPO:?set OCI_REPO in manifest/values.sh}"
: "${TRI_API_KEY:?set TRI_API_KEY}"
# Distinct secrets: agents hold TRI_API_KEY (baked as OPEN_TERMINAL_API_KEY)
# and can reach the callback listener — a shared key would let an agent
# proxy to any user's actor; a console token equal to the API key would let
# one self-approve egress.
: "${TRI_ACTOR_API_KEY:?set TRI_ACTOR_API_KEY (must differ from TRI_API_KEY)}"
: "${TRI_CONSOLE_TOKEN:?set TRI_CONSOLE_TOKEN (must differ from TRI_API_KEY)}"
if [[ "${TRI_ACTOR_API_KEY}" == "${TRI_API_KEY}" || "${TRI_CONSOLE_TOKEN}" == "${TRI_API_KEY}" ]]; then
  echo "TRI_ACTOR_API_KEY and TRI_CONSOLE_TOKEN must both differ from TRI_API_KEY" >&2
  exit 1
fi
export ATESPACE="${ATESPACE:-ots-webui}"
export ATE_SYSTEM_NAMESPACE="${ATE_SYSTEM_NAMESPACE:-ate-system}"
export TRI_NAMESPACE="${TRI_NAMESPACE:-trident}"
export TEMPLATE_NAME="${TEMPLATE_NAME:-open-terminal}"
ACTOR_IMAGE="${ACTOR_IMAGE:-}"

if [[ -z "${ACTOR_IMAGE}" ]]; then
  echo "==> building actor image"
  ACTOR_IMAGE="$(scripts/build-actor-image.sh | grep 'digest:' | awk '{print $2}')"
  echo "    ${ACTOR_IMAGE}"
fi
TRI_IMAGE="${TRI_IMAGE:-trident:dev}"

# 1. Worker pool (Kubernetes CRD, not the ate API). The template creates the
# namespace, so apply BEFORE labelling it (labelling first aborted under
# set -e on a fresh cluster).
echo "==> applying worker pool"
export WORKERPOOL_NAMESPACE="${TRI_NAMESPACE}"
export WORKERPOOL_REPLICAS="${WORKERPOOL_REPLICAS:-3}"
export WORKERPOOL_CPU="${WORKERPOOL_CPU:-4}"
export WORKERPOOL_MEMORY="${WORKERPOOL_MEMORY:-8192Mi}"
export WORKER_IMAGE="${WORKER_IMAGE:?set WORKER_IMAGE (digest-pinned ateworker image)}"
envsubst < manifest/workers/workerpool.yaml.tmpl | kubectl apply -f -
kubectl label namespace "${WORKERPOOL_NAMESPACE}" ate.dev/api-access=true --overwrite

# 2. Boot the template (golden snapshot build; idempotent).
echo "==> bootstrapping ActorTemplate (waits for golden snapshot)"
export TRI_ACTOR_API_KEY TRI_CONSOLE_TOKEN
if [[ "${TRI_IMAGE}" == *":latest" || -n "${KUBECONFIG:-}" ]]; then
  "${TRI_BIN:-$PWD/bin/trident}" bootstrap -image "${ACTOR_IMAGE}"
else
  echo "no kubeconfig for the shim binary to connect; run: TRI_ACTOR_API_KEY=... trident bootstrap -image ${ACTOR_IMAGE}" >&2
  exit 1
fi

# 3. RBAC + shim secret (needs the values above).
echo "==> applying shim RBAC + secret"
envsubst < manifest/trident/sa-rbac.yaml | kubectl apply -f -

# 4. Shim Deployment.
echo "==> deploying trident"
export ACTOR_PORT="${ACTOR_PORT:-8000}"
export IDLE_TTL="${IDLE_TTL:-10m}"
export DELETE_IDLE_TTL="${DELETE_IDLE_TTL:-48h}"
export MAX_AGE="${MAX_AGE:-168h}"
export FEATURES_JSON="${FEATURES_JSON:-}"
export EGRESS_HOSTS="${EGRESS_HOSTS:-}"
envsubst < manifest/trident/deployment.yaml | kubectl apply -f -

cat <<EOF

Done. Point Open WebUI at:
  Admin Settings -> Integrations -> Open Terminal
  URL:  the trident Service from step 4 (or its ingress/NodePort URL)
  Key:  the value of TRI_API_KEY

Remember: actor images are digest-pinned; replacing the ActorTemplate (new
image or actor-key change) cold-boots every chat actor. Deploy image bumps in
a maintenance window.
EOF
