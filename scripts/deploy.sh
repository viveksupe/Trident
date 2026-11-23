#!/usr/bin/env bash
# Deploy trident to an existing substrate cluster.
#
# Steps:
#  1. (optional) build & push the actor image
#  2. apply WorkerPool (creates the namespace) then label it for api access
#  3. bootstrap the ActorTemplate + golden snapshot via the shim binary
#     (bin/trident — built on demand by scripts/build-trident.sh)
#  4. apply shim RBAC + Deployment
#  5. print the Open WebUI settings
#
# Usage: scripts/deploy.sh [--rotate]
#   --rotate  regenerate all THREE secrets and persist them (loud: breaks
#             Open WebUI's saved API key and cold-boots every chat actor)
set -euo pipefail
cd "$(dirname "$0")/.."

ROTATE=0
for arg in "$@"; do
  case "${arg}" in
    --rotate) ROTATE=1 ;;
    -h|--help) echo "usage: scripts/deploy.sh [--rotate]" >&2; exit 0 ;;
    *) echo "usage: scripts/deploy.sh [--rotate]" >&2; exit 1 ;;
  esac
done

VALUES="${VALUES:-manifest/values.sh}"
if [[ -f "${VALUES}" ]]; then
  # shellcheck disable=SC1090
  source "${VALUES}"
else
  echo "values file ${VALUES} not found; cp manifest/values.sh.example ${VALUES} and edit it" >&2
  exit 1
fi

# Fail fast, BEFORE the actor image build/push: everything below needs
# cluster access and the render/apply tooling. The old step-2 gate keyed on
# the TRI_IMAGE tag ("built image tag OR kubeconfig") — nonsense; only
# cluster credentials decide whether bootstrap can run (P2-16).
: "${KUBECONFIG:?KUBECONFIG is not set — export it; deploy.sh bootstraps the ActorTemplate and kubectl-applies the manifests (the TRI_IMAGE tag does not gate this step)}"
for tool in envsubst kubectl; do
  command -v "${tool}" >/dev/null 2>&1 || { echo "required tool not on PATH: ${tool}" >&2; exit 1; }
done

# Secrets: generate whatever is missing ONCE and write it straight back into
# ${VALUES}, so the next deploy reuses the same keys. The example file used
# to default all three to "$(openssl rand ...)", i.e. a fresh random value on
# EVERY source (M6): Open WebUI's saved API key silently broke on each
# redeploy and the rotated actor key cold-booted every chat actor. A value
# that is already set (environment or a persisted values.sh) is never
# re-rolled unless --rotate says so.
#
# (The current value is passed by the caller: bash rejects the indirection
# "${!name:-}" with "invalid indirect expansion", which under set -e would
# abort the deploy at the first call.)
ensure_secret() {
  local name="$1" value="$2"
  if [[ "${ROTATE}" -eq 1 || -z "${value}" ]]; then
    command -v openssl >/dev/null 2>&1 || { echo "openssl is required to generate ${name}" >&2; exit 1; }
    value="$(openssl rand -hex 24)"
    printf -v "${name}" '%s' "${value}"
    export "${name?}"
    echo "==> generated ${name}"
  fi
  if ! grep -qF "export ${name}=\"${value}\"" "${VALUES}"; then
    # Replace the (still-template) line in place, or append: the file then
    # holds the literal value and later runs skip generation entirely.
    awk -v n="${name}" -v v="${value}" '
      index($0, "export " n "=") == 1 { print "export " n "=\"" v "\""; seen = 1; next }
      { print }
      END { if (!seen) print "export " n "=\"" v "\"" }' "${VALUES}" > "${VALUES}.tmp"
    # VALUES holds literal secret material from here on: tighten the mode on
    # both the temp file (pre-mv) and the target, and keep it tight on reruns.
    chmod 600 "${VALUES}.tmp"
    mv "${VALUES}.tmp" "${VALUES}"
    chmod 600 "${VALUES}"
    echo "==> persisted ${name} -> ${VALUES}"
  fi
}
if [[ "${ROTATE}" -eq 1 ]]; then
  echo "==> --rotate: rolling all three secrets."
  echo "    Open WebUI's saved API key stops working and the new actor key"
  echo "    cold-boots every chat actor — do this in a maintenance window."
fi
ensure_secret TRI_API_KEY "${TRI_API_KEY:-}"
ensure_secret TRI_ACTOR_API_KEY "${TRI_ACTOR_API_KEY:-}"
ensure_secret TRI_CONSOLE_TOKEN "${TRI_CONSOLE_TOKEN:-}"

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
# Render-only defaults for manifest/trident/deployment.yaml (exported: envsubst
# is a child process and sees only the environment — the old bare assignment
# rendered "image:" empty whenever TRI_IMAGE came from this default).
export TRI_IMAGE="${TRI_IMAGE:-trident:dev}"
export TRI_ACTOR_PREFIX="${TRI_ACTOR_PREFIX:-ot-}"

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

# 2. Boot the template (golden snapshot build; idempotent). Cluster access
#    was already required up front (the TRI_IMAGE-tag gate is gone), and
#    bin/trident is built on demand — nothing else in the repo builds it.
echo "==> bootstrapping ActorTemplate (waits for golden snapshot)"
export TRI_ACTOR_API_KEY TRI_CONSOLE_TOKEN
TRI_BIN="${TRI_BIN:-$PWD/bin/trident}"
if [[ ! -x "${TRI_BIN}" ]]; then
  echo "==> ${TRI_BIN} missing; building it (scripts/build-trident.sh)"
  scripts/build-trident.sh
  if [[ ! -x "${TRI_BIN}" ]]; then
    echo "TRI_BIN=${TRI_BIN} still does not exist; run scripts/build-trident.sh or point TRI_BIN at a built binary" >&2
    exit 1
  fi
fi
"${TRI_BIN}" bootstrap -image "${ACTOR_IMAGE}"

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
