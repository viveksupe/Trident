#!/usr/bin/env bash
# Smoke-render every manifest template the way scripts/deploy.sh does —
# envsubst over manifest/values.sh.example — then structurally check the
# YAML. No cluster, no kubectl: safe to call from CI (the example's empty
# secrets render as "", which is structurally fine; deploy.sh generates
# real values at deploy time).
#
# Only the variables the manifests actually consume are substituted: a
# typo'd or missing name then survives as a literal ${VAR} and fails the
# check below instead of silently rendering as an empty string (the bug
# class behind the un-exported TRI_IMAGE default).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v envsubst >/dev/null 2>&1 || { echo "render-manifest: envsubst not found (install gettext)" >&2; exit 1; }

# The committed example keeps this deterministic in CI; values.sh (user
# secrets) is deliberately NOT read.
# shellcheck disable=SC1091
source manifest/values.sh.example

# Defaults scripts/deploy.sh exports itself before rendering:
export TRI_IMAGE="${TRI_IMAGE:-trident:dev}"
export TRI_ACTOR_PREFIX="${TRI_ACTOR_PREFIX:-ot-}"
export WORKERPOOL_NAMESPACE="${WORKERPOOL_NAMESPACE:-${TRI_NAMESPACE}}"

VARS='${ATESPACE} ${TEMPLATE_NAME} ${TRI_NAMESPACE} ${TRI_ACTOR_PREFIX} ${TRI_IMAGE} ${TRI_API_KEY} ${TRI_ACTOR_API_KEY} ${TRI_CONSOLE_TOKEN} ${ACTOR_PORT} ${IDLE_TTL} ${DELETE_IDLE_TTL} ${MAX_AGE} ${FEATURES_JSON} ${EGRESS_HOSTS} ${ATE_SYSTEM_NAMESPACE} ${WORKERPOOL_NAMESPACE} ${WORKERPOOL_REPLICAS} ${WORKERPOOL_CPU} ${WORKERPOOL_MEMORY} ${WORKER_IMAGE}'

have_pyyaml=0
python3 -c 'import yaml' >/dev/null 2>&1 && have_pyyaml=1

fail=0
while IFS= read -r f; do
  out="$(mktemp)"
  if ! envsubst "${VARS}" < "${f}" > "${out}"; then
    echo "FAIL: ${f}: envsubst failed" >&2
    rm -f "${out}"; fail=1; continue
  fi
  leftover="$(grep -n '\${' "${out}" || true)"
  if [[ -n "${leftover}" ]]; then
    echo "FAIL: ${f}: unrendered \${...} variables (missing from VARS or unset):" >&2
    echo "${leftover}" >&2
    rm -f "${out}"; fail=1; continue
  fi
  if [[ "${have_pyyaml}" -eq 1 ]]; then
    if ! python3 - "${f}" "${out}" <<'PY'
import sys, yaml
path, rendered = sys.argv[1], sys.argv[2]
with open(rendered) as fh:
    docs = [d for d in yaml.safe_load_all(fh) if d is not None]
if not docs:
    sys.exit(f"FAIL: {path}: no YAML documents after render")
kinds = [d.get("kind", "?") if isinstance(d, dict) else type(d).__name__ for d in docs]
print(f"  ok {path}: {len(docs)} doc(s): {', '.join(kinds)}")
PY
    then
      echo "FAIL: ${f}: rendered output is not valid YAML (see above)" >&2
      fail=1
    fi
  else
    # Structural fallback without pyyaml: non-empty and every document
    # declares apiVersion/kind.
    if [[ ! -s "${out}" ]] || ! grep -q '^apiVersion:' "${out}" || ! grep -q '^kind:' "${out}"; then
      echo "FAIL: ${f}: rendered output lacks apiVersion:/kind: (pyyaml unavailable for a full check)" >&2
      fail=1
    else
      echo "  ok ${f} (structural check; install pyyaml for full YAML parsing)"
    fi
  fi
  rm -f "${out}"
done < <(find manifest -type f \( -name '*.yaml' -o -name '*.tmpl' \) | sort)

if [[ "${fail}" -ne 0 ]]; then
  echo "render-manifest: FAILED" >&2
  exit 1
fi
echo "render-manifest: all manifests render cleanly"
