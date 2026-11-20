#!/usr/bin/env bash
# Build and push the open-terminal actor image, then print the digest-pinned
# image reference substrate ActorTemplates require (repo@sha256:...).
#
# Usage: KOT_REPO=ghcr.io/you/ot-actor ./scripts/build-actor-image.sh [tag]
set -euo pipefail

REPO="${OCI_REPO:?OCI_REPO=registry.example.com/ot-actor is required (write access needed for the digest lookup)}"
TAG="${1:-$(git -C "$(dirname "$0")/.." rev-parse --short HEAD 2>/dev/null || date +%Y%m%d)}"
REF="${OT_REF:-v0.17.20}"   # open-terminal git ref baked into the image

cd "$(dirname "$0")/../images/actor"

docker buildx build \
  --platform linux/amd64 \
  --build-arg OT_REF="${REF}" \
  --push \
  -t "${REPO}:${TAG}" \
  .

DIGEST=$(docker buildx imagetools inspect "${REPO}:${TAG}" | grep -m1 Digest: | awk '{print $2}')
if [[ -z "${DIGEST}" ]]; then
  echo "failed to resolve digest for ${REPO}:${TAG}" >&2
  exit 1
fi

FULL_REF="${REPO}@${DIGEST}"
cat <<EOF

Actor image built:
  tag:    ${REPO}:${TAG}
  digest: ${FULL_REF}

Use with: trident bootstrap -image ${FULL_REF}
EOF
