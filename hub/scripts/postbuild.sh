#!/usr/bin/env bash
# Build the SwiftProof Hub image and publish it.
#
# Default target is Docker Hub, so a company can pull the same artifact the
# project publishes; point REGISTRY at an internal registry to keep the image
# inside the network instead.
#
#   hub/scripts/postbuild.sh                      # build, tag, push to Docker Hub
#   VERSION=v0.4.0 hub/scripts/postbuild.sh       # explicit version tag
#   PUSH=false hub/scripts/postbuild.sh           # build and tag only
#   REGISTRY=registry.internal IMAGE_NAMESPACE=platform hub/scripts/postbuild.sh
#
# Credentials come from the environment and are never written to disk by this
# script: DOCKERHUB_USERNAME with DOCKERHUB_TOKEN, or an existing docker login.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

REGISTRY="${REGISTRY:-docker.io}"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:-${DOCKERHUB_USERNAME:-gvinsot}}"
IMAGE_NAME="${IMAGE_NAME:-swiftproof-hub}"
PUSH="${PUSH:-true}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

# Version: an explicit VERSION, the tag being built, or the commit.
if [[ -z "${VERSION:-}" ]]; then
  if git describe --exact-match --tags >/dev/null 2>&1; then
    VERSION="$(git describe --exact-match --tags)"
  else
    VERSION="dev-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  fi
fi
if [[ ! "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$ ]]; then
  echo "postbuild: refusing the unusable version '$VERSION'" >&2
  exit 1
fi

image="${REGISTRY}/${IMAGE_NAMESPACE}/${IMAGE_NAME}"
if [[ "$REGISTRY" == "docker.io" ]]; then
  # Docker Hub is addressed without its registry host.
  image="${IMAGE_NAMESPACE}/${IMAGE_NAME}"
fi

tags=("${image}:${VERSION}")
# Only a released version moves the floating tag; a dev build never does.
if [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  tags+=("${image}:latest")
fi

echo "postbuild: image   ${image}"
echo "postbuild: version ${VERSION}"
echo "postbuild: tags    ${tags[*]}"
echo "postbuild: push    ${PUSH}"

if [[ "$PUSH" == "true" && -n "${DOCKERHUB_TOKEN:-}" && -n "${DOCKERHUB_USERNAME:-}" ]]; then
  echo "postbuild: signing in to ${REGISTRY} as ${DOCKERHUB_USERNAME}"
  printf '%s' "$DOCKERHUB_TOKEN" | docker login "$REGISTRY" --username "$DOCKERHUB_USERNAME" --password-stdin
fi

tag_args=()
for tag in "${tags[@]}"; do
  tag_args+=(--tag "$tag")
done

# buildx produces the multi-architecture manifest an on-premise cluster may
# need; it is also the only way to push several platforms in one pass.
if docker buildx version >/dev/null 2>&1; then
  builder="${BUILDX_BUILDER:-swiftproof-hub}"
  docker buildx inspect "$builder" >/dev/null 2>&1 || docker buildx create --name "$builder" --driver docker-container >/dev/null
  output=(--load)
  platforms=("--platform" "linux/amd64")
  if [[ "$PUSH" == "true" ]]; then
    output=(--push)
    platforms=("--platform" "$PLATFORMS")
  fi
  docker buildx build \
    --builder "$builder" \
    "${platforms[@]}" \
    --file hub/Dockerfile \
    --build-arg "VERSION=${VERSION}" \
    "${tag_args[@]}" \
    "${output[@]}" \
    .
else
  echo "postbuild: buildx is unavailable, falling back to a single-platform build" >&2
  docker build --file hub/Dockerfile --build-arg "VERSION=${VERSION}" "${tag_args[@]}" .
  if [[ "$PUSH" == "true" ]]; then
    for tag in "${tags[@]}"; do
      docker push "$tag"
    done
  fi
fi

echo "postbuild: done"
for tag in "${tags[@]}"; do
  echo "  ${tag}"
done
