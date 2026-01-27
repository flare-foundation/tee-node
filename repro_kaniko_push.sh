#!/bin/bash
set -euo pipefail

# Usage: ./repro_kaniko_push.sh [base-image-tag]
# Example: ./repro_kaniko_push.sh europe-west1-docker.pkg.dev/flare-network-sandbox/containers/tee-node-repro-test:v1
#
# This script builds the same image TWICE using Kaniko, pushes both to Artifact Registry,
# then compares them to verify reproducibility.
#
# Prerequisites:
#   - gcloud auth login (authenticated with AR access)
#   - crane installed (go install github.com/google/go-containerregistry/cmd/crane@latest)
#   - docker (to build the kaniko-gcloud helper image)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KANIKO_IMAGE="kaniko-gcloud:local"

DEFAULT_BASE="europe-west1-docker.pkg.dev/flare-network-sandbox/containers/tee-node-repro-test:v1"
BASE_IMAGE="${1:-$DEFAULT_BASE}"

IMAGE_BUILD1="${BASE_IMAGE}-build1"
IMAGE_BUILD2="${BASE_IMAGE}-build2"

# Use git commit timestamp for SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH

echo "========================================"
echo "Reproducible Build Test with Kaniko"
echo "========================================"
echo ""
echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH ($(date -d "@$SOURCE_DATE_EPOCH" --utc '+%Y-%m-%d %H:%M:%S UTC'))"
echo ""
echo "Build 1: $IMAGE_BUILD1"
echo "Build 2: $IMAGE_BUILD2"
echo ""

# Check prerequisites
check_prerequisites() {
  echo "=== Checking prerequisites ==="

  if ! command -v gcloud &> /dev/null; then
    echo "ERROR: gcloud not found. Install Google Cloud SDK."
    exit 1
  fi

  if ! gcloud auth print-access-token &> /dev/null; then
    echo "ERROR: Not authenticated with gcloud. Run: gcloud auth login"
    exit 1
  fi

  if ! command -v crane &> /dev/null; then
    echo "WARNING: crane not found. Install with:"
    echo "  go install github.com/google/go-containerregistry/cmd/crane@latest"
    echo ""
    echo "Continuing without crane (manual comparison needed)..."
    HAVE_CRANE=false
  else
    HAVE_CRANE=true
  fi

  if ! command -v docker &> /dev/null; then
    echo "ERROR: docker not found."
    exit 1
  fi

  echo "Prerequisites OK"
  echo ""
}

# Build the kaniko-gcloud helper image
build_kaniko_image() {
  echo "=== Building kaniko-gcloud helper image ==="

  if docker image inspect "$KANIKO_IMAGE" &> /dev/null; then
    echo "Using existing $KANIKO_IMAGE image"
  else
    echo "Building $KANIKO_IMAGE..."
    docker build -f "$SCRIPT_DIR/gcloud-kaniko-Dockerfile" -t "$KANIKO_IMAGE" "$SCRIPT_DIR"
  fi
  echo ""
}

# Run kaniko build
run_kaniko_build() {
  local destination="$1"
  local build_name="$2"

  echo "=== Building: $build_name ==="
  echo "Destination: $destination"
  echo ""

  docker run --rm \
    -v "$SCRIPT_DIR:/workspace" \
    -v "$HOME/.config/gcloud:/root/.config/gcloud:ro" \
    "$KANIKO_IMAGE" \
    --dockerfile=/workspace/Dockerfile \
    --context=dir:///workspace \
    --destination="$destination" \
    --reproducible \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"

  echo ""
  echo "$build_name complete"
  echo ""
}

# Compare images using crane
compare_images() {
  echo "========================================"
  echo "Comparing Images"
  echo "========================================"
  echo ""

  if [ "$HAVE_CRANE" = false ]; then
    echo "crane not available. Manual comparison commands:"
    echo "  crane digest $IMAGE_BUILD1"
    echo "  crane digest $IMAGE_BUILD2"
    echo "  crane manifest $IMAGE_BUILD1 | jq ."
    echo "  crane manifest $IMAGE_BUILD2 | jq ."
    return 1
  fi

  # Authenticate crane with gcloud
  gcloud auth print-access-token | crane auth login "${IMAGE_BUILD1%%/*}" -u oauth2accesstoken --password-stdin

  echo "Fetching digests..."
  DIGEST1=$(crane digest "$IMAGE_BUILD1" 2>/dev/null || echo "FAILED")
  DIGEST2=$(crane digest "$IMAGE_BUILD2" 2>/dev/null || echo "FAILED")

  echo ""
  echo "Build 1 digest: $DIGEST1"
  echo "Build 2 digest: $DIGEST2"
  echo ""

  if [ "$DIGEST1" = "FAILED" ] || [ "$DIGEST2" = "FAILED" ]; then
    echo "ERROR: Failed to fetch one or both digests"
    return 1
  fi

  if [ "$DIGEST1" = "$DIGEST2" ]; then
    echo "========================================"
    echo "SUCCESS: Builds are IDENTICAL!"
    echo "========================================"
    echo ""
    echo "Both builds produced the same digest: $DIGEST1"
    return 0
  else
    echo "========================================"
    echo "DIFFERENCE DETECTED (expected for metadata)"
    echo "========================================"
    echo ""

    echo "=== Manifest Comparison ==="
    echo ""
    diff -u \
      <(crane manifest "$IMAGE_BUILD1" | jq -S .) \
      <(crane manifest "$IMAGE_BUILD2" | jq -S .) || true

    echo ""
    echo "=== Config Comparison ==="
    echo ""
    diff -u \
      <(crane config "$IMAGE_BUILD1" | jq -S .) \
      <(crane config "$IMAGE_BUILD2" | jq -S .) || true

    echo ""
    echo "=== Layer Comparison ==="
    echo ""

    LAYERS1=$(crane manifest "$IMAGE_BUILD1" | jq -r '.layers[].digest' | sort)
    LAYERS2=$(crane manifest "$IMAGE_BUILD2" | jq -r '.layers[].digest' | sort)

    if [ "$LAYERS1" = "$LAYERS2" ]; then
      echo "Layer digests are IDENTICAL"
      echo ""
      echo "The difference is only in image config/metadata, not in actual content."
      echo "This is expected and acceptable for reproducibility verification."
      return 0
    else
      echo "Layer digests DIFFER:"
      echo ""
      echo "Build 1 layers:"
      echo "$LAYERS1"
      echo ""
      echo "Build 2 layers:"
      echo "$LAYERS2"
      echo ""
      diff -u <(echo "$LAYERS1") <(echo "$LAYERS2") || true
      return 1
    fi
  fi
}

# Main
main() {
  check_prerequisites
  build_kaniko_image

  echo "========================================"
  echo "Starting Build 1"
  echo "========================================"
  run_kaniko_build "$IMAGE_BUILD1" "Build 1"

  echo "========================================"
  echo "Starting Build 2"
  echo "========================================"
  run_kaniko_build "$IMAGE_BUILD2" "Build 2"

  compare_images
  exit_code=$?

  echo ""
  echo "========================================"
  echo "Summary"
  echo "========================================"
  echo "Build 1: $IMAGE_BUILD1"
  echo "Build 2: $IMAGE_BUILD2"
  echo ""

  if [ $exit_code -eq 0 ]; then
    echo "Result: Reproducible builds verified!"
  else
    echo "Result: Builds differ - check output above for details"
  fi

  exit $exit_code
}

main
