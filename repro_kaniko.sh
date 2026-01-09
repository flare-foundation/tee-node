#!/bin/bash
set -euo pipefail

# Before running this script, make sure to docker login registry.gitlab.com (use a read_registry PAT and any username to auth)

# To make the tar hash equality fail, rename to tee-node-kaniko2:latest and tee-node-kaniko3:latest, it will then load it as docker image and print out diffoci, showing only the name diff
DEST1="tee-node-kaniko1:latest"
DEST2="tee-node-kaniko1:latest"

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
echo "Setting SDE to $SOURCE_DATE_EPOCH"

# Build image 1 with Kaniko
echo "Building image 1 with Kaniko..."
docker run --rm \
  -v "$(pwd):/workspace" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  registry.gitlab.com/gitlab-ci-utils/container-images/kaniko:v1.25.5-debug@sha256:dc80edf7d86416ce435c80341008ba5e7c26fef6e0769ef3a18aafdbbc3a2771 \
  --dockerfile=/workspace/Dockerfile \
  --context=dir:///workspace \
  --no-push \
  --tarPath=/workspace/tee-node-kaniko1.tar \
  --destination=$DEST1 \
  --reproducible \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"

HASH1=$(sha256sum tee-node-kaniko1.tar | awk '{print $1}')

# Build image 2 with Kaniko
echo "Building image 2 with Kaniko..."
docker run --rm \
  -v "$(pwd):/workspace" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  registry.gitlab.com/gitlab-ci-utils/container-images/kaniko:v1.25.5-debug@sha256:dc80edf7d86416ce435c80341008ba5e7c26fef6e0769ef3a18aafdbbc3a2771 \
  --dockerfile=/workspace/Dockerfile \
  --context=dir:///workspace \
  --no-push \
  --tarPath=/workspace/tee-node-kaniko2.tar \
  --destination=$DEST2 \
  --reproducible \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"

HASH2=$(sha256sum tee-node-kaniko2.tar | awk '{print $1}')

echo "Hash 1: $HASH1"
echo "Hash 2: $HASH2"

if [ "$HASH1" == "$HASH2" ]; then
    echo "✓ SUCCESS: Tar hashes are identical, image is reproducible"
    exit 0
else
    echo "✗ FAILURE: Builds are NOT identical"
    echo "=== Running diffoci ==="

    if command -v diffoci >/dev/null 2>&1; then
        # Load images into diffoci
        echo "Loading images into diffoci..."
        diffoci load --input tee-node-kaniko1.tar > /dev/null 2>&1
        diffoci load --input tee-node-kaniko2.tar > /dev/null 2>&1

        echo "Semantic diff:"
        diffoci diff --semantic $DEST1 $DEST2 2>&1 || echo "  Differences found"

        echo ""
        echo "Full diff:"
        diffoci diff $DEST1 $DEST2 2>&1 || echo "  Differences found"
    else
        echo "diffoci not found, you need to install it"
    fi

    exit 1
fi
