#!/bin/bash
set -euo pipefail

export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
echo "Setting SDE to $SOURCE_DATE_EPOCH"

# Build image 1
podman build \
  -f Dockerfile \
  --no-cache \
  --timestamp "$SOURCE_DATE_EPOCH" \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -t tee-node-podman1 \
  .

# Build image 2 (fresh, same inputs)
podman build \
  -f Dockerfile \
  --no-cache \
  --timestamp "$SOURCE_DATE_EPOCH" \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -t tee-node-podman2 \
  .

# Compare images
echo ""
echo "=== Checking Image Reproducibility ==="

# Get image digests using inspect
DIGEST1=$(podman inspect localhost/tee-node-podman1:latest --format '{{.Digest}}')
DIGEST2=$(podman inspect localhost/tee-node-podman2:latest --format '{{.Digest}}')

echo "Image 1 Digest: $DIGEST1"
echo "Image 2 Digest: $DIGEST2"

echo ""
podman images --digests | grep -E "REPOSITORY|tee-node-podman"

# Export to tar archives for diffoci comparison
echo ""
echo "=== Exporting images for diffoci ==="
rm -f /tmp/tee-node-podman1.tar /tmp/tee-node-podman2.tar
podman save localhost/tee-node-podman1:latest -o /tmp/tee-node-podman1.tar
podman save localhost/tee-node-podman2:latest -o /tmp/tee-node-podman2.tar

# Final
echo ""
if [ "$DIGEST1" = "$DIGEST2" ]; then
    echo "✓ SUCCESS: Builds are bit-for-bit reproducible!"
    echo "  - Identical digests: $DIGEST1"
    exit 0
else
    echo "✗ FAILURE: Builds are NOT identical"
    
    echo "=== Running diffoci ==="
    if command -v diffoci >/dev/null 2>&1; then
        # Load images into diffoci
        echo "Loading images into diffoci..."
        diffoci load --input /tmp/tee-node-podman1.tar > /dev/null 2>&1
        /home/cen/go/bin/diffoci load --input /tmp/tee-node-podman2.tar > /dev/null 2>&1

        echo "Semantic diff:"
        /home/cen/go/bin/diffoci diff --semantic localhost/tee-node-podman1:latest localhost/tee-node-podman2:latest 2>&1 || echo "  Differences found"

        echo ""
        echo "Full diff:"
        /home/cen/go/bin/diffoci diff localhost/tee-node-podman1:latest localhost/tee-node-podman2:latest 2>&1 || echo "  Differences found"
    else
        echo "diffoci not found, you need to install it"
    fi

    exit 1
fi
