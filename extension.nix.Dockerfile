FROM nixos/nix:2.33.1 AS builder

# Enable sandboxing. Must be run with --privileged.
RUN cat > /etc/nix/nix.conf << 'EOF'
build-users-group = nixbld
sandbox = true
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
experimental-features = nix-command flakes
EOF

# Create the entrypoint script.
RUN cat > /entrypoint.sh << 'EOF'
#!/bin/sh
set -e

git clone -b erik/deploy-extension https://node-build:${DEPLOY_TOKEN}@gitlab.com/flarenetwork/tee/tee-node.git /src
cd /src

echo "Building..."
nix build .#with-extension
echo "Build finished. Checking the built binary's hash..."

H=$(sha256sum result/bin/extension | cut -d' ' -f1)    
if [ "$H" != "$HASH" ]; then
    echo "Error: unexpected hash."
    echo "Expected: $HASH"
    echo "Actual:   $H"
else
echo "Hash is correct: $H"
fi

exec /bin/sh
EOF

RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]