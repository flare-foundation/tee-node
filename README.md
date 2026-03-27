<div align="center">
  <a href="https://flare.network/" target="blank">
    <img src="https://content.flare.network/Flare-2.svg" width="300" alt="Flare Logo" />
  </a>
  <br />
  <a href="CONTRIBUTING.md">Contributing</a>
  ·
  <a href="SECURITY.md">Security</a>
  ·
  <a href="CHANGELOG.md">Changelog</a>
</div>

# Flare TEE server node

Flare TEE server node is a secure server implementation running inside a Trusted Execution Environment (TEE).
It provides protocol managed wallets as well as a base for extensions.

The TEE node is designed to run behind a proxy service. Only the proxy should have direct network access to the TEE node — external clients communicate exclusively through the proxy.

[![API Reference](https://pkg.go.dev/badge/github.com/flare-foundation/tee-node)](https://pkg.go.dev/github.com/flare-foundation/tee-node?tab=doc)

### Requirements

- Go 1.25.1 or higher
- Google Cloud Platform account (for attestation verification) (GCP Confidential Space)

### Deployment

For running in GCP Confidential Space, a Docker image must be built using a reproducible build process and deployed to the confidential VM. Reproducible builds ensure that the image digest can be independently verified, which is essential for TEE attestation.

### Reproducible Docker image build

The project uses [Nix](https://nixos.org/) to produce deterministic Docker images. All build inputs — Go toolchain, dependencies, and configuration — are pinned via `flake.nix`, `flake.lock`, and `gomod2nix.toml`, ensuring that the same source always produces a byte-identical image.

**Building with Nix via Docker:**

```
docker run --rm -v $(pwd):/src -w /src nixos/nix bash -c \
  "git config --global --add safe.directory /src && nix build .#docker --extra-experimental-features 'nix-command flakes' && cp result /src/tee-node-image.tar.gz"
docker load < tee-node-image.tar.gz
```

### Run tests

Run all tests with

```
go test ./...
```
