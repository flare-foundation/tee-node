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

# Flare TEE Server Node

A secure server running inside a Trusted Execution Environment (TEE) on GCP Confidential Space. It provides protocol managed wallets and serves as a base for extensions.

The TEE node runs behind a proxy service — external clients communicate exclusively through the proxy.

[![API Reference](https://pkg.go.dev/badge/github.com/flare-foundation/tee-node)](https://pkg.go.dev/github.com/flare-foundation/tee-node?tab=doc)

## Documentation

See [docs/](docs/README.md) for the full documentation, including architecture, configuration, security model, and extension integration.

## Reproducible Builds

Docker images are built reproducibly so that the image digest can be independently verified for TEE attestation. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for build and verification instructions.

## Requirements

- Go 1.25.1 or higher
- Docker with BuildKit support
- GCP account (for production deployment)

## Quick Start

```sh
go run cmd/main.go
```

## Tests

```sh
go test ./...
```
