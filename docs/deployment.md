# Deployment Guide

## Prerequisites

- Go 1.25.1 or higher
- Docker with BuildKit support
- Google Cloud Platform account (for production deployment)

## Building

### Reproducible Docker Build

The project produces reproducible Docker images — given the same source code, builds produce bit-for-bit identical image layers regardless of when or where they are built. This is essential for TEE attestation, as the image digest must be independently verifiable.

Reproducibility is achieved through:

- `SOURCE_DATE_EPOCH` set to the commit timestamp, clamping all file timestamps
- Go binary built with `-trimpath -ldflags="-buildid= -s -w"` to strip non-deterministic metadata
- Base image digests pinned by SHA256 in the Dockerfile
- BuildKit's `rewrite-timestamp=true` exporter option to normalize layer timestamps
- Explicit `find + touch` in the build stage to normalize all source file timestamps before `COPY`

#### Builder Setup (One-Time)

The default Docker builder does not properly support `rewrite-timestamp`. A BuildKit builder using the `docker-container` driver is required:

```sh
docker buildx create \
  --driver=docker-container \
  --name=moby-buildkit \
  --driver-opt image=moby/buildkit \
  --bootstrap
```

#### Build from Tag

```sh
git clone https://github.com/flare-foundation/tee-node.git
cd tee-node

TAG=$(git describe --tags --abbrev=0)
git checkout "$TAG"

docker buildx build \
  --builder moby-buildkit \
  --platform linux/amd64 \
  --no-cache \
  --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  --output "type=docker,rewrite-timestamp=true" \
  -t local/tee-node:verify --load -f Dockerfile .
```

#### Verify Against Registry

```sh
docker pull --platform linux/amd64 ghcr.io/flare-foundation/tee-node:"$TAG"

docker inspect --format='{{.Id}}' local/tee-node:verify
docker inspect --format='{{.Id}}' ghcr.io/flare-foundation/tee-node:"$TAG"
```

Both IDs must be identical. If they differ, the image in the registry does not match the source at that tag.

### Dockerfile

The Dockerfile uses `golang:1.25.1-alpine` (pinned by SHA256) as the build stage and `alpine:3.23.3` (pinned by SHA256) as the runtime. It produces a single statically-linked Go binary (`server`) and includes CA certificates and the Google Confidential Space root certificate.

The image exposes port 5500 and sets `MODE=0` (production) by default. Allowed environment variable overrides are declared via the `tee.launch_policy.allow_env_override` label: `LOG_LEVEL`, `PROXY_URL`, `INITIAL_OWNER`, `EXTENSION_ID`.

### Transfer Image to Server

```bash
docker save local/tee-node | gzip | ssh user@server 'docker load'
```

## GCP Confidential Space

### Setup

1. Build a reproducible Docker image
2. Push to Google Artifact Registry
3. Create a Confidential VM instance with the image
4. The TEE node automatically connects to the Confidential Space attestation service via Unix socket

### Attestation

In production mode (`MODE=0`), the TEE requests attestation tokens from:

```
/run/container_launcher/teeserver.sock -> POST /v1/token
```

The token contains claims about:

- Hardware model (used as platform identifier)
- Container image digest (used as code hash)

These are included in the TEE's registration attestation response. The code hash corresponds to the reproducible image digest, allowing independent parties to verify that the TEE is running the expected code.

## Operating Modes

The TEE node supports two operating modes determined by which router is used at startup:

- **Base mode (Extension 0)**: `cmd/main.go` uses `NewPMWRouter`. All Flare protocol operations (wallet management, XRP signing, VRF, FDC) are built-in. No extension server needed.

- **Extension mode**: Uses `NewForwardRouter`. Base wallet management and attestation are built-in; all other actions are forwarded to a user-implemented extension server on port 8889. Set `EXTENSION_ID` to identify the extension in attestation responses.

See [Architecture](architecture.md) and [Extensions](extensions.md) for details.

## Environment Configuration

Create a `.env` file based on `.env.template`:

```bash
MODE=0                    # 0=production, 1=local/test
PROXY_URL=http://proxy:8080
INITIAL_OWNER=0x...       # Optional: 20-byte Ethereum address
EXTENSION_ID=0x...        # Optional: 32-byte hash (relevant for extension mode)
LOG_LEVEL=INFO            # FATAL, ERROR, WARN, INFO, DEBUG
```

The proxy URL can also be set at runtime via `POST /proxy` on port 5500.

## Running

```bash
# Local development
go run cmd/main.go

# Docker
docker run -p 5500:5500 -p 8888:8888 --env-file .env local/tee-node

# Verify the node is running
curl -v -X POST http://localhost:5500/proxy \
  -H "Content-Type: application/json" \
  -d '{"url":"http://your-proxy:8080"}'
```
