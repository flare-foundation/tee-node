# Flare TEE server node

Flare TEE server node is a secure gRPC server implementation running inside a Trusted Execution Environment (TEE). It provides network managed wallets.

### Features

-   Secure policy management within TEE
-   Policy signature verification and validation
-   Remote attestation with Google Cloud verification
-   gRPC interface for all operations

### Requirements

-   Go 1.23 or higher
-   Protocol Buffers compiler (buff package)
-   Google Cloud Platform account (for attestation verification) (gcp confidential space)

## Local Setup and Installation

1. Clone the repository:

```bash
git clone https://gitlab.com/flarenetwork/tee/tee-node
cd tee-node
```

2. Install dependencies:

```bash
go mod download
```

3. Build the server:

```bash
go build -o tee-node cmd/server/main.go
```

## Usage

1. Start the server:

```bash
./tee-node
```

2. The server will be available at `localhost:50051` (default) or the configured address

## Deploying the server in Google TEE

This guide explains how to deploy the Flare TEE server node on Google Cloud Platform (GCP) using Confidential Computing.

#### Prerequisites

-   [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) installed and configured
-   Appropriate GCP project permissions (should be done by default in flare-sandbox)
-   Service account with necessary permissions (should be done by default in flare-sandbox)

#### Hardware Options

The server supports two types of Confidential Computing hardware:

-   `SEV`: AMD SEV-SNP technology
-   `TDX`: Intel TDX technology

### Build Docker container

On Intel/AMD arm64 based machines:
```bash
docker build -t us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest --no-cache
```

On Apple silicon (M1, M2, M3 processors):
```bash
docker buildx create --use
docker buildx build --platform linux/amd64 -t us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest . --no-cache --load
```

Set up Docker authetication for artifact registry
```bash
gcloud auth configure-docker us-docker.pkg.dev
```

Add image to Artifact Registry
```bash
docker push us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest
```

### Deployment Steps

#### 0. Delete the previous instance (\*if you had one running)

```bash
gcloud compute instances delete <INSTANCE-NAME> --zone us-central1-a
```

#### 1. Create Confidential Computing Instance

```bash
gcloud compute instances create <INSTANCE-NAME> \
    --confidential-compute-type=<COMPUTE-TYPE> \
    --shielded-secure-boot \
    --scopes=cloud-platform \
    --zone=us-central1-a \
    --maintenance-policy=TERMINATE \
    --image-project=confidential-space-images \
    --image-family=<IMAGE-FAMILY> \
    --service-account=confidential-sa@flare-network-sandbox.iam.gserviceaccount.com \
    --tags=rpc-server \
    --metadata="^~^tee-image-reference=us-docker.pkg.dev/flare-network-sandbox/flare-tee/tee-node:latest"
```

#### Parameter Explanation

| Parameter         | Description                                         | Example Value                                                        |
| ----------------- | --------------------------------------------------- | -------------------------------------------------------------------- |
| `<INSTANCE-NAME>` | Unique instance identifier (preferably tied to you) | `jure-test-tee1`                                                     |
| `<COMPUTE-TYPE>`  | Hardware type for Confidential Computing            | `SEV` or `TDX`                                                       |
| `<IMAGE-FAMILY>`  | must match what you chose for COMPUTE-TYPE          | `confidential-space-debug` or `confidential-space-debug-preview-tdx` |

#### Important Flags

-   `--confidential-compute-type`: Specifies the TEE hardware type
-   `--shielded-secure-boot`: Enables secure boot for additional security
-   `--scopes=cloud-platform`: Grants necessary GCP API access
-   `--service-account`: Specifies the service account for the instance
-   `--tags`: Used for firewall rules targeting
-   `--metadata`: Specifies the container image to deploy

#### 2. Configure Firewall Rules

The following command creates a firewall rule to allow gRPC traffic on port 50051. This needs to be executed only once per project.

```bash
gcloud compute firewall-rules create allow-port-8545 \
    --network=default \
    --priority=1000 \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=tcp:8545 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=<CUSTOM_TAG>
```

⚠️ **Security Note**: The current firewall rule allows access from any IP (`0.0.0.0/0`). For production environments, we would restrict this to only specific IPs (data provider or other TEEs).

### Verification

To verify your deployment:

1. Check instance status:

```bash
gcloud compute instances describe <INSTANCE-NAME> --zone=us-central1-a
```

2. View instance logs:

```bash
gcloud compute instances get-serial-port-output <INSTANCE-NAME> --zone=us-central1-a
```

## Project Structure

### Proto Definitions

Location: `api/proto/`

Contains the gRPC service definitions and message types for the signing service. This schema defines the contract between the client and server.

### Proto auto-generated go code

Location: `gen/go/`

Contains the gRPC service interface in go.

To generate it run (with installed `buf`, see [here](https://buf.build/docs/installation/#__tabbed_1_1))

```bash
buf generate
```

### Service Implementation

Location: `internal/service`

Implements the core gRPC service methods:

#### InitializePolicy TODO

Validates and activates the initial policy configuration.

**Function:**

```go
InitializePolicy(ctx context.Context, req *api.InitializePolicyRequest) (*api.InitializePolicyResponse, error)
```

**Purpose:**

-   Takes initial policy and change history
-   Verifies the entire policy chain
-   Establishes the active policy state

#### SignNewPolicy

Handles signature verification and policy updates.

**Function:**

```go
SignNewPolicy(ctx context.Context, req *api.SignNewPolicyRequest) (*api.SignNewPolicyResponse, error)
```

**Purpose:**

-   Verifies individual signatures for new policies
-   Validates signature against current policy
-   Updates policy when weight threshold is reached
-   Can be used for general message signing

#### GetAttestationToken

Provides TEE attestation verification.

**Function:**

```go
GetAttestationToken(ctx context.Context, req *api.GetAttestationTokenRequest) (*api.GetAttestationTokenResponse, error)
```

**Purpose:**

-   Generates attestation quote from TEE
-   Communicates with Google's verification server
-   Returns JWT token proving valid attestation

<!-- ## Test

Once everything is deployed you can modify the GCP_INSTANCE_IP variable in the cmd/client/main.go file and run

```bash
go run cmd/client/main.go cmd/client/utils.go
``` -->

<!-- ## Next Steps

-   Implement hardware attestation API
-   Understand What the attestation is attesting? :) -->

### Run tests

Run all tests with
```
go test ./...
```
