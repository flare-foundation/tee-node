# TEE Attestation

## Overview

TEE attestation allows the TEE node to prove its identity and integrity to external verifiers. It produces a signed attestation response containing the TEE's public key, policy state, and a Google Cloud Confidential Space attestation token.

## Route

`F_REG` / `TEE_ATTESTATION` (instruction)

## Attestation Flow

### Request

The attestation request contains a challenge (arbitrary bytes) that is included in the attestation response to prevent replay attacks. The TEE ID in the request must match the node's actual TEE ID.

### Threshold Phase

1. Validate request: TEE ID match, non-empty challenge
2. Construct `TeeInfo`:
    - TEE public key
    - Challenge from request
    - Initial owner address
    - Extension ID
    - Initial and active signing policy IDs and hashes
    - Node state
    - Current timestamp
3. Hash `TeeInfo`
4. Request Google Cloud attestation token for the hash
5. Extract claims from attestation token:
    - **Code hash**: derived from container image digest (`sha256:...`)
    - **Platform**: derived from hardware model string
6. Construct `MachineData`:
    - Extension ID, initial owner
    - Code hash, platform
    - TEE public key
7. Sign `MachineData` hash with TEE private key
8. Return `TeeInfoResponse` containing TeeInfo, MachineData, MachineData signature, and attestation token

### End Phase

Returns nil (acknowledgment only).

## Google Cloud Attestation

### Production Mode (MODE=0)

The TEE communicates with the Google Cloud attestation service via a Unix socket at `/run/container_launcher/teeserver.sock`. It sends a POST request to `/v1/token` with:

- `audience`: hex-encoded hash of the TeeInfo
- `token_type`: `PKI` or `OIDC`
- `nonces`: array containing the hex-encoded audience

The returned JWT token contains claims about the hardware model and container image, which are used to derive the code hash and platform.

### Test/Local Mode (MODE!=0)

Returns `"magic_pass"` as the attestation token. Code hash and platform are set to test defaults:

- Platform: `Hash("TEST_PLATFORM")`
- Code hash: `0x194844cf417dde867073e5ab7199fa4d21fd82b5dbe2bdea8b3d7fc18d10fdc2`

## Attestation Claims

The JWT token from Google Cloud contains:

```json
{
    "hwmodel": "<hardware model string>",
    "submods": {
        "container": {
            "image_digest": "sha256:<hex digest>"
        }
    }
}
```

- `hwmodel` is hashed to produce the platform identifier
- `image_digest` prefix `sha256:` is stripped, remainder decoded as the code hash

## Reproducible Builds

For attestation to be meaningful, the Docker image must be reproducibly built so that independent parties can verify the code hash. See [Deployment](deployment.md) for build instructions.
