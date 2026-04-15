# Flare Data Connector (FDC) Proving

## Overview

The FDC processor validates attestation responses from data providers and cosigners, then produces a TEE-signed proof that can be used for on-chain finalization. For the FDC client implementation, see [fdc-client](https://github.com/flare-foundation/fdc-client).

## Route

`F_FDC2` / `PROVE`

## Request Structure

The FDC request is ABI-encoded in the instruction's `OriginalMessage` field and contains:

- **ResponseHeader** - Attestation type, source ID, threshold BIPS, cosigner data, timestamp
- **RequestBody** - The original attestation request
- **ResponseBody** - The attestation response (in `AdditionalFixedMessage`)

## Threshold Validation

FDC has custom threshold logic:

- If `ThresholdBIPS == 0`: defaults to 50% of total voting weight
- Minimum threshold: 4000 BIPS (40%)
- Maximum threshold: < 10000 BIPS (100%)
- If DP threshold < 50%, then cosigner threshold must be > 50% (one-above-50 rule)

## Processing Flow (Threshold Phase)

1. Decode FDC request from original message
2. Compute message hash: `Keccak256(ResponseBody || Cosigners || Timestamp)`
3. For each signer:
    - Verify signature against message hash
    - Classify as data provider or cosigner
    - Data provider signatures: create indexed signature (sorted by voter index)
    - Cosigner signatures: collected separately
4. Prepare finalization TX input (ABI-encoded relay call with signing policy, message, and indexed signatures)
5. Sign message hash with TEE private key

## Response

```json
{
  "responseHeader": "<ABI-encoded header>",
  "requestBody": "<original request>",
  "responseBody": "<attestation response>",
  "teeSignature": "<TEE signature over message hash>",
  "dataProviderSignatures": "<ABI-encoded indexed DP signatures>",
  "cosignerSignatures": ["<raw sig 1>", "<raw sig 2>", ...]
}
```

## End Phase

Generates rewarding data with vote hash and TEE signature. No state changes.
