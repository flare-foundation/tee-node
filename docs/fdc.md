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

## Message Hash

The proof is bound to a domain-separated, chain-bound preimage (see [Cryptography](cryptography.md#domain-separated-signed-payloads)):

```
messageHash = signing.Payload{FDC2, chainID, keccak256(abi.encode(
    keccak256(abi.encode(header)),
    keccak256(abi.encode(requestBody)),
    keccak256(abi.encode(responseBody)),
))}.Hash()
```

`chainID` comes from the node's configured `CHAIN_ID`. Two recovery preimages are derived from `messageHash`:

- **TEE signature** recovers against `messageHash` directly (matching `Verification._verifyTeeSignature`).
- **Data-provider and cosigner signatures** recover against the *relay-prefixed* hash `keccak256(0x01_00000000_00 || messageHash)` — the 6-byte Relay Mode-2 header (`protocolId=1`, `votingRoundId=0`, `isSecureRandom=0`) that the on-chain Relay/Verification prepend.

## Processing Flow (Threshold Phase)

1. Decode FDC request from original message
2. Compute `messageHash` (above) and the relay-prefixed hash
3. For each signer:
    - Verify signature against the relay-prefixed hash
    - Classify as data provider or cosigner
    - Data provider signatures: create indexed signature (sorted by voter index)
    - Cosigner signatures: collected separately
4. Prepare finalization TX input (relay function selector, signing policy, the 6-byte direct-signing prefix, `messageHash`, and ABI-encoded indexed signatures)
5. Sign `messageHash` with the TEE private key

## Response

```json
{
  "responseHeader": "<ABI-encoded header>",
  "requestBody": "<original request>",
  "responseBody": "<attestation response>",
  "teeSignature": "<TEE signature over messageHash>",
  "cosignerSignatures": ["<raw sig 1>", "<raw sig 2>", ...],
  "dataProviderSignatures": "<ABI-encoded indexed DP signatures>"
}
```

## End Phase

Generates rewarding data with the vote hash and a TEE signature. The vote-hash signature is domain-separated: the TEE signs `signing.Payload{TEE_VOTE_HASH, chainID, voteHash}.Hash()` (see [Cryptography](cryptography.md#domain-separated-signed-payloads)), so the on-chain/proxy consumer must recover against the same preimage. No state changes.
