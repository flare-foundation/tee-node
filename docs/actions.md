# Action Processing

## Action Lifecycle

```
Proxy Queue -> Fetch -> Validate -> Route -> Process -> Sign -> Post Response
```

### 1. Fetch

The TEE polls each queue endpoint (`POST /queue/{main|direct|backup}`) with a timeout controlled by `ProxyTimeout` (default 2 s). The response size is bounded by `MaxFetchResponseSize` (default 10 MB) via `io.LimitReader`.

### 2. Validate (CheckAndAdapt)

Before routing, every action is validated:

- If `AdditionalVariableMessages` is empty, it is initialized to match the number of signatures
- Array alignment is enforced: `len(Timestamps) == len(AdditionalVariableMessages) == len(Signatures)`
- Total variable message size must not exceed `MaxVariableMessageSize` (default 1 MB)

### 3. Route

The OpType and OpCommand are extracted from the action message (first two JSON fields). The router looks up a registered processor for the `(OpType, OpCommand)` pair. If none exists, the behavior depends on the operating mode: in base mode the action is rejected, while in extension mode it is forwarded to the extension service via the default direct or instruction processor.

### 4. Process

#### Direct Actions

Direct actions are parsed and passed directly to their handler. No signing policy validation is required. Message size is bounded by `MaxActionSize` (default 10 MB).

#### Instruction Actions

Instructions go through preprocessing before reaching the handler:

1. **Parse** - Message decoded as `instruction.DataFixed`, bounded by `MaxInstructionSize` (default 100 KB)
2. **Policy lookup** - Signing policy for the instruction's `RewardEpochID`
3. **Policy validity** - Referenced policy must not be more than one epoch behind active
4. **Instruction validation**:
    - TEE ID must match
    - Instruction ID must match Action ID
    - OpType/OpCommand must be a valid pair
    - Fixed and variable message sizes checked against per-command constraints
5. **Signature extraction** - Each signature recovered to a signer address; double signing rejected
6. **Threshold checks**:
    - Cosigner threshold met
    - Data provider weight threshold met (>50% for most operations, 0 for restore)
    - All signers must be either cosigners or registered data providers

### 5. Sign Result

The action result's `Data` field is hashed with Keccak256 and signed with the TEE's private key. The signed response is posted to `{proxyURL}/result`.

### 6. Error Handling

- Validation failures return status `0` with an error log
- Processing errors return status `0`
- Successful Threshold returns status `1` (immediate) or `2` (deferred)
- Successful End returns status `1` with rewarding data
- Panics in queue processing are recovered; the queue continues

## Per-Command Size Constraints

| OpCommand              | Original Message | Additional Fixed | Variable (each)  |
| ---------------------- | ---------------- | ---------------- | ---------------- |
| KeyDataProviderRestore | 50 KB            | 100 KB           | 1 MB             |
| Pay, Reissue           | 50 KB            | 100 KB           | 0 (none allowed) |
| TEEAttestation         | 50 KB            | 100 KB           | 0                |
| KeyGenerate, KeyDelete | 50 KB            | 100 KB           | 0                |
| Prove (FDC)            | 50 KB            | 100 KB           | 50 KB            |
| Default                | 50 KB            | 100 KB           | 50 KB            |

## Rewarding Data

At the End phase, the TEE produces rewarding data containing:

- A vote hash computed over all signatures, variable messages, and timestamps (must be in increasing order)
- The instruction hash
- The TEE's signature over the vote hash
- All original signatures and variable message hashes

This data enables on-chain verification and reward distribution.
