# Security Model

## Trust Boundaries

### What the TEE Trusts

- **Its own key material**: Generated internally, never exported
- **Google Cloud Confidential Space**: Hardware-level isolation and attestation
- **Cryptographic primitives**: secp256k1, Keccak256, SHA512-Half, ECIES, Shamir
- **Extension server**: In extension mode, the TEE node and the user-implemented extension are expected to run inside the same trusted TEE instance. Communication between them occurs over localhost and is protected by the TEE's hardware isolation — no external entity can observe or tamper with this traffic. The extension server API (sign, decrypt) does not perform authentication, as security relies on the shared TEE boundary.

### What the TEE Validates

- **Instruction signatures**: Every signer is cryptographically recovered from their signature
- **Signing policy thresholds**: Cosigner and data provider weight thresholds checked
- **TEE ID matching**: Instructions must target this specific TEE
- **Instruction/Action ID consistency**: Prevents cross-action replay
- **Message sizes**: All inputs bounded by constants
- **Nonce ordering**: Delete and restore operations require strictly increasing nonces
- **Policy freshness**: Instructions can only reference recent policies (within 1 epoch)

### Config Server

The config server (port `CONFIG_PORT`) exposes endpoints to set the proxy URL, initial owner, and extension ID. It is assumed that network access to this port is restricted to the node owner. No authentication is performed on these endpoints; security relies on network-level access control.

### What the Proxy Controls

The proxy is a transport layer. It can always **block or censor** actions, but it **cannot create** an action that the TEE accepts without valid signatures from data providers and/or cosigners. Specifically, the proxy has the ability to:

- Deliver or withhold actions, including selectively withholding End phases
- Reorder action delivery
- Corrupt variable messages in transit, rendering encrypted splits unable to be decrypted
- Time delivery to specific policy epochs

The proxy **cannot**:

- Forge instruction signatures
- Bypass threshold requirements
- Extract private keys
- Modify signed instruction content, as signature verification would fail

### Data Provider Majority

A majority of data providers (by voting weight) can construct and sign arbitrary instructions that the TEE will accept. This is by design — the signing policy threshold mechanism assumes honest majority among data providers.

For operations where data provider majority alone is not sufficient security (e.g., XRP payments, wallet restore), **cosigners** are added as an additional authorization layer. Cosigner thresholds are checked independently from data provider thresholds, requiring both to be met before the TEE executes the operation.

## Replay Protection

### Instruction-Level

- Each instruction has a unique `InstructionID` that must match the `ActionID`
- Double signing by the same address is rejected
- Timestamps must be monotonically increasing within an instruction

### Wallet-Level

- Delete and restore operations require a nonce greater than the stored nonce
- Permanent records survive wallet deletion, preventing nonce reuse
- Permanent record count is bounded (1,000,000) to prevent memory exhaustion

## Resource Exhaustion Protections

### Memory

All limits below are controlled by constants in `internal/settings/settings.go`. See [Configuration](configuration.md) for default values.

| Resource                | Setting                     | Mitigation                                 |
| ----------------------- | --------------------------- | ------------------------------------------ |
| Active wallets          | `MaxWallets`                | `Store()` rejects beyond limit             |
| Permanent records       | `MaxPermanentWalletsStatus` | `Store()` rejects new records beyond limit |
| Sign goroutines         | `MaxSignGoroutines`         | Atomic counter checked before spawn        |
| Fee schedule entries    | `MaxFeeEntries`             | Rejected before signing or spawning        |
| Fee schedule delay      | `MaxFeeScheduleTime`        | Rejected before signing or spawning        |
| Instruction message     | `MaxInstructionSize`        | Rejected at parse time                     |
| Action message          | `MaxActionSize`             | Rejected at parse time                     |
| Variable messages total | `MaxVariableMessageSize`    | Rejected at validation time                |
| Fetch response          | `MaxFetchResponseSize`      | `io.LimitReader` on HTTP response          |

### CPU

- Queue processing sleeps for `QueuedActionsSleepTime` (default 100 ms) between iterations when idle
- Proxy HTTP timeout is controlled by `ProxyTimeout` (default 2 s)
- Shamir interpolation is O(n^2) in threshold, bounded by share count
