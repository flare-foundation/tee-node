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
- **Nonce ordering**: Delete and restore operations require strictly increasing nonces; the machine-path list requires a strictly increasing nonce
- **Policy freshness**: Instructions can only reference recent policies (within 1 epoch)
- **Domain separation**: *Every* TEE signature — key-existence proofs, machine registration, FDC2 proofs, action results, end-phase vote hashes, and backup signatures — is taken over a payload-type-tagged, chain-ID-bound preimage, so a signature for one purpose cannot be replayed for another (see [Cryptography](cryptography.md#domain-separated-signed-payloads)). The XRP transaction and VRF proof signatures are the deliberate exceptions (external bit-exact formats).
- **Governance signatures**: `SET_MACHINE_PATH_LIST` requires a threshold of distinct governance-signer signatures
- **Machine-path authorization**: Direct key transfers must be authorized by the current machine-path list for the (source, destination) TEE pair

> **Chain-ID dependency**: because action-result, vote-hash, and backup signing all bind the chain ID, `CHAIN_ID` must be configured (via env or the config server) before the node can sign — signing fails closed otherwise. The matching chain ID must also be wired into the on-chain, proxy, and data-provider verifiers, which recover against the same domain-separated preimage. Deploy these in lockstep.

### Config Server

The config server (port `CONFIG_PORT`) exposes endpoints to set the proxy URL, initial owner, extension ID, chain ID, and the governance signer set. It is assumed that network access to this port is restricted to the node owner. No authentication is performed on these endpoints; security relies on network-level access control.

All setters except `/proxy` are **one-shot** (a second call is rejected), and each value can instead be fixed at deploy time via its environment variable. The env vars are read during node initialization, *before* the config server starts, so providing them at deploy time closes any window in which a config-port reacher could set the value first. This matters most for `/governance`: the governance signer set is the root of direct-key-transfer authorization, and it is committed into the node's attested `GovernanceHash` (registered via `TEE_MACHINE_REGISTER`), so a value set here is observable on-chain rather than silent. Setting governance does not by itself enable key exfiltration — direct backup/restore are independently gated by the data-provider quorum (see [Governance & Machine-Path Authorization](#governance--machine-path-authorization)).

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

## Governance & Machine-Path Authorization

Direct TEE-to-TEE key transfer (`KEY_DIRECT_BACKUP` / `KEY_DIRECT_RESTORE`) is constrained by a governance-approved **machine-path list** that enumerates which `(source, destination)` TEE pairs may move keys.

### Governance Signatures

The list is installed by `F_GOVERNANCE` / `SET_MACHINE_PATH_LIST`. The handler:

- Recovers each provided signature over `signing.Payload{TEE_MACHINE_PATH_LIST, chainID, keccak256(abi.encode(extensionID, nonce, paths))}.Hash()`
- Requires each recovered address to be in the node's governance signer set, and counts only **distinct** signers
- Requires at least `threshold` distinct signers
- Requires the list nonce to be strictly greater than the currently stored nonce

The governance set is itself one-shot and committed into the attested `GovernanceHash`; the threshold must be `>= 1` and `<=` the number of signers, and no signer may be the zero address.

### Layered Authorization for Key Transfer

The machine-path list is **not** the only gate on direct backup/restore. Because both commands are instructions, they first pass the standard pipeline checks — including a `>50%` data-provider voting-weight quorum and cosigner thresholds. The machine-path list *narrows* which TEE pairs may participate on top of that quorum; it cannot by itself authorize a transfer. Consequently, an actor who controls only governance (and thus the machine-path list) on a node still cannot cause a key to move without a quorum-signed instruction.

### Integrity & Confidentiality of Direct Backup

- The private key travels only as ECIES ciphertext under the destination TEE's public key.
- The quorum-signed instruction `BackupId` is cross-checked (by canonical ABI encoding) against the source-TEE-signed payload, and the decrypted key must derive `BackupID.PublicKey`.
- The envelope signature must verify against the declared `sourceTeeId`, which must equal `BackupId.teeId`.
- A `{epoch, epoch+1}` reward-epoch window and the per-key nonce bound replay.

See [Backup & Restore](backup-restore.md#direct-backup--restore-tee-to-tee) for the full flow.

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
