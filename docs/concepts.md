# Concepts & Glossary

## Core Entities

### TEE Node

A server running inside a Trusted Execution Environment (GCP Confidential Space). It generates a fresh ECDSA key pair on each boot, which serves as its identity (`teeID`). The private key never leaves the TEE.

### Proxy

An external service that bridges external clients and the TEE node. The TEE polls the proxy for actions and posts results back. The proxy manages action queues. See [tee-proxy](https://github.com/flare-foundation/tee-proxy).

### Relay Client

Monitors the on-chain `TeeExtensionRegistry` contract for `TeeInstructionsSent` events and forwards instructions to the TEE proxy. Operates in provider mode (for signing policy participants) or cosigner mode (for external cosigners). See [tee-relay-client](https://github.com/flare-foundation/tee-relay-client).

### Wallet

A key pair managed by the TEE. Each wallet is identified by a `KeyIDPair` (WalletID + KeyID). Wallets store a private key, signing algorithm, admin configuration, cosigner list, and settings.

### Extension

The TEE node supports two operating modes. In **base mode** (Extension 0, `NewPMWRouter`), all operations — wallet management, XRP signing, VRF, FDC — are handled by built-in processors. In **extension mode** (`NewForwardRouter`), the TEE provides base wallet management and attestation, but delegates unrecognized actions to a user-implemented external **extension server**. The extension server can call back to the TEE's sign/decrypt API to use managed keys. Each extension is identified by an `ExtensionID` included in attestation responses. See [Extensions](extensions.md) for details.

### Chain ID

The EVM chain ID the node is bound to (`CHAIN_ID`). It is mixed into every domain-separated signed payload, so a signature the TEE produces is valid only for one network. It is set once (env var or config server) and is required before the node can sign chain-bound payloads.

### Governance Signer Set

A set of Ethereum addresses plus a threshold, configured once (env vars or the `/governance` config endpoint). At least `threshold` *distinct* signatures from this set authorize a `SET_MACHINE_PATH_LIST` update. The set is committed as `GovernanceHash = keccak256(abi.encode(signers, threshold))`, which is included in the node's registered machine data.

### Machine Path

A governance-approved tuple `(sourceTeeIds[], destinationTeeIds[])`. A path authorizes a direct key transfer when the source TEE is in `sourceTeeIds` **and** the destination TEE is in `destinationTeeIds` of the same path. The full list carries a strictly increasing nonce and is installed via `SET_MACHINE_PATH_LIST`. See [Backup & Restore](backup-restore.md#direct-backup--restore-tee-to-tee).

### Direct (TEE-to-TEE) Backup

A backup mechanism in which a source TEE encrypts a whole wallet private key under one destination TEE's public key (ECIES) and signs the payload, rather than splitting it among admins and providers. Only machine-path-authorized TEE pairs may participate. Contrast with the Shamir-based data-provider backup.

## Key Types and Signing Algorithms

### Key Types

- **XRP** - Keys for XRP Ledger transactions
- **EVM** - Keys for EVM-compatible chains

### Signing Algorithms

| Algorithm                    | ID          | Signature Size | Description                       |
| ---------------------------- | ----------- | -------------- | --------------------------------- |
| `sha512half-secp256k1-ecdsa` | XRPSignAlgo | 65 bytes       | SHA512-Half hash, secp256k1 ECDSA |
| `keccak256-secp256k1-ecdsa`  | EVMSignAlgo | 65 bytes       | Keccak256 hash, secp256k1 ECDSA   |
| `keccak256-secp256k1-vrf`    | VRFAlgo     | ~939 bytes     | Verifiable Random Function proof  |

All ECDSA signatures use the format `[R || S || V]` where R and S are 32 bytes each and V is the recovery ID (0 or 1).

## Signing Policies

### Reward Epoch

A time period identified by a `RewardEpochID` (uint32). Each epoch has an associated signing policy that defines which data providers can participate and their voting weights.

### Signing Policy

Defines the set of authorized voters (data providers) and their weights for a reward epoch. Policies are stored by epoch ID and must be initialized before any instruction processing. Signing policies are managed on-chain by the contracts in [flare-smart-contracts-v2](https://github.com/flare-foundation/flare-smart-contracts-v2). The policy data types used by the TEE node are defined in [go-flare-common](https://github.com/flare-foundation/go-flare-common).

### Policy Validity

Each instruction references a `RewardEpochID`. The TEE verifies that the referenced policy is at most one epoch behind the active policy: `activePolicyID - 1 <= policyID`. Instructions referencing older policies are rejected.

## Action Model

### Action

A message fetched from the proxy containing:

- **ActionData** - ID, type, submission tag, and encoded message
- **AdditionalVariableMessages** - Per-signer variable data (e.g., encrypted key splits)
- **Timestamps** - Per-signer timestamps
- **Signatures** - Per-signer ECDSA signatures

### Action Types

- **Instruction** - Requires multi-signature validation against a signing policy
- **Direct** - Immediate operations without signing policy checks

### Submission Tags

- **Threshold** — Sent when consensus among signers is reached. The TEE executes the operation and applies state changes.
- **End** — Sent after the Threshold phase. The TEE verifies the operation was performed and produces rewarding data for the participating entities.
- **Submit** — Used for direct actions (no two-phase protocol).

### OpID

A pair of (OpType, OpCommand) that determines which processor handles an action. Each pair is a keccak256 hash of a string identifier.

The following OpID pairs are built-in:

| OpType   | OpCommand                 | Handler                |
| -------- | ------------------------- | ---------------------- |
| F_WALLET | KEY_GENERATE              | KeyGenerate            |
| F_WALLET | KEY_DELETE                | KeyDelete              |
| F_WALLET | KEY_DATA_PROVIDER_RESTORE | KeyDataProviderRestore |
| F_WALLET | KEY_DIRECT_BACKUP         | KeyDirectBackup        |
| F_WALLET | KEY_DIRECT_RESTORE        | KeyDirectRestore       |
| F_WALLET | VRF                       | ProveRandomness        |
| F_XRP    | PAY                       | SignXRPLPayment        |
| F_XRP    | REISSUE                   | SignXRPLPayment        |
| F_REG    | TEE_ATTESTATION           | TEEAttestation         |
| F_FDC2   | PROVE                     | Prove                  |
| F_GET    | KEY_INFO                  | KeysInfo               |
| F_GET    | TEE_INFO                  | TEEInfo                |
| F_GET    | TEE_BACKUP                | TEEBackup              |
| F_POLICY | INITIALIZE_POLICY         | InitializePolicy       |
| F_POLICY | UPDATE_POLICY             | UpdatePolicy           |
| F_GOVERNANCE | SET_MACHINE_PATH_LIST | SetMachinePathList    |

In extension mode, user-implemented extensions may define custom OpType and OpCommand values. Actions with OpID pairs that do not match any built-in processor are forwarded to the extension server for handling. This allows extensions to introduce new operation types without modifying the TEE node itself.

## Roles

### Data Providers

Voters in a signing policy. Each has a weight. Instructions require a threshold of total voting weight to be met (typically >50%).

### Cosigners

Additional signers specified per-wallet. Cosigner threshold is checked separately from data provider threshold. Cosigners are typically wallet administrators.

### Admins

Entities with administrative control over a wallet. During backup, each admin receives encrypted key shares. During restore, an admin threshold must be met.

### Governance Signers

Holders of the keys in the node's governance signer set. A threshold of them authorizes machine-path-list updates (`SET_MACHINE_PATH_LIST`), which in turn govern which TEE pairs may perform direct key transfers. Governance does not by itself move keys: direct backup/restore still require the data-provider quorum enforced by the instruction pipeline.

## Cryptographic Primitives

### Shamir Secret Sharing

Used in wallet backup to split key material among multiple parties. A threshold number of shares is required to reconstruct the secret. Shares are evaluated points on a random polynomial over the secp256k1 curve order.

### ECIES (Elliptic Curve Integrated Encryption Scheme)

Used to encrypt key splits for individual recipients during backup. Each recipient's split is encrypted with their public key. Overhead: 113 bytes per encryption.

### Additive Key Splitting

The wallet private key is split into two additive shares (admin part + provider part). Both parts must be reconstructed independently via Shamir sharing, then added together to recover the full key.

## Storage Model

### Wallet Storage

Two-tier in-memory storage:

- **Active wallets** (`map[KeyIDPair]*Wallet`) - Currently usable wallets
- **Permanent records** (`map[KeyIDPair]*WalletStatus`) - Nonce tracking that persists across deletion

When a wallet is deleted, its permanent record (nonce) is preserved to prevent replay attacks. When a wallet is stored, it reuses the existing permanent record if one exists.

### WalletStatus

Tracks mutable wallet state:

- **Nonce** - Monotonically increasing, prevents replay of delete/restore operations
- **PausingNonce** - Reserved for future pausing functionality
- **StatusCode** - Reserved for future status tracking
