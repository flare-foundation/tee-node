# Package Map

## Overview

The codebase is split into `pkg/` (importable library packages) and `internal/` (application-specific packages). The entry point is `cmd/main.go`.

The primary external dependency is [go-flare-common](https://github.com/flare-foundation/go-flare-common), which provides shared types for signing policies, instruction encoding, operation identifiers, and logging.

## Package Dependency Flow

```
cmd/main.go
  |
  +-- internal/router         (action routing, queue processing)
  |     +-- internal/router/queue    (proxy HTTP communication)
  |     +-- internal/processors/     (all action handlers)
  |
  +-- internal/settings       (configuration, config server)
  +-- pkg/node                (TEE identity, signing)
  +-- pkg/wallets             (wallet storage, key management)
  +-- pkg/policy              (signing policy storage)
```

## pkg/ - Library Packages

### pkg/node
TEE node identity management. Generates the ECDSA key pair, provides signing and decryption, manages initial owner and extension ID.

### pkg/wallets
Wallet storage and key operations. Defines the `Wallet` struct, `Storage` with dual-tier (active + permanent) maps, and signing methods for all three algorithms (ECDSA-Keccak256, ECDSA-SHA512Half, VRF).

### pkg/wallets/backup
Data types for backup structures: `WalletBackup`, `WalletBackupMetaData`, `EncryptedShares`, `KeySplit`, `KeySplitData`, `ShamirShare`. Also contains signature verification and hash computation methods.

### pkg/wallets/vrf
VRF (Verifiable Random Function) implementation. Proof generation and verification using secp256k1. Includes `HashToCurve`, `HashToZn`, and on-chain-compatible proof structure.

### pkg/policy
Signing policy storage. Stores policies by reward epoch ID, tracks active policy and associated voter public keys. Thread-safe with RWMutex.

### pkg/types
Shared data structures: `Action`, `ActionResult`, `ActionResponse`, `OpID`, `DirectInstruction`, submission tags, payment types, VRF types, sign/decrypt request/response types.

### pkg/processorutils
Common utilities for processors: action parsing with size limits, threshold checking (cosigner + data provider), `CheckAndAdapt` validation, `CheckMatchingCosigners`.

### pkg/constraints
Per-operation-command size constraints for original messages, additional fixed messages, and variable messages.

### pkg/attestation
Google Cloud attestation token claim structures (`NeededClaims`). Parses JWT tokens to extract hardware model and container image digest.

### pkg/fdc
Flare Data Connector request decoding. Parses ABI-encoded FDC requests.

### pkg/utils
Cryptographic utilities: ECDSA/ECIES key conversion, signature-to-address recovery, public key parsing, address derivation, hash helpers.

## internal/ - Application Packages

### internal/router
Action router. Maps `(OpType, OpCommand)` pairs to processors. Runs three queue workers (Main, Direct, Backup). Signs results with TEE key before posting.

### internal/router/queue
HTTP client for proxy communication. `FetchAction` polls a queue, `PostActionResponse` sends results.

### internal/settings
Runtime configuration. Constants (size limits, timeouts, safety bounds), environment variable reading, config HTTP server (/proxy, /initial-owner, /extension-id).

### internal/processors/direct
Direct action processors (no signing policy required):
- **getutils**: TEEInfo, KeysInfo, TEEBackup handlers
- **policyutils**: InitializePolicy, UpdatePolicy handlers

### internal/processors/instructions
Instruction processors (require signing policy validation):
- **walletutils**: KeyGenerate, KeyDelete, KeyDataProviderRestore
- **signutils**: SignXRPLPayment (Pay + Reissue)
- **vrfutils**: VRF proof generation
- **fdcutils**: FDC attestation proving
- **regutils**: TEE attestation/registration

### internal/wallets/backup
Wallet backup creation and recovery. Key splitting (additive + Shamir), ECIES encryption per-recipient, wallet reconstruction from shares.

### internal/attestation
Google Cloud Confidential Space attestation token retrieval. Communicates via Unix socket in production, returns test values in local mode.

### internal/extension
Extension service communication. Forwards unrecognized actions to extension, provides sign/decrypt server for extension use.

### internal/testutils
Test utilities: mock wallet creation, mock action building, random key/policy generation, mock proxy server.
