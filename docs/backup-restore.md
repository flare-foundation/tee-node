# Backup & Restore

## Overview

The TEE node supports two independent mechanisms for moving a wallet's private key:

1. **Data-provider backup & restore** (Shamir-based) — the key is split into encrypted shares distributed among admins and data providers. Restoring requires collecting enough shares from both groups to reconstruct the key via Shamir secret sharing. This is the default, quorum-recoverable backup.

2. **Direct backup & restore** (TEE-to-TEE) — a source TEE encrypts the *whole* private key directly under a single destination TEE's public key (ECIES) and signs it. The destination TEE decrypts and stores it. Both ends must be authorized by a governance-approved **machine-path list**. See [Direct Backup & Restore (TEE-to-TEE)](#direct-backup--restore-tee-to-tee).

Both mechanisms run through the standard instruction pipeline, so the usual signature, threshold, and replay checks described in [Action Processing](actions.md) apply before any key material moves. Direct backup/restore additionally require a `>50%` data-provider voting-weight quorum; data-provider restore instead relies on Shamir reconstruction and the admin threshold (its data-provider weight threshold is `0`, see [Known Limitations](#data-provider-voting-weight-not-checked)).

## Data-Provider Backup (Shamir)

**Route**: `F_GET` / `TEE_BACKUP` (direct action)

### Process

1. Retrieve wallet from storage
2. Get active signing policy voter public keys and normalized weights
3. Generate a random nonce (`RandomNonce`) to uniquely identify this backup
4. Split private key into 2 additive shares (admin part + provider part)
5. For each part, create Shamir secret shares and encrypt per-recipient
6. Sign the backup with the wallet's private key over `signing.Payload{PMW_WALLET_BACKUP, chainID, contentHash}.Hash()`
7. Return backup for the TEE signature over `signing.Payload{TEE_WALLET_BACKUP, chainID, contentHash}.Hash()`

### Key Splitting

The wallet's private key `sk` is split additively:

```
sk = adminPart + providerPart  (mod N)
```

Both parts are random; neither reveals the full key alone.

### Shamir Secret Sharing

Each part is further split using Shamir's scheme:

**Admin shares**: Total shares = number of admins (weight 1 each). Threshold = `AdminsThreshold`.

**Provider shares**: Total shares = 1000 (normalized weights). Threshold = 666 (~66.7%). Each provider gets shares proportional to their voting weight.

### Per-Recipient Encryption

For each recipient (admin or provider):

1. Create `KeySplitData` containing their Shamir shares, backup ID, and owner public key
2. Sign the `KeySplitData` with the wallet's private key over `signing.Payload{PMW_KEY_SPLIT, chainID, hash}.Hash()`
3. Wrap in `KeySplit` (data + signature)
4. JSON-marshal the `KeySplit`
5. Encrypt with recipient's ECIES public key

### Backup Structure

```
WalletBackup
  WalletBackupMetaData
    WalletBackupID (TeeID, WalletID, KeyID, PublicKey, KeyType, SigningAlgo, RewardEpochID, RandomNonce)
    AdminsPublicKeys, AdminsThreshold
    ProvidersThreshold
    Cosigners, CosignersThreshold
  AdminEncryptedParts
    Splits[]          (one ECIES-encrypted KeySplit per admin)
    OwnersPublicKeys[]
    Threshold, Weights[]
  ProviderEncryptedParts
    Splits[]          (one ECIES-encrypted KeySplit per provider)
    OwnersPublicKeys[]
    Threshold, Weights[]
  Signature           (wallet-key signature, signing.Payload{PMW_WALLET_BACKUP, chainID, contentHash}.Hash())
  TEESignature        (TEE-key signature, signing.Payload{TEE_WALLET_BACKUP, chainID, contentHash}.Hash())
```

### Backup Sizes

Measured with the test suite (3 admins, 100 providers):

| Wallet Type | WalletBackup JSON | TEEBackupResponse |
|-------------|-------------------|-------------------|
| ECDSA (XRP/EVM) | ~420 KB | ~560 KB |
| VRF | ~660 KB | ~880 KB |

VRF backups are larger because VRF signatures are ~939 bytes vs 65 bytes for ECDSA.

## Data-Provider Restore (Shamir)

**Route**: `F_WALLET` / `KEY_DATA_PROVIDER_RESTORE` (instruction)

### Validation (`keyRestoreDataCheck`)

1. Parse restore request from instruction
2. Verify TEE public key matches current TEE ID
3. Verify signing algorithm is supported
4. Unmarshal backup metadata from `AdditionalFixedMessage`
5. Verify backup ID in request matches metadata
6. Verify cosigners match admin addresses and thresholds
7. Verify admin threshold is met among instruction signers
8. Verify all signers are either data providers (from backup epoch policy) or admins
9. Look up signing policy for backup's reward epoch

### Key Split Processing (`processKeySplitMessages`)

For each signer's variable message:

1. **Decrypt** with TEE private key (ECIES)
2. **Parse** JSON to KeySplit (single split for provider-only, two splits for provider+admin)
3. **Verify backup ID** in split matches expected ID
4. **Verify signature** on split (signed by wallet's key, not provider's key)
5. **Check for duplicates** via hash

Decryption or validation failures are logged and skipped rather than treated as fatal errors. This permits partial recovery when some providers are absent or submit invalid data.

### Key Reconstruction (`RecoverWallet`)

1. Separate key splits into admin and provider groups
2. Validate admin shares (backup ID consistency, admin public key membership)
3. Reconstruct admin key part via `JoinKeyShares` (Lagrange interpolation)
4. Validate provider shares (backup ID consistency)
5. Reconstruct provider key part via `JoinKeyShares`
6. Add both parts: `sk = adminKey + providerKey (mod N)`
7. Verify recovered public key matches expected public key from metadata

### Threshold Phase

1. Verify wallet does not already exist (prevents overwrite)
2. If permanent record exists, validate nonce
3. Store recovered wallet
4. Update nonce
5. Return signed key existence proof

### End Phase

- Verify wallet exists
- Verify nonce matches (confirms Threshold executed)

## Direct Backup & Restore (TEE-to-TEE)

Direct backup transfers a wallet key from one TEE to exactly one other TEE without splitting it. The source TEE encrypts the whole private key under the destination TEE's public key, and only TEE pairs explicitly authorized by a governance-approved machine-path list may participate.

### Machine-Path Authorization

A **machine path** is a tuple `(sourceTeeIds[], destinationTeeIds[])`. A path authorizes a transfer if the source TEE is in `sourceTeeIds` **and** the destination TEE is in `destinationTeeIds` of the *same* path. The list is installed by governance via the `F_GOVERNANCE` / `SET_MACHINE_PATH_LIST` direct action and is gated by governance signatures and a strictly increasing nonce (see [Security](security.md#governance--machine-path-authorization)). Authorization is always evaluated against the node's *current* machine-path list.

### Direct Backup

**Route**: `F_WALLET` / `KEY_DIRECT_BACKUP` (instruction)

1. Parse the request and validate authorization (`validateKeyDirectBackupRequest`):
    - `sourceTeeId` must equal this TEE's identity
    - `machinePathListNonce` must equal the node's current nonce
    - the destination public key must parse, and the current path list must authorize `(this TEE, destination)`
2. Look up the wallet; require a secp256k1 signing algorithm
3. ECIES-encrypt the private key under the destination's public key
4. Assemble a `KeyDirectBackupPayload`: the `BackupID` (TEE ID, wallet/key ID, derived public key, key type, signing algo, **current reward epoch**, and a fresh `RandomNonce`), the encrypted private key, and the plaintext wallet configuration (admin keys, cosigners, thresholds, settings, status)
5. Sign `signing.Payload{TEE_KEY_DIRECT_BACKUP, chainID, keccak256(payload)}.Hash()` with the TEE identity key and return the envelope:

```
SignedKeyDirectBackup
  Payload        (JSON KeyDirectBackupPayload)
  TEESignature   (source TEE signature over signing.Payload{TEE_KEY_DIRECT_BACKUP, chainID, keccak256(Payload)}.Hash())
```

The blob is stateless with respect to the destination's per-key nonce; replay is bounded by the reward-epoch window checked at restore.

### Direct Restore

**Route**: `F_WALLET` / `KEY_DIRECT_RESTORE` (instruction)

The restore instruction carries a quorum-signed `BackupId` in its original message and the source TEE's `SignedKeyDirectBackup` envelope in `AdditionalFixedMessage`.

1. Parse the request and validate authorization (`validateKeyDirectRestoreRequest`):
    - `BackupId.teeId` must equal `sourceTeeId`
    - `machinePathListNonce` must not exceed the node's current nonce
    - the current path list must authorize `(source, this TEE)`
2. Verify the envelope `TEESignature` over `signing.Payload{TEE_KEY_DIRECT_BACKUP, chainID, keccak256(Payload)}.Hash()` against `sourceTeeId`
3. Cross-check the source-signed payload's `BackupID` against the quorum-signed instruction `BackupId` by comparing their canonical ABI encodings (`matchesInstructionBackupId`)
4. Verify the backup's `RewardEpochID` is fresh: the node's current reward epoch must be the backup's epoch or one greater (`{epoch, epoch+1}`)
5. ECIES-decrypt the private key with this TEE's own key
6. Reconstruct the wallet and verify the public key derived from the decrypted key matches `BackupID.PublicKey`
7. Threshold phase: reject if the wallet already exists, validate the per-key nonce against any permanent record, store the wallet (marked `Restored`), update the nonce, and return a signed key existence proof. End phase verifies the wallet exists and the nonce matches.

### Security Properties

- **Confidentiality**: the private key is only ever transmitted as ECIES ciphertext under the destination TEE's public key; the plaintext never leaves the source TEE.
- **Authorization is layered**: in addition to the data-provider quorum and cosigner checks enforced by the instruction pipeline, both ends must be authorized by the governance-approved machine-path list. The machine-path list narrows *who* may transfer; it is not a substitute for the quorum.
- **Integrity binding**: the `BackupID` (including the public key and signing algorithm) is bound by the quorum-signed instruction, by the source TEE's signature over the payload, and by the decrypted-key-derives-`BackupID.PublicKey` check. A tampered payload, mismatched key, or wrong source signer is rejected.
- **Replay protection**: the per-key nonce (against the permanent record) and the `{epoch, epoch+1}` reward-epoch freshness window bound reuse of a backup envelope.

## Data-Provider Security Properties

These properties apply to the Shamir-based data-provider backup/restore flow.

### RandomNonce Binding

Every backup generates a fresh `RandomNonce`. This is included in the `WalletBackupID` which is embedded in every key split and verified during restore. Shares from different backup runs, different epochs, or different TEEs cannot be mixed.

### Wallet Signature Verification

Each `KeySplit` is signed with the wallet's private key during backup over `signing.Payload{PMW_KEY_SPLIT, chainID, hash}.Hash()`. During restore, this signature is verified. Providers cannot forge or modify their shares without the wallet's key.

### Duplicate Detection

Key splits are deduplicated by hash. If two providers submit the same split, only one is accepted.

### Provider Denial Threshold

With `ProvidersThreshold = 666` out of 1000 total shares, providers controlling ~34% of weight can deny a restore by submitting invalid data. Their splits fail validation and are skipped, leaving insufficient honest shares.

## Known Limitations

### State Reset on Restore

Restored wallets have zeroed `SettingsVersion`, `Settings`, `StatusCode`, and `PausingNonce`. This is acceptable while these fields are unused but must be addressed before they carry security semantics.

### Data Provider Voting Weight Not Checked

The data provider voting weight threshold is 0 for restore operations. Provider participation is enforced cryptographically via Shamir reconstruction, not through voting weight checks.
