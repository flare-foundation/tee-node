# Backup & Restore

## Overview

Wallet backup splits a wallet's private key into encrypted shares distributed among admins and data providers. Restoring requires collecting enough shares from both groups to reconstruct the key via Shamir secret sharing.

## Backup Creation

**Route**: `F_GET` / `TEE_BACKUP` (direct action)

### Process

1. Retrieve wallet from storage
2. Get active signing policy voter public keys and normalized weights
3. Generate a random nonce (`RandomNonce`) to uniquely identify this backup
4. Split private key into 2 additive shares (admin part + provider part)
5. For each part, create Shamir secret shares and encrypt per-recipient
6. Sign the backup with the wallet's private key
7. Return backup for TEE signature

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
2. Sign the `KeySplitData` with the wallet's private key
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
  Signature           (wallet key signature over backup content)
  TEESignature        (TEE key signature over backup hash)
```

### Backup Sizes

Measured with the test suite (3 admins, 100 providers):

| Wallet Type | WalletBackup JSON | TEEBackupResponse |
|-------------|-------------------|-------------------|
| ECDSA (XRP/EVM) | ~420 KB | ~560 KB |
| VRF | ~660 KB | ~880 KB |

VRF backups are larger because VRF signatures are ~939 bytes vs 65 bytes for ECDSA.

## Restore

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

## Security Properties

### RandomNonce Binding

Every backup generates a fresh `RandomNonce`. This is included in the `WalletBackupID` which is embedded in every key split and verified during restore. Shares from different backup runs, different epochs, or different TEEs cannot be mixed.

### Wallet Signature Verification

Each `KeySplit` is signed with the wallet's private key during backup. During restore, this signature is verified. Providers cannot forge or modify their shares without the wallet's key.

### Duplicate Detection

Key splits are deduplicated by hash. If two providers submit the same split, only one is accepted.

### Provider Denial Threshold

With `ProvidersThreshold = 666` out of 1000 total shares, providers controlling ~34% of weight can deny a restore by submitting invalid data. Their splits fail validation and are skipped, leaving insufficient honest shares.

## Known Limitations

### State Reset on Restore

Restored wallets have zeroed `SettingsVersion`, `Settings`, `StatusCode`, and `PausingNonce`. This is acceptable while these fields are unused but must be addressed before they carry security semantics.

### Data Provider Voting Weight Not Checked

The data provider voting weight threshold is 0 for restore operations. Provider participation is enforced cryptographically via Shamir reconstruction, not through voting weight checks.
