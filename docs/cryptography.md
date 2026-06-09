# Cryptography Reference

## Curve

All cryptographic operations currently use the **secp256k1** elliptic curve, matching Ethereum and XRP Ledger.

- Curve order N: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- Private keys: 256-bit integers in [1, N-1]
- Public keys: curve points (X, Y), each 32 bytes, uncompressed format (64 bytes total)

## Signing Algorithms

### ECDSA-Keccak256 (EVM)

Used for EVM-compatible wallets and TEE identity signing.

1. Hash message with Keccak256 (32 bytes)
2. Sign hash with secp256k1 ECDSA
3. Output: `[R || S || V]` = 65 bytes (R: 32, S: 32, V: 1)

Recovery: `crypto.SigToPub(hash, signature)` recovers the signer's public key.

### ECDSA-SHA512Half (XRP)

Used for XRP Ledger wallets.

1. Hash message with SHA512, take first 32 bytes (SHA512-Half)
2. Sign hash with secp256k1 ECDSA
3. Output: `[R || S || V]` = 65 bytes

### VRF (Verifiable Random Function)

Used for generating provable randomness. See [VRF documentation](vrf.md) for full details.

1. Hash nonce to curve point: `h = HashToCurve(nonce)`
2. Compute gamma: `gamma = sk * h`
3. Generate random k, compute witness points
4. Compute challenge: `c = HashToZn(Pack(G, h, pk, gamma, u, v))`
5. Compute response: `s = k - sk*c (mod N)`
6. Output: `Proof{Gamma, C, S, U, CGamma, V, ZInv}` (~939 bytes JSON)

Verification checks four equations involving the witness points and can be performed on-chain.

## ECIES Encryption

Elliptic Curve Integrated Encryption Scheme, used for encrypting key splits during backup and for encrypting a full wallet private key during direct TEE-to-TEE backup.

- Parameters: `ECIES_AES128_SHA256` with secp256k1
- Overhead: 113 bytes per encryption (ephemeral public key + MAC)
- Encryption: `utils.Encrypt(plaintext, recipientPubKey)` (wraps `ecies.Encrypt(rand, ..., nil, nil)`)
- Decryption: `utils.Decrypt(ciphertext, privKey)` (wraps `eciesPrivKey.Decrypt(ciphertext, nil, nil)`)

The `utils.Encrypt` / `utils.Decrypt` helpers in `pkg/utils/crypto.go` convert the secp256k1 ECDSA key to its ECIES form (rejecting non-S256 curves) before delegating to go-ethereum's `ecies`. Decryption is supported for XRP and EVM wallet types only. VRF wallets do not support decryption.

## Domain-Separated Signed Payloads

Every signature the TEE produces is taken over a canonical domain-separated preimage rather than a bare hash, so a signature is bound to both its payload type and the target network and cannot be replayed in another context. (The only exceptions are the external bit-exact formats — XRP Ledger transaction signatures and VRF proofs — which must not be wrapped.) The construction matches the on-chain `SignedPayload` library:

```
signing.Payload{prefix, chainID, dataHash}.Hash() = keccak256(abi.encode(
    bytes32 prefix,     // domain-separation tag for the payload type
    uint256 chainID,    // binds the signature to one EVM network
    bytes32 dataHash    // keccak256(abi.encode(payload fields))
))
```

The TEE then signs this value with the standard eth-signed-message wrap (`accounts.TextHash`); on-chain verifiers recover against the matching `SignedPayload.ethSignedHash`. `signing.Payload` is provided by go-flare-common's `pkg/signing`; `chainID` comes from the node's configured `CHAIN_ID` and is required (signing fails if it is unset).

| Domain tag (`bytes32(string)`) | Payload | `dataHash` = `keccak256(abi.encode(...))` of |
| ------------------------------ | ------- | -------------------------------------------- |
| `TEE_MACHINE_REGISTER` | Machine registration / attestation | `TeeMachineData` (extension ID, owner, code hash, platform, public key, governance hash) |
| `TEE_KEY_EXISTENCE`    | Key existence proof | the `KeyExistence` struct (TEE ID, wallet/key ID, public key, nonce, config) |
| `TEE_MACHINE_PATH_LIST`| Governance machine-path list | `(extensionID, nonce, paths)` |
| `FDC2`                 | FDC2 attestation proof | `(headerHash, requestBodyHash, responseBodyHash)` — see [FDC Proving](fdc.md) |
| `TEE_KEY_DIRECT_BACKUP`| Direct (TEE-to-TEE) backup envelope | `keccak256(payload)` — see [Backup & Restore](backup-restore.md#direct-backup--restore-tee-to-tee) |
| `TEE_WALLET_BACKUP`    | TEE-identity signature over a data-provider wallet backup | `WalletBackup.HashForSigning()` |
| `PMW_WALLET_BACKUP`    | Wallet-key signature over a data-provider wallet backup | `WalletBackup.HashForSigning()` |
| `PMW_KEY_SPLIT`        | Wallet-key signature over a single encrypted key split | `KeySplitData.HashForSigning()` |
| `TEE_VOTE_HASH`        | End-phase vote hash / rewarding data | `voteHash` — see [Action Processing](actions.md) |
| `TEE_ACTION_RESULT`    | Action result posted to the proxy | `ActionResult.Hash()` |

The governance signer set itself is committed as `GovernanceHash = keccak256(abi.encode(address[] signers, uint256 threshold))`, included in the registered `TeeMachineData`.

The `TEE_WALLET_BACKUP` and `PMW_WALLET_BACKUP` tags share the same `dataHash` but differ so a TEE-identity signature and a wallet-key signature over identical backup content stay non-interchangeable.

## Shamir Secret Sharing

Splits a secret into shares such that any `threshold` shares can reconstruct the secret, but fewer reveal nothing.

### Share Generation

1. Construct random polynomial of degree `threshold - 1` with the secret as constant term
2. Evaluate polynomial at points `x = 1, 2, ..., numShares`
3. Each share is a point `(x, y)` on the polynomial

All arithmetic is modulo the secp256k1 curve order N.

### Share Reconstruction (Lagrange Interpolation)

Given `threshold` shares, reconstruct the secret (y-intercept) using Lagrange interpolation:

```
secret = sum_i ( y_i * product_j!=i ( x_j / (x_j - x_i) ) ) mod N
```

Duplicate X values (same share submitted twice) are detected and rejected.

## Additive Key Splitting

The wallet private key is split into `n` additive shares:

```
shares[0], shares[1], ..., shares[n-2]  = random
shares[n-1] = privateKey - sum(shares[0..n-2])  mod N
```

Reconstruction: `privateKey = sum(all shares) mod N`

In backup, `n = 2`: one share for admins, one for providers. Each share is further split via Shamir sharing.

## Backup Signing

All three backup signatures use the domain-separated `signing.Payload{tag, chainID, innerHash}.Hash()` construction described above (the legacy `"\x19Flare PMW backup:\n32"` prefix has been removed).

### Key Split Signature

Each `KeySplitData` is JSON-marshaled and Keccak256-hashed, then the wallet's private key signs `signing.Payload{PMW_KEY_SPLIT, chainID, hash}.Hash()`. Signing with the wallet key (not the recipient's) means recipients cannot forge modified splits.

### Backup Signature

The `WalletBackup` content (metadata + both encrypted share sets) is JSON-marshaled and hashed, then the wallet key signs `signing.Payload{PMW_WALLET_BACKUP, chainID, hash}.Hash()`.

### TEE Signature

The same backup content hash is signed by the TEE's identity key over `signing.Payload{TEE_WALLET_BACKUP, chainID, hash}.Hash()`.

## Hash Functions

| Function | Usage |
|----------|-------|
| Keccak256 | EVM signing, action result signing, backup hashing, vote hashes |
| SHA512-Half | XRP transaction signing |
| HashToZn | VRF challenge generation (Keccak256 mod N) |
| HashToCurve | VRF nonce-to-point mapping (iterative Keccak256) |
