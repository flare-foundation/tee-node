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

Elliptic Curve Integrated Encryption Scheme, used for encrypting key splits during backup.

- Parameters: `ECIES_AES128_SHA256` with secp256k1
- Overhead: 113 bytes per encryption (ephemeral public key + MAC)
- Encryption: `ecies.Encrypt(rand, recipientPubKey, plaintext, nil, nil)`
- Decryption: `eciesPrivKey.Decrypt(ciphertext, nil, nil)`

Decryption is supported for XRP and EVM wallet types only. VRF wallets do not support decryption.

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

### Key Split Signature

Each `KeySplitData` is JSON-marshaled, Keccak256-hashed, then signed with a domain-separated prefix:

```
"\x19Flare PMW backup:\n32" + hash
```

The signature is made with the wallet's private key (not the recipient's), so recipients cannot forge modified splits.

### Backup Signature

The `WalletBackup` content (metadata + both encrypted share sets) is JSON-marshaled, hashed, and signed with the same prefix by the wallet key.

### TEE Signature

The backup hash is signed by the TEE's private key (standard Keccak256 ECDSA, no prefix).

## Hash Functions

| Function | Usage |
|----------|-------|
| Keccak256 | EVM signing, action result signing, backup hashing, vote hashes |
| SHA512-Half | XRP transaction signing |
| HashToZn | VRF challenge generation (Keccak256 mod N) |
| HashToCurve | VRF nonce-to-point mapping (iterative Keccak256) |
