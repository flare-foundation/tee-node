# Wallet Operations

## Overview

Wallets are protocol-managed key pairs stored in the TEE's memory. Each wallet is identified by a `KeyIDPair` (WalletID hash + KeyID uint64) and contains a private key, signing configuration, and administrative metadata.

## KeyGenerate

Creates a new wallet key pair.

**Route**: `F_WALLET` / `KEY_GENERATE`

**Validation**:

- TEE ID must match
- At least one admin public key required
- Admin threshold must be > 0 and <= number of admins
- Cosigner threshold must be <= number of cosigners
- Signing algorithm must be supported (XRP, EVM, or VRF)
- No permanent record may already exist for this KeyIDPair

**Threshold phase**:

1. Generate random ECDSA private key
2. Store wallet with admin keys, cosigner list, and thresholds
3. Return signed key existence proof

**End phase**:

- Verify wallet exists
- Verify nonce was not used (confirms Threshold executed)

**Key Existence Proof** contains: TEE ID, wallet/key IDs, key type, signing algo, public key, nonce, restored flag, admin keys, cosigners, settings.

## KeyDelete

Removes a wallet from active storage.

**Route**: `F_WALLET` / `KEY_DELETE`

**Threshold phase**:

1. Check permanent record exists (wallet was created at some point)
2. Validate nonce is greater than stored nonce
3. Remove wallet from active storage
4. Update nonce in permanent record

**End phase**:

- Verify wallet does not exist (deletion succeeded)
- Verify nonce was consumed

The permanent record persists after deletion, preserving the nonce for replay protection.

## Storage Model

### Active Wallets

In-memory map of `KeyIDPair -> *Wallet`. Wallets are deep-copied on read (`Get`) and write (`Store`) to prevent external modification.

### Permanent Records

In-memory map of `KeyIDPair -> *WalletStatus`. Created when a wallet is first stored, never deleted. Tracks:

- **Nonce**: Monotonically increasing counter. Each delete or restore must provide a nonce greater than the stored value.
- **PausingNonce**: Reserved for future use.
- **StatusCode**: Reserved for future use.

When a wallet is stored and a permanent record already exists, the wallet's Status pointer is replaced with the existing permanent record, preserving the nonce history.

### Safety Limits

- Maximum active wallets: 200,000 (checked in `Store()`)
- Maximum permanent records: 1,000,000 (checked when creating new permanent records)

Both limits prevent out-of-memory conditions from unbounded wallet creation.

## Wallet Fields

| Field              | Type                | Description                               |
| ------------------ | ------------------- | ----------------------------------------- |
| WalletID           | Hash                | Wallet identifier                         |
| KeyID              | uint64              | Key identifier within wallet              |
| PrivateKey         | []byte              | Raw private key bytes (32 bytes)          |
| KeyType            | Hash                | XRP or EVM                                |
| SigningAlgo        | Hash                | ECDSA-SHA512Half, ECDSA-Keccak256, or VRF |
| Restored           | bool                | True if wallet was recovered from backup  |
| AdminPublicKeys    | []\*ecdsa.PublicKey | Admin ECDSA public keys                   |
| AdminsThreshold    | uint64              | Required admin signatures for recovery    |
| Cosigners          | []Address           | Cosigner Ethereum addresses               |
| CosignersThreshold | uint64              | Required cosigner signatures              |
| SettingsVersion    | Hash                | Version hash for settings                 |
| Settings           | []byte              | Encoded wallet settings                   |
| Status             | \*WalletStatus      | Mutable nonce and status tracking         |
