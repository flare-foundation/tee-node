# Extension Integration

## Overview

The TEE node can run in two modes (see [Architecture](architecture.md)):

- **Base mode (Extension 0)**: All operations (wallet management, XRP signing, VRF, FDC) are handled by built-in processors. No extension delegation. This is the default `cmd/main.go` configuration using `NewPMWRouter`.

- **Extension mode**: The TEE provides base wallet management (generate, delete, backup, restore) and policy/attestation, but delegates all other actions to a user-implemented **extension server**. This mode uses `NewForwardRouter`.

Extension mode is designed for custom protocols that need the TEE's managed keys and attestation but implement their own business logic. The TEE handles key lifecycle and cryptographic operations; the extension implements domain-specific processing.

## Base Capabilities (Available in Both Modes)

The following are handled directly by the TEE in both modes:

| Operation                       | Description                          |
| ------------------------------- | ------------------------------------ |
| KeyGenerate                     | Create wallet key pairs              |
| KeyDelete                       | Remove wallets with nonce protection |
| KeyDataProviderRestore          | Restore wallets from backup shares   |
| TEEBackup                       | Create encrypted wallet backups      |
| TEEInfo / KeyInfo               | Query TEE and wallet information     |
| InitializePolicy / UpdatePolicy | Manage signing policies              |
| TEEAttestation                  | Produce TEE attestation responses    |

## Extension-Only Capabilities

In extension mode, the extension server can define custom `(OpType, OpCommand)` handlers for any operation not listed above. It can use the TEE's sign/decrypt server to perform cryptographic operations with managed keys.

In base mode (Extension 0), the following are built-in instead of delegated:

| Operation         | Description                           |
| ----------------- | ------------------------------------- |
| XRP Pay / Reissue | Sign XRP Ledger transactions          |
| VRF               | Generate verifiable randomness proofs |
| FDC2 Prove        | Produce FDC attestation proofs        |

## Architecture

```
TEE Node                        Extension Service
  |                                   |
  |-- POST /action ------------------>|  (forward unrecognized action)
  |<-- ActionResult ------------------|
  |                                   |
  |<-- POST /sign/{walletID}/{keyID} -|  (sign with wallet key)
  |-- SignResponse ------------------>|
  |                                   |
  |<-- POST /sign -------------------|  (sign with TEE key)
  |-- SignResponse ------------------>|
  |                                   |
  |<-- POST /decrypt/{wID}/{kID} ----|  (decrypt with wallet key)
  |-- DecryptResponse --------------->|
  |                                   |
  |<-- POST /decrypt ----------------|  (decrypt with TEE key)
  |-- DecryptResponse --------------->|
```

## Action Forwarding

When an action's `(OpType, OpCommand)` does not match any registered processor, the router forwards it to the extension:

- **Direct actions**: Forwarded via the default direct processor.
- **Instruction actions**: Preprocessed (signatures validated, thresholds checked), then forwarded via the default instruction processor.

The extension receives the full `Action` as JSON via `POST http://localhost:{EXTENSION_PORT}/action` and must return an `ActionResult`.

For instructions, the Threshold result is forwarded directly. At End, the TEE computes rewarding data.

## Ports

Two separate ports are involved in extension communication:

| Port             | Default | Purpose                                                                                                        |
| ---------------- | ------- | -------------------------------------------------------------------------------------------------------------- |
| `EXTENSION_PORT` | 8889    | The extension service listens here. The TEE forwards unrecognized actions to this port.                        |
| `SIGN_PORT`      | 8888    | The TEE exposes its sign/decrypt API here. The extension calls back to this port for cryptographic operations. |

## Extension Server API (SIGN_PORT)

The TEE sign/decrypt server runs on `SIGN_PORT` (default 8888) and exposes the following endpoints. All responses use `Content-Type: application/json`.

### GET /key-info/{walletID}/{keyID}

Returns the key existence proof for a wallet.

**Parameters**:

- `walletID`: hex-encoded 32-byte hash
- `keyID`: decimal uint64

**Response**: `KeyExistenceProof` JSON

**Errors**: 404 if wallet not found

### POST /sign/{walletID}/{keyID}

Signs a message with the specified wallet's private key using its configured signing algorithm.

**Request**:

```json
{ "message": "0x..." }
```

**Response**:

```json
{ "message": "0x...", "signature": "0x..." }
```

### POST /sign

Signs a message with the TEE's private key. The message is Keccak256-hashed before signing.

**Request/Response**: Same format as above.

### POST /decrypt/{walletID}/{keyID}

Decrypts an ECIES-encrypted message with the specified wallet's private key. Only works for XRP and EVM signing algorithms (not VRF).

**Request**:

```json
{ "encryptedMessage": "0x..." }
```

**Response**:

```json
{ "decryptedMessage": "0x..." }
```

### POST /decrypt

Decrypts an ECIES-encrypted message with the TEE's private key.

**Request/Response**: Same format as above.

### POST /result

Receives an `ActionResult` from the extension, signs it with the TEE key, and forwards it to the proxy.

**Request**: `ActionResult` JSON

The server retries posting to the proxy for up to 100 ms on failure.
