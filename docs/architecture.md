# Architecture Overview

## System Context

The Flare TEE node is a secure server running inside a Google Cloud Confidential Space (Trusted Execution Environment). It manages protocol-controlled wallets and provides cryptographic operations for the Flare network.

```
External Clients
       |
       v
  +---------+        +----------+
  |  Proxy  | <----> | TEE Node |
  +---------+  HTTP  +----------+
       |                  |
       v                  v
   Network          Wallet Storage
                    Policy Storage
                    Extension Server
```

The TEE node never communicates directly with external clients. All communication is routed through a proxy service. The TEE node polls the proxy for actions and posts results back.

## Operating Modes

The TEE node can run in two modes, determined by which router is used at startup.

### Base Mode (Extension 0)

Used by `cmd/main.go` with `NewPMWRouter`. This is the **Protocol Managed Wallet** service, known on-chain as **Extension 0**. It provides the full built-in feature set:

- Wallet management (generate, delete, backup, restore)
- XRP Ledger transaction signing (Pay, Reissue)
- VRF proof generation
- FDC attestation proving
- TEE registration/attestation

In this mode, all supported OpType/OpCommand pairs are handled directly by the TEE node. There is no extension delegation — unrecognized actions are rejected.

### Extension Mode

Used with `NewForwardRouter`. This mode provides **base wallet management capabilities** (generate, delete, backup, restore, attestation) but delegates all other actions to an external **extension server**.

```
TEE Node (Extension Mode)
  |
  +-- Built-in: Wallet ops, Policy, TEEInfo, TEEBackup, Attestation
  |
  +-- Forwarded to extension (port 8889):
      +-- Unrecognized direct actions
      +-- Unrecognized instruction actions (after signature validation)
```

The extension server is a user-implemented HTTP service that:

- Receives forwarded actions on `POST /action` (port 8889)
- Can call back to the TEE's sign/decrypt server (port 8888) for cryptographic operations
- Returns `ActionResult` responses that the TEE signs and forwards to the proxy

This allows custom protocols to leverage the TEE's managed keys and attestation while implementing their own business logic. Each extension has a unique `ExtensionID` that is included in attestation responses and set once at startup.

**Key difference**: In base mode, FDC proving, XRP signing, and VRF are built-in processors. In extension mode, these would need to be implemented by the extension server (or are not available).

## Components

### Proxy

The proxy is an external intermediary that manages action queues and routes messages between external clients and the TEE node. The TEE node connects to the proxy via HTTP and continuously polls for new actions.

### TEE Node

The TEE node is the core component. On startup it:

1. Generates a fresh ECDSA private key (TEE identity)
2. Initializes empty wallet and policy storage
3. Starts the config server (port 5500)
4. Creates the router (base mode or extension mode)
5. Starts the queue processing loop (polls proxy)

### Three Processing Queues

The TEE node processes actions from three separate queues:

| Queue      | Purpose                                                        |
| ---------- | -------------------------------------------------------------- |
| **Main**   | Instruction-based actions requiring multi-signature validation |
| **Direct** | Immediate queries and configuration (no signing policy needed) |
| **Backup** | Backup-specific operations                                     |

Each queue runs as an independent goroutine, polling the proxy continuously.

### Extension Server

The extension server (port 8888) exposes wallet and TEE signing/decryption to external extension services running alongside the TEE. In extension mode, actions that do not match a registered processor are forwarded to the extension service (port 8889). See [Extensions](extensions.md) for details.

### Config Server

The config server (port 5500) accepts runtime configuration:

- `/proxy` - Set/update proxy URL
- `/initial-owner` - Set initial owner address (once)
- `/extension-id` - Set extension machine ID (once)

## Action Processing Flow

```
1. Poll proxy queue (POST /queue/{queueID})
2. Receive Action (JSON)
3. Validate structure (CheckAndAdapt)
4. Route by OpType + OpCommand
5. For instructions: validate signatures, check thresholds
6. Execute processor
7. Sign result with TEE key
8. Post response to proxy (POST /result)
```

## Trust Model

**The proxy is trusted for transport, not content.** The TEE node validates:

- All instruction signatures cryptographically
- Cosigner and data provider thresholds against signing policies
- TEE ID matching in instruction data
- Action/instruction ID consistency
- Message size constraints

**The proxy controls:**

- Which actions to deliver and when
- Order of action delivery
- Whether to deliver End phase after Threshold

**The proxy cannot:**

- Forge valid instruction signatures
- Bypass cosigner/data provider thresholds
- Extract private keys from the TEE

## Two-Phase Instruction Protocol

Instructions are processed in two phases:

1. **Threshold phase** — Sent by the proxy once a sufficient number of signers (data providers and cosigners) have reached consensus. The TEE executes the requested operation (e.g., stores a wallet, signs a transaction). All state mutations occur in this phase.

2. **End phase** — Sent after the Threshold phase has completed. The TEE verifies that the operation was performed (e.g., the wallet exists, the nonce was consumed) and produces rewarding data. This data includes a signed vote hash that identifies the participating signers and their timestamps, enabling on-chain reward distribution to the entities involved.

## Safety Limits

All limits are defined as constants in `internal/settings/settings.go`. See [Configuration](configuration.md) for the full list and default values.

| Setting                     | Default   | Purpose                                       |
| --------------------------- | --------- | --------------------------------------------- |
| `MaxWallets`                | 200,000   | Prevent OOM from wallet accumulation          |
| `MaxPermanentWalletsStatus` | 1,000,000 | Prevent OOM from nonce tracking growth        |
| `MaxSignGoroutines`         | 3,000     | Prevent OOM from sleeping XRP sign goroutines |
| `MaxFeeEntries`             | 50        | Limit per-instruction resource usage          |
| `MaxFeeScheduleTime`        | 10 min    | Bound goroutine lifetime                      |
| `MaxInstructionSize`        | 100 KB    | Limit parsing overhead                        |
| `MaxActionSize`             | 10 MB     | Limit total fetch size                        |
| `MaxVariableMessageSize`    | 1 MB      | Limit aggregated variable data                |

## Related Repositories

### TEE Infrastructure

| Repository                                                               | Description                                                                                                                                                                      |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [tee-proxy](https://github.com/flare-foundation/tee-proxy)               | Proxy service that sits between external clients and the TEE node. Manages action queues and provides the `POST /direct` endpoint for direct instructions.                       |
| [tee-relay-client](https://github.com/flare-foundation/tee-relay-client) | Listens for `TeeInstructionsSent` events from the on-chain `TeeExtensionRegistry` contract and forwards instructions to the TEE proxy. Supports provider mode and cosigner mode. |

### Shared Libraries and Contracts

| Repository                                                                               | Description                                                                                 |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| [go-flare-common](https://github.com/flare-foundation/go-flare-common)                   | Shared Go library used by tee-node (signing policies, instruction types, logging)           |
| [flare-smart-contracts-v2](https://github.com/flare-foundation/flare-smart-contracts-v2) | On-chain protocol contracts (signing policy management, VRF verification, TEE registration) |
| [flare-system-client](https://github.com/flare-foundation/flare-system-client)           | System client for FSO smart contract interactions, voter registration, and data submission  |
| [fdc-client](https://github.com/flare-foundation/fdc-client)                             | Flare Data Connector client                                                                 |
| [docs](https://github.com/flare-foundation/docs)                                         | Flare technical documentation                                                               |
