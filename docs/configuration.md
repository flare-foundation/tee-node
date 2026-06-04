# Configuration Reference

## Environment Variables

| Variable         | Default | Description                                                           |
| ---------------- | ------- | --------------------------------------------------------------------- |
| `MODE`           | `1`     | `0` = production (GCP attestation), `1` = local/test (no attestation) |
| `LOG_LEVEL`      | `FATAL` | Logging level                                                         |
| `PROXY_URL`      | (empty) | Initial proxy URL, can be updated at runtime via config server        |
| `INITIAL_OWNER`  | (empty) | Hex-encoded Ethereum address (20 bytes), optional `0x` prefix         |
| `EXTENSION_ID`   | `MaxHash` | Hex-encoded 32-byte hash, optional `0x` prefix. Defaults to `MaxHash` if not set. |
| `CHAIN_ID`       | (unset) | EVM chain ID (decimal or `0x`). Bound into every domain-separated signed payload (see [Cryptography](cryptography.md)). Set once via env or config server; `0` is rejected. |
| `GOVERNANCE_SIGNERS`   | (unset) | Comma-separated `0x`-prefixed Ethereum addresses authorized to sign `SET_MACHINE_PATH_LIST`. Must be set together with `GOVERNANCE_THRESHOLD`. |
| `GOVERNANCE_THRESHOLD` | (unset) | Minimum number of *distinct* `GOVERNANCE_SIGNERS` signatures required per machine-path list. Must be `>= 1` and `<=` the number of signers. |
| `CONFIG_PORT`    | `5500`  | Port for the configuration HTTP server                                |
| `SIGN_PORT`      | `8888`  | Port for the extension sign/decrypt server                            |
| `EXTENSION_PORT` | `8889`  | Port where the extension service listens                              |

## Constants

### Size Limits

| Constant                 | Value  | Description                                            |
| ------------------------ | ------ | ------------------------------------------------------ |
| `MaxInstructionSize`     | 100 KB | Maximum size of an instruction message                 |
| `MaxActionSize`          | 10 MB  | Maximum size of a direct instruction message           |
| `MaxFetchResponseSize`   | 10 MB  | Maximum size of a fetched action response from proxy   |
| `MaxVariableMessageSize` | 1 MB   | Maximum total size of all aggregated variable messages |

### Wallet Limits

| Constant                    | Value     | Description                                         |
| --------------------------- | --------- | --------------------------------------------------- |
| `MaxWallets`                | 200,000   | Maximum active wallets in memory                    |
| `MaxPermanentWalletsStatus` | 1,000,000 | Maximum permanent wallet records (includes deleted) |

### XRP Signing Limits

| Constant             | Value  | Description                                       |
| -------------------- | ------ | ------------------------------------------------- |
| `MaxSignGoroutines`  | 3,000  | Maximum concurrent sign schedule goroutines       |
| `MaxFeeEntries`      | 50     | Maximum fee schedule entries per sign instruction |
| `MaxFeeScheduleTime` | 10 min | Maximum delay for any fee schedule entry          |

### Timing

| Constant                 | Value  | Description                                   |
| ------------------------ | ------ | --------------------------------------------- |
| `ProxyTimeout`           | 2 s    | HTTP timeout for proxy communication          |
| `QueuedActionsSleepTime` | 100 ms | Sleep between queue poll iterations when idle |

## Config Server Endpoints

The config server listens on `CONFIG_PORT` (default 5500) and accepts POST requests with JSON bodies.

### POST /proxy

Sets or updates the proxy URL.

```json
{ "url": "http://proxy-host:8080" }
```

The URL must be a valid URI. This endpoint may be called multiple times to update the proxy address.

### POST /initial-owner

Sets the initial owner address. This endpoint may only be called once; subsequent calls are rejected.

```json
{ "owner": "0xaabbccdd..." }
```

### POST /extension-id

Sets the extension machine ID. This endpoint may only be called once; subsequent calls are rejected.

```json
{ "extensionId": "0xaabbccdd..." }
```

### POST /chain-id

Sets the EVM chain ID bound into signed payloads. This endpoint may only be called once; subsequent calls are rejected, and `0` is rejected.

```json
{ "chainId": 14 }
```

### POST /governance

Sets the governance signer set and threshold that authorize `SET_MACHINE_PATH_LIST`. This endpoint may only be called once; subsequent calls are rejected. The threshold must be `>= 1` and `<=` the number of signers, and no signer may be the zero address.

```json
{ "signers": ["0xaabb...", "0xccdd..."], "threshold": 2 }
```

> **Note:** As with the other config endpoints, these setters are unauthenticated; security relies on network-level access control of `CONFIG_PORT`. Each value can alternatively (and preferably) be fixed at deploy time via its environment variable, which is read during node initialization *before* the config server starts and therefore closes any post-start window. See [Security](security.md#config-server).

## Startup Sequence

1. Logger initialized with configured level
2. TEE node initialized (generates key pair, reads env vars)
3. Wallet storage initialized (empty)
4. Policy storage initialized (empty)
5. Config server started on CONFIG_PORT
6. Router created with all processors registered
7. Queue processing started (Main, Direct, Backup queues)

During node initialization the env vars for the initial owner, extension ID, chain ID, and governance (signers + threshold) are read; each takes precedence over the corresponding config-server endpoint.

The TEE node will not process any actions until:

- A proxy URL is configured (via env var or config server)
- A signing policy is initialized (via `INITIALIZE_POLICY` direct action)

Additionally, direct TEE-to-TEE backup/restore (`KEY_DIRECT_BACKUP` / `KEY_DIRECT_RESTORE`) requires governance to be configured and a machine-path list to be installed via `SET_MACHINE_PATH_LIST`. See [Backup & Restore](backup-restore.md#direct-backup--restore-tee-to-tee).
