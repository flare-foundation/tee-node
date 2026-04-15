# Configuration Reference

## Environment Variables

| Variable         | Default | Description                                                           |
| ---------------- | ------- | --------------------------------------------------------------------- |
| `MODE`           | `1`     | `0` = production (GCP attestation), `1` = local/test (no attestation) |
| `LOG_LEVEL`      | `FATAL` | Logging level                                                         |
| `PROXY_URL`      | (empty) | Initial proxy URL, can be updated at runtime via config server        |
| `INITIAL_OWNER`  | (empty) | Hex-encoded Ethereum address (20 bytes), optional `0x` prefix         |
| `EXTENSION_ID`   | `MaxHash` | Hex-encoded 32-byte hash, optional `0x` prefix. Defaults to `MaxHash` if not set. |
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

## Startup Sequence

1. Logger initialized with configured level
2. TEE node initialized (generates key pair, reads env vars)
3. Wallet storage initialized (empty)
4. Policy storage initialized (empty)
5. Config server started on CONFIG_PORT
6. Router created with all processors registered
7. Queue processing started (Main, Direct, Backup queues)

The TEE node will not process any actions until:

- A proxy URL is configured (via env var or config server)
- A signing policy is initialized (via `INITIALIZE_POLICY` direct action)
