# Changelog

## [v0.1.0](https://github.com/flare-foundation/fcc-node/tree/v0.1.0) - 2026-11-24

### Changed

- Module renamed from `github.com/flare-foundation/tee-node` to `github.com/flare-foundation/fcc-node`; importers must update their import paths.
- Breaking wire-format changes; the proxy, relay client, CLI and extensions need matching updates:
  - An action's `data.message` is the JSON object of the instruction's `DataFixed` or of the `DirectInstruction` instead of the hex of that JSON. A message that is not a JSON object is rejected.
  - An action result's `data` is base64 in JSON instead of hex; its other byte strings stay 0x-prefixed hex. Extensions must return `data` as base64. `ActionResult.Hash()` is unchanged, as it covers the decoded bytes.
  - A `TEE_BACKUP` result carries `walletBackup` as a JSON object instead of the base64 of its JSON, its encrypted splits are base64 instead of hex, and the backup, key split and share keys are camelCase. This roughly halves a backup response.
  - Policy initialize and update requests, TEE info requests, wallet statuses and restore statuses use camelCase JSON keys.
- Wallet backups made before this release no longer verify, as their signatures cover the backup's JSON.
- `TEEBackupResponse` moves from `pkg/wallets` to `pkg/wallets/backup`.
- Each instruction is accepted once with the `threshold` tag and then once with `end`; a repeated action, an `end` before its `threshold` and any other tag are rejected with status `0`. Only a quorum-signed action uses up the instruction ID.
- go-flare-common bumped to v1.6.1.

## [v0.0.30](https://github.com/flare-foundation/fcc-node/tree/v0.0.30) - 2026-11-12

### Changed

- go-flare-common bumped to v1.6.0, which requires Go 1.27.4; Go bumped to 1.27.4.
- XRP payment instructions from or to the zero account `rrrrrrrrrrrrrrrrrrrrrhoLvTp` are rejected, as rippled would reject the transaction. Only an instruction whose fee schedule is all nullify tries still signs its `AccountSet`s.

## [v0.0.29](https://github.com/flare-foundation/fcc-node/tree/v0.0.29) - 2026-10-19

### Changed

- go-flare-common bumped to v1.5.0.
- Go bumped to 1.26.9, fixing reachable `net/http` and `crypto/tls` vulnerabilities, and go-ethereum to v1.17.8.
- Log timestamps change from `[01-02|15:04:05.000]` to RFC 3339 in UTC with milliseconds, and ERROR lines no longer carry a stack trace; anything parsing the logs needs updating. `LOG_LEVEL` values are unchanged.
- Instruction messages with a truncated or non-canonical ABI encoding are rejected.

### Fixed

- Extension mode no longer forwards `F_`-prefixed actions (e.g. `F_XRP`, `F_BTC`, `F_FDC2`, `F_WALLET`/`VRF`) to the extension; without a built-in processor they are rejected.
- Failed and timed-out action results (status 0 and 3, incl. router-level errors) now carry `opType`/`opCommand` whenever the action's message yields them.
- Direct actions tagged `threshold` or `end` are rejected in both modes, built-in or forwarded, so their signed results can't pass as an instruction's.
