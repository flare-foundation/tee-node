# Changelog

## [v0.0.29](https://github.com/flare-foundation/tee-node/tree/v0.0.29) - 2026-10-19

### Changed

- go-flare-common bumped to v1.5.0.
- Go bumped to 1.26.9, fixing reachable `net/http` and `crypto/tls` vulnerabilities, and go-ethereum to v1.17.8.
- Log timestamps change from `[01-02|15:04:05.000]` to RFC 3339 in UTC with milliseconds, and ERROR lines no longer carry a stack trace; anything parsing the logs needs updating. `LOG_LEVEL` values are unchanged.
- Instruction messages with a truncated or non-canonical ABI encoding are rejected.

### Fixed

- Extension mode no longer forwards `F_`-prefixed actions (e.g. `F_XRP`, `F_BTC`, `F_FDC2`, `F_WALLET`/`VRF`) to the extension; without a built-in processor they are rejected.
- Failed and timed-out action results (status 0 and 3, incl. router-level errors) now carry `opType`/`opCommand` whenever the action's message yields them.
- Direct actions tagged `threshold` or `end` are rejected in both modes, built-in or forwarded, so their signed results can't pass as an instruction's.
