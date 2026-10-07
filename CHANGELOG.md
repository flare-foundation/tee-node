# Changelog

## [Unreleased]

### Fixed

- Extension mode no longer forwards `F_`-prefixed actions (e.g. `F_XRP`, `F_BTC`, `F_FDC2`, `F_WALLET`/`VRF`) to the extension; without a built-in processor they are rejected.
