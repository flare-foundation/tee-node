# Testing Guide

## Running Tests

```bash
# All tests
go test ./...

# Specific package
go test ./pkg/wallets/...
go test ./internal/processors/...

# Verbose with no cache
go test ./... -v -count=1
```

## Test Structure

### Unit Tests

| Package                                      | Tests Cover                                                                       |
| -------------------------------------------- | --------------------------------------------------------------------------------- |
| `pkg/wallets`                                | Storage operations, signing algorithms, key generation, wallet copy, nonce checks |
| `pkg/wallets/vrf`                            | VRF proof generation and verification, edge cases (nil keys, invalid points)      |
| `pkg/policy`                                 | Policy storage, initialization, updates, public key mapping                       |
| `pkg/processorutils`                         | Threshold checking, cosigner matching                                             |
| `internal/processors/instructions/signutils` | XRP signing, multisig, fee schedules, cosigner validation, error cases            |
| `internal/processors/direct/policyutils`     | Policy init/update with signature verification                                    |
| `internal/processors/direct/getutils`        | TEE info, key info responses                                                      |
| `internal/wallets/backup`                    | Shamir sharing, key splitting/joining round-trips                                 |
| `internal/settings`                          | Config server endpoint validation                                                 |
| `internal/extension/server`                  | Sign/decrypt server endpoints                                                     |

### End-to-End Test

`internal/processors/processor_test.go` contains `TestProcessorsEndToEnd`, which exercises the full action processing pipeline:

1. Initialize TEE node, wallet storage, policy storage
2. Start mock proxy server
3. Configure proxy URL via config server
4. Fetch TEE info (direct action)
5. Initialize signing policy (direct action)
6. Generate wallets (XRP, VRF) via instruction actions
7. Prove VRF randomness
8. Sign XRP transaction
9. Create backups for both wallets
10. Delete both wallets
11. Restore both wallets from backups
12. Verify restored wallet proofs match originals
13. TEE attestation
14. FDC proof

This test validates the complete lifecycle including backup/restore round-trips.
