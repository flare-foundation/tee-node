# XRP Signing

## Overview

The TEE signs XRP Ledger payment transactions using wallet keys of type XRP. A single sign instruction can produce multiple signed transactions with different fee levels, delivered on a time-based schedule.

## Route

- `F_XRP` / `PAY` - Standard payments
- `F_XRP` / `REISSUE` - Reissue payments

Both use the same `SignXRPLPayment` processor.

## Payment Instruction

The instruction contains:

- **WalletId** - Which wallet to sign with
- **TeeIdKeyIdPairs** - List of (TeeID, KeyID) pairs; only keys matching this TEE's ID are used
- **FeeSchedule** - Encoded fee entries (4 bytes each: 2 bytes BIPS + 2 bytes delay)
- Payment details (destination, amount, etc.)

## Fee Schedule

Each fee entry is 4 bytes:

| Bytes | Field | Range |
|-------|-------|-------|
| 0-1 | FeeBIPS (int16) | -10000 to 10000, nonzero |
| 2-3 | Delay (uint16) | 0 to 65535 seconds |

- Negative BIPS indicates a nullify transaction
- Maximum entries: 50
- Maximum delay: 10 minutes

### Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| MaxFeeEntries | 50 | Prevents excessive signed TX accumulation in memory |
| MaxFeeScheduleTime | 10 min | Bounds goroutine sleep duration |
| MaxSignGoroutines | 3,000 | Prevents OOM from accumulated goroutines |

## Processing Flow

### Threshold Phase

1. Parse payment instruction
2. Parse and validate fee schedule entries
3. Check fee entry count and delay limits
4. Filter key IDs matching this TEE
5. Load private keys from wallet storage (must be XRP type + XRP signing algo)
6. Validate cosigners match between instruction and stored wallet
7. **Pre-sign all transactions** for all fee entries
8. Check goroutine limit
9. Spawn goroutine to deliver results on schedule

### Goroutine Delivery

The goroutine posts cumulative results to the proxy after each entry's delay:

```
t=0s:  Post signedTxs[0]           (status 3)
t=5s:  Post signedTxs[0..1]        (status 4)
t=30s: Post signedTxs[0..2]        (status 1 = final)
```

Status codes: intermediate entries get `3 + index`, the final entry gets `1`.

Each result is signed with the TEE key before posting.

### End Phase

No operation is performed. Returns an empty result.

## Multisig Support

When multiple key IDs are provided, the TEE signs with each key and produces a multisig transaction. Signer items are sorted deterministically before being joined into the final multisig JSON.

## Safety

- All transactions are pre-signed before the goroutine starts. No key access is required during delivery.
- The atomic goroutine counter prevents unlimited accumulation.
- Goroutines decrement the counter via `defer` on exit, including early returns from errors.
- Each goroutine holds approximately 50-100 KB of memory (signed transaction data and stack).
- At maximum load (3,000 goroutines), total memory consumption is approximately 250-500 MB.
