# Test Scripts Documentation

## Start Servers

### Test Locally

You can start 3 servers locally by running:

```bash
./tests/scripts/start_server.sh
```

They will start on ports defined in the `tests/configs/config_server.toml`, `tests/configs/config_backup0.toml` and `config_backup1.toml`.

Then you can initialize mock policies by running:

```bash
./tests/scripts/initialize_policies.sh
```

which will start a mock policy with three signers.

### Test Remotely (on GCP)

First if you want to push the latest version of the code to the package registry run:

```bash
./tests/scripts/gcp/launch_servers.sh --build-docker
```

Then to launch 3 servers on GCP run

```bash
./tests/scripts/gcp/launch_servers.sh --launch-instances
```

This will automatically add the addresses of these instances to the config files so you don't have to do anything else.

If you want to delete the instances when you are done testing or if someone else forgot to you can run:

```bash
./tests/scripts/gcp/launch_servers.sh --stop-instances
```

## Wallets

You can test the basic flow of creating, backing up and restoring a wallet as follows:

### Create Wallet

Run

```bash
./tests/scripts/wallet/create_wallet.sh --local
```

to create a new wallet with ID "0x6969". This script generates a new wallet by sending requests to the server with a randomly generated instruction ID and stores the wallet information for later use.

### Backup Wallet

Run

```bash
./tests/scripts/wallet/backup_wallet.sh --local
```

to split the wallet and back it up on the 2 backup servers. This script retrieves the wallet information, splits the key into shares, and distributes these shares to the backup servers for secure storage.

### Restore Wallet

Run

```bash
./tests/scripts/wallet/restore_wallet.sh --local
```

to test restoring the wallet from the backup servers. This script retrieves the wallet shares from the backup servers, reconstructs the original wallet, and verifies that the restored wallet matches the original address.

_If you want to test it on the deployed GCP instances instead of locally replace `--local` with `--remote`_

## XRP

### Create XRP Wallets

Run

```bash
./tests/scripts/xrp/create_wallet.sh --local
```

to create XRP wallets on each of the three servers. This script generates a new XRP wallet for each server configuration, retrieves the XRP addresses, and stores them in `tests/scripts/generated/xrp/addresses.txt` for later use in payment signing.

### Sign XRP Payment

Run

```bash
./tests/scripts/xrp/sign_payment.sh --local
```

to sign an XRP payment transaction. This script:

1. Reads the previously generated XRP addresses
2. Creates a payment transaction for each address
3. Hashes the payment data
4. Collects signatures from all required signers
5. Outputs the payment information and signatures to both human-readable (`tests/scripts/generated/xrp/signatures.txt`) and JSON formats (`tests/scripts/generated/xrp/signatures.json`)

The payment JSON is currently hardcoded in the script. If you want to test with your own transaction, you can modify it directly in the script.

## Generated Files

The scripts generate several files with intermidiate and final results:

- `tests/scripts/generated/node_info.json`: Contains TEE node IDs and public keys
- `tests/scripts/generated/active_policy.json`: Contains the current policy information including epoch ID
- `tests/scripts/generated/xrp/addresses.txt`: Stores the XRP addresses for each TEE node
- `tests/scripts/generated/xrp/signatures.txt`: Human-readable format of payment signatures
- `tests/scripts/generated/xrp/signatures.json`: JSON format of payment signatures for programmatic use
