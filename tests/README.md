# Tests

## Client

Use the client to test the server

### Deploy TEE nodes

Deploy a TEE node server and two backup TEE nodes locally (for `gcloud` deployment configs need to be modified)

```bash
./tests/scripts/start_server.sh
```

### Initialize a TEE node

Initialize the TEE nodes with (simulated) initial policy with 3 data providers

```bash
./tests/scripts/initialize_policies.sh
```

### Create a new wallet

Use 3 data providers to create a new wallet with unique ID `foo`:

```bash
./tests/scripts/wallet/create_wallet.sh
```

### Back up a wallet

Now backup the wallet with Shamir sharing 2 out of 2 to the backup servers.

```bash
./tests/scripts/wallet/backup_wallet.sh
```

### Recover a wallet

Optionally you can now stop the TEE node with the wallet (but not the backup ones) and restart it.

Recover the wallet, by running the following commands replacing the address with the address obtained before

```bash
./tests/scripts/wallet/restore_wallet.sh
```

### Create multi-sig wallet on multiple TEE nodes

Create a new wallet with unique ID `foo` on all three nodes:

```bash
./tests/scripts/xrp/create_wallets.sh
```

### Create a transaction and sign it with a multi-sig wallet on multiple TEE nodes

```bash
./tests/scripts/xrp/sign_payment.sh
```

### Get google attestation

Get google attestation token (you must provide nonce in arg1 otherwise service fails - nonce must be between 8 and 88 bytes)

```bash
go run tests/client/cmd/main.go --call google_attestation --arg1 1234567890 --config tests/configs/config_client.toml
```

## Unit tests of client

Before running policy tests for a client, set up a database with indexed data from
coston2 blockchain. Navigate to `tests/docker` and run

```bash
docker compose up
```

This will start an indexer and a database. Wait a bit for the indexer to put some data in the database.

Now you can run a test. For the client unit test

```bash
go test -v tee-node/tests/client/policy
```
