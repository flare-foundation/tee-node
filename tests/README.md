# Tests

## Client

Use the client to test the server

### Deploy TEE nodes

Deploy a TEE node server locally (for `gcloud` deployment configs need to be modified)

```bash
go run cmd/server/main.go --config tests/configs/config_server.toml
```

Additionally deploy two backup TEE nodes

```bash
go run cmd/server/main.go --config tests/configs/config_server_backup0.toml & go run cmd/server/main.go --config tests/configs/config_server_backup1.toml
```

### Initialize a TEE node

Then use the client with its CLI to initialize the TEE node with (simulated) initial policy with 3 data providers

```bash
go run tests/client/cmd/main.go --call initial_policy_simulate --config tests/configs/config_client.toml
```

### Create a new wallet

Use 2 out of 3 data providers to create a new wallet with unique ID `foo` and get its address:

```bash
go run tests/client/cmd/main.go --call new_wallet --arg1 0 --arg2 foo --config tests/configs/config_client.toml
go run tests/client/cmd/main.go --call new_wallet --arg1 1 --arg2 foo --config tests/configs/config_client.toml

go run tests/client/cmd/main.go --call pub_key --arg1 foo --config tests/configs/config_client.toml
```

### Back up a wallet

The last command should return the address of the generated wallet. Now backup the wallet with Shamir sharing
2 out of 2.

```bash
go run tests/client/cmd/main.go --call split_wallet --arg1 0 --arg2 foo --config tests/configs/config_client.toml
go run tests/client/cmd/main.go --call split_wallet --arg1 1 --arg2 foo --config tests/configs/config_client.toml
```

### Recover a wallet

You can now stop the TEE node with the wallet (but not the backup ones). Restart it

```bash
go run cmd/server/main.go --config tests/configs/config_server.toml
```

and initialize it again

```bash
go run tests/client/cmd/main.go --call initial_policy_simulate --config tests/configs/config_client.toml
```

and recover the wallet, by running the following commands replacing the address with the address obtained before

```bash
go run tests/client/cmd/main.go --call recover_wallet --arg1 0 --arg2 foo --arg3 0xb06023c32B5326293bccf78BFf4Be42FD9554c7a --config tests/configs/config_client.toml
go run tests/client/cmd/main.go --call recover_wallet --arg1 1 --arg2 foo --arg3 0xb06023c32B5326293bccf78BFf4Be42FD9554c7a --config tests/configs/config_client.toml
```

Check if the wallet is on the server

```bash
go run tests/client/cmd/main.go --call pub_key --arg1 foo --config tests/configs/config_client.toml
```

## Unit tests

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
