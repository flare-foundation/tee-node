# Tests

## Client

Before running policy tests for a client, set up a database with indexed data from
coston2 blockchain. Navigate to `tests/docker` and run

```bash
docker compose up
```

This will start an indexer and a database. Wait a bit for the indexer to put some data in the database.

Now you can run a test. Deploy a server using gcloud or simply locally

```bash
go run cmd/server/main.go
```

Then use client with its CLI, for example

```bash
go run tests/client/cmd/main.go --call initial_policy --config tests/configs/config_client.toml
go run tests/client/cmd/main.go --call new_wallet -arg1 new_wallet_name --config tests/configs/config_client.toml
```

For client unit test

```bash
go test -v tee-node/tests/client/policy
```
