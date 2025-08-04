package policy

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/stretchr/testify/require"
)

var params = &PolicyHistoryParams{
	RelayContractAddress:              common.HexToAddress("0x5A0773Ff307Bf7C71a832dBB5312237fD3437f9F"),
	FlareSystemManagerContractAddress: common.HexToAddress("0xa4bcDF64Cdd5451b6ac3743B414124A6299B65FF"),
	FlareVoterRegistryContractAddress: common.HexToAddress("0xB00cC45B4a7d3e1FEE684cFc4417998A1c183e6d"),
}

// TestFetchPolicyHistory assumes that a DB with indexed txs and logs
// needed to obtain policies.
func TestFetchPolicyHistory(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "db", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	_, _, err = FetchPolicyHistory(context.Background(), params, db)
	require.NoError(t, err)
}

func TestPublicKeys(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "db", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	params := PolicyHistoryParams{
		RelayContractAddress:              common.HexToAddress("0x97702e350CaEda540935d92aAf213307e9069784"),
		FlareSystemManagerContractAddress: common.HexToAddress("0xA90Db6D10F856799b10ef2A77EBCbF460aC71e52"),
		FlareVoterRegistryContractAddress: common.HexToAddress("0xB00cC45B4a7d3e1FEE684cFc4417998A1c183e6d"),
	}

	rewardEpochId := uint32(1)
	minBlockNum, maxBlockNum, err := FetchVoterRegisteredBlocksInfo(context.Background(), &params, db, rewardEpochId)
	require.NoError(t, err)

	_, err = FetchVotersPublicKeysMap(context.Background(), &params, db, minBlockNum, maxBlockNum, rewardEpochId)
	require.NoError(t, err)
}
