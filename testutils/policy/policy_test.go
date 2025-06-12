package policy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/go-flare-common/pkg/database"

	api "tee-node/api/types"
	pd "tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/processor/actions/policyactions"
	"tee-node/pkg/tee/settings"
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

	policies, signatures, err := FetchPolicyHistory(context.Background(), params, db)
	require.NoError(t, err)
	_ = policies
	_ = signatures
}

func TestPolicyDecodingEncoding(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "db", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	policies, _, err := FetchPolicyHistory(context.Background(), params, db)
	require.NoError(t, err)

	require.Greater(t, len(policies), 0)

	// Test encoding and decoding of the last available policy
	policy := policies[len(policies)-1]

	signingPolicyDecoded, err := pd.DecodeSigningPolicy(policy.SigningPolicyBytes[:])
	require.NoError(t, err)

	if big.NewInt(int64(signingPolicyDecoded.RewardEpochId)).Cmp(policy.RewardEpochId) != 0 {
		t.Error("RewardEpochId mismatch", signingPolicyDecoded.RewardEpochId, policy.RewardEpochId)
	}
	require.Equal(t, signingPolicyDecoded.StartVotingRoundId, policy.StartVotingRoundId, "StartVotingRoundId mismatch")
	require.Equal(t, signingPolicyDecoded.Threshold, policy.Threshold, "Threshold mismatch")
	if signingPolicyDecoded.Seed.Cmp(policy.Seed) != 0 {
		t.Error("Seed mismatch", signingPolicyDecoded.Seed, policy.Seed)
	}

	require.Equal(t, len(signingPolicyDecoded.Voters), len(policy.Voters), "Voters length mismatch")
	require.Equal(t, len(signingPolicyDecoded.Weights), len(policy.Weights), "Weights length mismatch")
	require.Equal(t, len(signingPolicyDecoded.Voters), len(signingPolicyDecoded.Weights), "Voters and weights length mismatch")
	for i := 0; i < len(signingPolicyDecoded.Voters); i++ {
		require.Equal(t, signingPolicyDecoded.Voters[i], policy.Voters[i], "Voters mismatch on index %d", i)
		require.Equal(t, signingPolicyDecoded.Weights[i], policy.Weights[i], "Weights mismatch on index %d", i)
	}

	// Test encoding of the policy
	signingPolicyEncoded, err := pd.EncodeSigningPolicy(signingPolicyDecoded)
	require.NoError(t, err)

	require.Equal(t, len(signingPolicyEncoded), len(policy.SigningPolicyBytes), "Encoded policy length mismatch")
	for i := 0; i < len(signingPolicyEncoded); i++ {
		require.Equal(t, signingPolicyEncoded[i], policy.SigningPolicyBytes[i], "Encoded policy mismatch on index %d", i)
	}
}

func TestPolicyReplayingWithIndexerData(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "db", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	policies, signatures, err := FetchPolicyHistory(context.Background(), params, db)
	require.NoError(t, err)
	require.Greater(t, len(policies), 0)

	activePolicyRewardEpoch := int(policies[len(policies)-1].RewardEpochId.Int64())
	minBlockNum, maxBlockNum, err := FetchVoterRegisteredBlocksInfo(context.Background(), params, db, activePolicyRewardEpoch)
	require.NoError(t, err)
	pubKeysMap, err := FetchVotersPublicKeysMap(context.Background(), params, db, minBlockNum, maxBlockNum, activePolicyRewardEpoch)
	require.NoError(t, err)

	req, err := CreateInitializePolicyAction(policies, signatures, pubKeysMap)
	require.NoError(t, err)

	var decoded api.InitializePolicyRequest
	err = json.Unmarshal(req.Data.Message, &decoded)
	require.NoError(t, err)

	settings.InitialPolicyHash = hex.EncodeToString(pd.SigningPolicyBytesToHash(decoded.InitialPolicyBytes))

	err = policyactions.InitializePolicy(req.Data.Message)
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

	rewardEpochId := 1
	minBlockNum, maxBlockNum, err := FetchVoterRegisteredBlocksInfo(context.Background(), &params, db, rewardEpochId)
	require.NoError(t, err)
	_ = minBlockNum
	_ = maxBlockNum

	addressToPubKey, err := FetchVotersPublicKeysMap(context.Background(), &params, db, minBlockNum, maxBlockNum, rewardEpochId)
	require.NoError(t, err)

	_ = addressToPubKey
	fmt.Println(addressToPubKey)
}
