package policy

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/go-flare-common/pkg/database"

	"tee-node/pkg/config"
	pd "tee-node/pkg/policy"
	ps "tee-node/pkg/service/policyservice"
)

// TestFetchPolicyHistory assumes that a DB with indexed txs and logs
// needed to obtain policies.
func TestFetchPolicyHistory(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "flare_ftso_indexer_tee_node", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	params := PolicyHistoryParams{RelayContractAddress: common.HexToAddress("0x97702e350CaEda540935d92aAf213307e9069784"), FlareSystemManagerContractAddress: common.HexToAddress("0xA90Db6D10F856799b10ef2A77EBCbF460aC71e52")}

	policies, signatures, err := FetchPolicyHistory(context.Background(), &params, db)
	require.NoError(t, err)
	_ = policies
	_ = signatures
}

func TestPolicyDecodingEncoding(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "flare_ftso_indexer_tee_node", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	params := PolicyHistoryParams{RelayContractAddress: common.HexToAddress("0x97702e350CaEda540935d92aAf213307e9069784"), FlareSystemManagerContractAddress: common.HexToAddress("0xA90Db6D10F856799b10ef2A77EBCbF460aC71e52")}

	policies, _, err := FetchPolicyHistory(context.Background(), &params, db)
	require.NoError(t, err)

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
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "flare_ftso_indexer_tee_node", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	params := PolicyHistoryParams{RelayContractAddress: common.HexToAddress("0x97702e350CaEda540935d92aAf213307e9069784"), FlareSystemManagerContractAddress: common.HexToAddress("0xA90Db6D10F856799b10ef2A77EBCbF460aC71e52")}

	policies, signatures, err := FetchPolicyHistory(context.Background(), &params, db)
	require.NoError(t, err)

	req, err := CreateSigningRequest(policies, signatures)
	require.NoError(t, err)

	signingService := ps.NewService()

	config.InitialPolicyHash = hex.EncodeToString(pd.SigningPolicyHash(req.InitialPolicyBytes))

	_, err = signingService.InitializePolicy(context.Background(), req)
	require.NoError(t, err)
}
