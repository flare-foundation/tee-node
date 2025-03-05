package requests_test

import (
	"encoding/hex"
	"tee-node/internal/config"
	"tee-node/internal/policy"
	"tee-node/internal/requests"
	"tee-node/internal/utils"
	testutils "tee-node/tests"
	"testing"

	api "tee-node/api/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const walletName = "wallet1"

func TestInvalidRequestSignature(t *testing.T) {

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instruction, err := testutils.BuildMockInstruction(
		"WALLET",
		"KEY_GENERATE",
		api.NewWalletRequest{Name: walletName},
		privKeys[0],
		"1234",
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	wrongPrivKey, err := utils.GenerateEthereumPrivateKey()
	require.NoError(t, err)

	wrongSig, err := requests.Sign(instruction.Data, wrongPrivKey)
	require.NoError(t, err)

	_, err = requests.CheckSignature(instruction.Data, wrongSig, policy.ActiveSigningPolicy)

	if assert.Error(t, err) {
		assert.Equal(t, "not a voter", err.Error())
	}

}

func TestRequestCheckActive(t *testing.T) {

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	sigPolicy, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instruction, err := testutils.BuildMockInstruction(
		"WALLET",
		"KEY_GENERATE",
		api.NewWalletRequest{Name: walletName},
		privKeys[0],
		"1234",
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	// Process the request
	_, _, err = requests.ProcessRequest(*instruction.Data, instruction.Signature)
	require.NoError(t, err)

	// Increase the reward epoch id by config.ACTIVE_POLICY_COUNT (should pass)
	for i := 0; i < config.ACTIVE_POLICY_COUNT; i++ {
		sigPolicy.RewardEpochId += 1

		policyBytes, _ := policy.EncodeSigningPolicy(&sigPolicy)
		policy.SetSigningPolicy(&sigPolicy, policy.SigningPolicyHash(policyBytes))
	}

	_, _, err = requests.ProcessRequest(*instruction.Data, instruction.Signature)
	require.NoError(t, err)

	// Increase the reward epoch id by 1 (should fail)
	sigPolicy.RewardEpochId += 1

	policyBytes, _ := policy.EncodeSigningPolicy(&sigPolicy)
	policy.SetSigningPolicy(&sigPolicy, policy.SigningPolicyHash(policyBytes))

	_, _, err = requests.ProcessRequest(*instruction.Data, instruction.Signature)
	if assert.Error(t, err) {
		assert.Equal(t, "not active", err.Error())
	}

}
