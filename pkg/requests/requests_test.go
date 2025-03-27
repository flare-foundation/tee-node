package requests_test

import (
	"encoding/hex"
	"math/big"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	"tee-node/pkg/requests"
	"tee-node/pkg/utils"
	testutils "tee-node/tests"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var walletId = hex.EncodeToString(common.HexToHash("0xabcdef").Bytes())
var keyId = big.NewInt(1)

func TestInvalidRequestSignature(t *testing.T) {
	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	originalMessage := wallet.ITeeWalletManagerKeyGenerate{
		TeeId:    common.HexToAddress("1234"),
		WalletId: common.HexToHash(walletId),
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	instruction, err := testutils.BuildMockInstruction(
		"WALLET",
		"KEY_GENERATE",
		originalMessageEncoded,
		interface{}(nil),
		privKeys[0],
		node.GetNodeId().Id,
		hex.EncodeToString(instructionIdBytes),
		1,
	)
	require.NoError(t, err)

	wrongPrivKey, err := utils.GenerateEthereumPrivateKey()
	require.NoError(t, err)

	wrongSig, err := requests.Sign(&instruction.Data, wrongPrivKey)
	require.NoError(t, err)

	_, err = requests.CheckSignature(&instruction.Data, wrongSig, policy.ActiveSigningPolicy)

	if assert.Error(t, err) {
		assert.Equal(t, "not a voter", err.Error())
	}

}

func TestRequestCheckActive(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	sigPolicy, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	originalMessage := wallet.ITeeWalletManagerKeyGenerate{
		TeeId:    common.HexToAddress("1234"),
		WalletId: common.HexToHash(walletId),
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	instruction, err := testutils.BuildMockInstruction(
		"WALLET",
		"KEY_GENERATE",
		originalMessageEncoded,
		interface{}(nil),
		privKeys[0],
		node.GetNodeId().Id,
		hex.EncodeToString(instructionIdBytes),
		1,
	)
	require.NoError(t, err)

	// Process the request
	_, err = requests.CheckSigner(&instruction.Data, instruction.Signature)
	require.NoError(t, err)
	_, err = requests.CheckRequest(&instruction.Data)
	require.NoError(t, err)

	// Increase the reward epoch id by 1
	sigPolicy.RewardEpochId += 1

	policyBytes, _ := policy.EncodeSigningPolicy(&sigPolicy)
	policy.SetSigningPolicy(&sigPolicy, policy.SigningPolicyHash(policyBytes))

	_, err = requests.CheckRequest(&instruction.Data)
	if assert.Error(t, err) {
		assert.Equal(t, "reward epoch id too old", err.Error())
	}
}
