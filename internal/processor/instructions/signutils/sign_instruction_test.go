package signutils_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"

	"github.com/stretchr/testify/require"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = uint64(1)

// Send enough signatures for the payment hash, to pass the threshold.
func TestSignPaymentTransaction(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode(node.ZeroState{})
	require.NoError(t, err)
	myNodeId := node.TeeID()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys, err := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)
	require.NoError(t, err, "generating")

	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, epochId, []*ecdsa.PrivateKey{privKeys[0]}, nil)

	instructionId, err := utils.GenerateRandom()
	require.NoError(t, err)
	instructionDataFixed := instruction.DataFixed{
		InstructionID:          instructionId,
		TeeID:                  myNodeId,
		RewardEpochID:          epochId,
		OPType:                 op.XRP.Hash(),
		OPCommand:              op.Pay.Hash(),
		OriginalMessage:        testutils.BuildMockPaymentOriginalMessage(t, mockWalletId, myNodeId, mockKeyId),
		AdditionalFixedMessage: nil,
	}

	_, err = signutils.SignPaymentTransaction(&instructionDataFixed, nil)
	require.NoError(t, err, "response")
}
