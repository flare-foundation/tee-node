package signutils_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/processors/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"

	"github.com/stretchr/testify/require"
)

var mockWalletID = common.HexToHash("0xabcdef")
var mockKeyID = uint64(1)

func TestSignPaymentTransaction(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	_, _, privKeys, err := testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochID)
	require.NoError(t, err, "generating")

	testutils.CreateMockWallet(t, testNode, pStorage, wStorage, mockWalletID, mockKeyID, epochID, []*ecdsa.PrivateKey{privKeys[0]}, nil)

	instructionID, err := random.Hash()
	require.NoError(t, err)
	instructionDataFixed := instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  testNode.TeeID(),
		RewardEpochID:          epochID,
		OPType:                 op.XRP.Hash(),
		OPCommand:              op.Pay.Hash(),
		OriginalMessage:        testutils.BuildMockPaymentOriginalMessage(t, mockWalletID, testNode.TeeID(), mockKeyID),
		AdditionalFixedMessage: nil,
	}

	proc := signutils.Processor{Storage: wStorage, Identifier: testNode}

	_, _, err = proc.SignXRPLPayment(types.Threshold, &instructionDataFixed, nil, nil, nil)
	require.NoError(t, err, "response")
}
