package router

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	cwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestRoutID(t *testing.T) {
	tests := []struct {
		opt op.Type
		opc op.Command
	}{
		{
			opt: op.FTDC,
			opc: op.Prove,
		},
		{
			opt: "",
			opc: "",
		},
		{
			opt: "a",
			opc: "a",
		},
	}

	for j, test := range tests {
		da := testutils.BuildMockDirectAction(t, test.opt, test.opc, nil)

		rID, err := routID(da)
		require.NoError(t, err, j)

		require.Equal(t, test.opt.Hash(), rID.OPType)
		require.Equal(t, test.opc.Hash(), rID.OPCommand)
	}
}

func TestRouterDirectActionRouting(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	r := NewPMWRouter(testNode, pStorage, wStorage)

	// Create a direct action
	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEInfo, types.TeeInfoRequest{
		Challenge: common.Hash{0x1},
	})

	result := r.process(action)

	// Verify results
	require.Equal(t, uint8(1), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Equal(t, action.Data.ID, result.ID)
}

func TestRouterInstructionActionRoutingThreshold(t *testing.T) {
	// Initialize node for testing
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, providerPrivKeys, err := testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochId)
	require.NoError(t, err)

	r := NewPMWRouter(testNode, pStorage, wStorage)

	// Create an instruction action with Threshold submission tag
	teeId := testNode.TeeID()
	walletId := common.HexToHash("0xabcdef")
	keyId := uint64(1)

	numAdmins := 3
	adminPubKeys := make([]cwallet.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)

		pk := types.PubKeyToStruct(&adminPrivKeys[i].PublicKey)
		adminPubKeys[i] = cwallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	// Create a proper KeyGenerate message
	originalMessage := cwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   op.XRP.Hash(),
		ConfigConstants: cwallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminPubKeys,
			AdminsThreshold:    1,
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		},
	}

	// Encode the message properly
	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	action, err := testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyGenerate, originalMessageEncoded, providerPrivKeys, teeId,
		epochId, nil, nil, nil, 0, types.Threshold, 1234567890,
	)
	require.NoError(t, err)

	// Process the action
	result := r.process(action)

	// Verify results
	require.Equal(t, uint8(1), result.Status)
	require.Equal(t, action.Data.ID, result.ID)
	require.Equal(t, types.Threshold, result.SubmissionTag)
}

func TestRouterUnregisteredExtension(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)
	r := NewPMWRouter(testNode, pStorage, wStorage)

	// Create a direct action for an unregistered extension (no processor registered)
	action := testutils.BuildMockDirectAction(t, op.Type("UnregisteredExt"), op.Command("UnregisteredCmd"), nil)

	// Process the action - should fail
	result := r.process(action)

	// Verify failure
	require.Equal(t, uint8(0), result.Status)
	require.Contains(t, result.Log, "processor for UnregisteredExt, UnregisteredCmd not registered")
}

func TestRouterExtensionStartingWithF_NotConfigured(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)
	r := NewExtensionRouter(testNode, pStorage, wStorage, 8001)

	// Create a direct action for extension starting with F_ but not configured
	action := testutils.BuildMockDirectAction(t, op.Type("F_CustomExtension"), op.Command("CustomCommand"), nil)

	// Process the action - should fail since no processor is registered
	result := r.process(action)

	require.Equal(t, uint8(0), result.Status)
	require.Contains(t, result.Log, "invalid OPType, OPCommand pair")
}
