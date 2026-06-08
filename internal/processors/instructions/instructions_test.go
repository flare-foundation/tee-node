package instructions

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/processorutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestSignaturesToSignersBindsChainID checks that signer recovery is bound to
// the chain ID, so signatures cannot be replayed across chains.
func TestSignaturesToSignersBindsChainID(t *testing.T) {
	const chainID = uint64(31337)

	const numSigners = 5
	privKeys := make([]*ecdsa.PrivateKey, numSigners)
	expected := make([]common.Address, numSigners)
	for i := range privKeys {
		pk, err := crypto.GenerateKey()
		require.NoError(t, err)
		privKeys[i] = pk
		expected[i] = crypto.PubkeyToAddress(pk.PublicKey)
	}

	// Non-empty, so the action's AdditionalVariableMessages align with the signatures.
	variableMessages := make([][]byte, numSigners)

	action := testutils.BuildMockInstructionAction(
		t,
		"someOpType", "someOpCommand", []byte("dummyAction"),
		privKeys, chainID, common.Address{}, uint32(1),
		nil, variableMessages, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)

	data, err := processorutils.Parse[instruction.DataFixed](action.Data.Message)
	require.NoError(t, err)

	// Correct chain ID recovers the signers, in signature order.
	recovered, err := signaturesToSigners(data, chainID, action.AdditionalVariableMessages, action.Signatures)
	require.NoError(t, err)
	require.Equal(t, expected, recovered)

	// A different chain ID recovers different addresses.
	otherChain, err := signaturesToSigners(data, chainID+1, action.AdditionalVariableMessages, action.Signatures)
	require.NoError(t, err)
	require.NotEqual(t, recovered, otherChain)
	for _, addr := range otherChain {
		require.NotContains(t, expected, addr)
	}
}

// TestProcessorsRejectUnsetChainID checks that both processors fail closed when
// the node has no chain ID configured.
func TestProcessorsRejectUnsetChainID(t *testing.T) {
	testNode, pStorage, _ := testutils.Setup(t, testutils.WithoutChainID())

	// Precondition: node reports no chain ID.
	_, err := testNode.ChainID()
	require.Error(t, err)

	// Valid action; processing must stop at the chain-ID lookup, so its
	// signatures are irrelevant.
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	action := testutils.BuildMockInstructionAction(
		t,
		"someOpType", "someOpCommand", []byte("dummyAction"),
		[]*ecdsa.PrivateKey{privKey}, uint64(31337), testNode.TeeID(), uint32(1),
		nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)

	t.Run("Processor", func(t *testing.T) {
		// nil handler is never reached: ChainID() fails first.
		proc := NewProcessor(nil, testNode, pStorage, true)
		res := proc.Process(context.Background(), action)
		require.Equal(t, uint8(0), res.Status)
		require.Equal(t, "chainID not set", res.Log)
	})

	t.Run("DefaultProcessor", func(t *testing.T) {
		proc := NewDefaultProcessor(0, pStorage, testNode)
		res := proc.Process(context.Background(), action)
		require.Equal(t, uint8(0), res.Status)
		require.Equal(t, "chainID not set", res.Log)
	})
}
