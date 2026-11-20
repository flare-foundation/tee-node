package instructions

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	cpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
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
		require.Equal(t, op.Type("someOpType").Hash(), res.OPType)
		require.Equal(t, op.Command("someOpCommand").Hash(), res.OPCommand)
	})

	t.Run("DefaultProcessor", func(t *testing.T) {
		proc := NewDefaultProcessor(0, pStorage, testNode)
		res := proc.Process(context.Background(), action)
		require.Equal(t, uint8(0), res.Status)
		require.Equal(t, "chainID not set", res.Log)
		require.Equal(t, op.Type("someOpType").Hash(), res.OPType)
		require.Equal(t, op.Command("someOpCommand").Hash(), res.OPCommand)
	})
}

// TestProcessorAcceptsInstructionOncePerTag checks that an instruction is
// processed once at threshold and then once at end, and that an action failing
// authentication does not use up the instruction's ID.
func TestProcessorAcceptsInstructionOncePerTag(t *testing.T) {
	testNode, pStorage, _ := testutils.Setup(t)
	epochID := uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(t, testutils.DefaultTestChainID, pStorage, 100, 12345, epochID)

	calls := 0
	handler := func(context.Context, types.SubmissionTag, *instruction.DataFixed, []hexutil.Bytes, []common.Address, *cpolicy.SigningPolicy) ([]byte, []byte, error) {
		calls++
		return []byte("done"), nil, nil
	}
	proc := NewProcessor(handler, testNode, pStorage, true)

	threshold := testutils.BuildMockInstructionAction(
		t,
		"someOpType", "someOpCommand", []byte("dummyAction"),
		privKeys, testutils.DefaultTestChainID, testNode.TeeID(), epochID,
		nil, make([][]byte, len(privKeys)), nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)

	// Signed by one provider only: below the threshold.
	underSigned := *threshold
	underSigned.Signatures = threshold.Signatures[:1]
	underSigned.AdditionalVariableMessages = threshold.AdditionalVariableMessages[:1]
	underSigned.Timestamps = threshold.Timestamps[:1]
	res := proc.Process(context.Background(), &underSigned)
	require.Equal(t, uint8(0), res.Status)
	require.Equal(t, "data providers threshold not reached", res.Log)

	// End before the threshold.
	end := testutils.EndAction(threshold)
	res = proc.Process(context.Background(), end)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "not accepted with submission tag threshold")

	res = proc.Process(context.Background(), threshold)
	require.Equal(t, uint8(1), res.Status, res.Log)

	res = proc.Process(context.Background(), threshold)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "already accepted with submission tag threshold")

	res = proc.Process(context.Background(), end)
	require.Equal(t, uint8(1), res.Status, res.Log)

	res = proc.Process(context.Background(), end)
	require.Equal(t, uint8(0), res.Status)
	require.Contains(t, res.Log, "already accepted with submission tag end")

	require.Equal(t, 2, calls)
}
