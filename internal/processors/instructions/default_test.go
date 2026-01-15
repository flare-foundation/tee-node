package instructions

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestDefaultInstructionProcessor(t *testing.T) {
	testNode, pStorage, _ := testutils.Setup(t)
	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	_, signers, privKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)
	variableMessages := make([][]byte, len(privKeys))

	extenderPort := 8612
	extensionPort := 8613

	extensionServer := testutils.NewDummyExtensionServer(extensionPort, extenderPort)
	go extensionServer.Serve()    //nolint:errcheck
	defer extensionServer.Close() //nolint:errcheck

	actionResponseChan := make(chan *types.ActionResult, 1)
	go testutils.MockExtenderServerResult(t, extenderPort, actionResponseChan)
	time.Sleep(500 * time.Millisecond)

	proc := NewDefaultProcessor(extensionPort, pStorage, testNode)

	action := testutils.BuildMockInstructionAction(
		t,
		"someOpType", "someOpCommand", []byte("dummyAction"),
		privKeys, testNode.TeeID(), epochID, nil, variableMessages, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	firstResult := proc.Process(action)

	require.Equal(t, action.Data.ID, firstResult.ID)
	require.Len(t, firstResult.Data, 0)
	require.Equal(t, uint8(2), firstResult.Status)
	require.Equal(t, "action in processing", firstResult.Log)
	require.Equal(t, action.Data.SubmissionTag, firstResult.SubmissionTag)

	finalResult := <-actionResponseChan
	require.Equal(t, action.Data.ID, finalResult.ID)
	require.Equal(t, uint8(1), finalResult.Status)
	require.Equal(t, action.Data.SubmissionTag, finalResult.SubmissionTag)

	endAction := testutils.BuildMockInstructionAction(
		t,
		"someOpType", "someOpCommand", []byte("dummyAction"),
		privKeys, testNode.TeeID(), epochID, nil, variableMessages, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	endResult := proc.Process(endAction)

	require.Equal(t, endAction.Data.ID, endResult.ID)
	require.Equal(t, uint8(1), endResult.Status)
	require.Equal(t, types.End, endResult.SubmissionTag)
	require.Equal(t, "someOpType", string(op.HashToOPType(endResult.OPType)))
	require.Equal(t, "someOpCommand", string(op.HashToOPType(endResult.OPCommand)))

	var rewardingData types.RewardingData
	err := json.Unmarshal(endResult.Data, &rewardingData)
	require.NoError(t, err)

	var instructionData instruction.DataFixed
	err = json.Unmarshal(endAction.Data.Message, &instructionData)
	require.NoError(t, err)
	instructionHash, err := instructionData.HashFixed()
	require.NoError(t, err)
	require.Equal(t, instructionHash, rewardingData.VoteSequence.InstructionHash)
	expectedVoteHash, err := voteHash(&instructionData, endAction.Signatures, endAction.AdditionalVariableMessages, signers, endAction.Timestamps)
	require.NoError(t, err)
	require.Equal(t, expectedVoteHash, rewardingData.VoteSequence.VoteHash)
	require.Equal(t, epochID, rewardingData.VoteSequence.RewardEpochID)
	require.Equal(t, testNode.TeeID(), rewardingData.VoteSequence.TeeID)
	require.Len(t, rewardingData.VoteSequence.Signatures, len(privKeys))
	require.Len(t, rewardingData.VoteSequence.AdditionalVariableMessageHashes, len(privKeys))
	require.NoError(t, utils.VerifySignature(rewardingData.VoteSequence.VoteHash[:], rewardingData.Signature, rewardingData.VoteSequence.TeeID))
}
