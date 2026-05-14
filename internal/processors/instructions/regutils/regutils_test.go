package regutils

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestValidateTeeAttestationRequestSuccess(t *testing.T) {
	expectedTeeID := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	challengeHash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	req := buildTeeAttestationRequest(expectedTeeID, [32]byte(challengeHash))

	encoded, err := types.EncodeTeeAttestationRequest(&req)
	require.NoError(t, err)

	challenge, err := ValidateTeeAttestationRequest([]byte(encoded), expectedTeeID)
	require.NoError(t, err)
	require.Equal(t, [32]byte(challengeHash), challenge)
}

func TestValidateTeeAttestationRequestDecodeError(t *testing.T) {
	expectedTeeID := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	challenge, err := ValidateTeeAttestationRequest([]byte("invalid"), expectedTeeID)
	require.Error(t, err)
	require.Equal(t, [32]byte{}, challenge)
}

func TestValidateTeeAttestationRequestMismatchedTeeID(t *testing.T) {
	actualTeeID := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	expectedTeeID := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	challengeHash := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	req := buildTeeAttestationRequest(actualTeeID, [32]byte(challengeHash))

	encoded, err := types.EncodeTeeAttestationRequest(&req)
	require.NoError(t, err)

	_, err = ValidateTeeAttestationRequest([]byte(encoded), expectedTeeID)
	require.ErrorContains(t, err, "TeeIds do not match")
}

func TestValidateTeeAttestationRequestEmptyChallenge(t *testing.T) {
	teeID := common.HexToAddress("0x00000000000000000000000000000000000000aa")

	req := buildTeeAttestationRequest(teeID, [32]byte{})

	encoded, err := types.EncodeTeeAttestationRequest(&req)
	require.NoError(t, err)

	_, err = ValidateTeeAttestationRequest([]byte(encoded), teeID)
	require.ErrorContains(t, err, "challenge not given")
}

func TestProcessorTEEAttestationThreshold(t *testing.T) {
	proc, dataFixed, challenge := setupTEEAttestationProcessor(t)

	responseBytes, signature, err := proc.TEEAttestation(context.Background(), types.Threshold, &dataFixed, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, responseBytes)
	require.Nil(t, signature)

	var response types.TeeInfoResponse
	require.NoError(t, json.Unmarshal(responseBytes, &response))

	nodeInfo := proc.Info()
	state, err := nodeInfo.State.State()
	require.NoError(t, err)

	require.Equal(t, common.Hash(challenge), response.TeeInfo.Challenge)
	require.Equal(t, nodeInfo.PublicKey, response.TeeInfo.PublicKey)
	require.Equal(t, state, response.TeeInfo.State)

	initialID, initialHash, activeID, activeHash := proc.pStorage.Info()
	require.Equal(t, initialID, response.TeeInfo.InitialSigningPolicyID)
	require.Equal(t, initialHash, response.TeeInfo.InitialSigningPolicyHash)
	require.Equal(t, activeID, response.TeeInfo.LastSigningPolicyID)
	require.Equal(t, activeHash, response.TeeInfo.LastSigningPolicyHash)

	require.NotZero(t, response.TeeInfo.TeeTimestamp)
	require.Equal(t, attestation.MagicPass, response.Attestation)
}

func TestProcessorTEEAttestationEnd(t *testing.T) {
	proc, dataFixed, _ := setupTEEAttestationProcessor(t)

	responseBytes, signature, err := proc.TEEAttestation(context.Background(), types.End, &dataFixed, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, responseBytes)
	require.Nil(t, signature)
}

func TestProcessorTEEAttestationUnexpectedTag(t *testing.T) {
	proc, dataFixed, _ := setupTEEAttestationProcessor(t)

	_, _, err := proc.TEEAttestation(context.Background(), types.SubmissionTag("unexpected"), &dataFixed, nil, nil, nil)
	require.ErrorContains(t, err, "unexpected submission tag")
}

func TestProcessorTEEAttestationValidationError(t *testing.T) {
	proc, _, _ := setupTEEAttestationProcessor(t)

	badData := instruction.DataFixed{OriginalMessage: []byte("bad payload")}

	_, _, err := proc.TEEAttestation(context.Background(), types.Threshold, &badData, nil, nil, nil)
	require.Error(t, err)
}

func buildTeeAttestationRequest(teeID common.Address, challenge [32]byte) verification.IVerificationTeeAttestation {
	return verification.IVerificationTeeAttestation{
		TeeMachine: verification.IMachineManagerTeeMachineWithAttestationData{
			TeeId:        teeID,
			InitialTeeId: common.HexToAddress("0x00000000000000000000000000000000000000cc"),
			Url:          "https://example.com/tee",
			CodeHash:     [32]byte(common.HexToHash("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")),
			Platform:     [32]byte(common.HexToHash("0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
		},
		Challenge: challenge,
	}
}

func setupTEEAttestationProcessor(t *testing.T) (*Processor, instruction.DataFixed, [32]byte) {
	t.Helper()

	testNode, pStorage, _ := testutils.Setup(t)

	const (
		numVoters = 5
		randSeed  = int64(98765)
		epochID   = uint32(3)
	)

	testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)

	processor := NewProcessor(testNode, pStorage)

	teeID := testNode.TeeID()
	challengeHash := common.HexToHash("0x11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff")

	request := buildTeeAttestationRequest(teeID, [32]byte(challengeHash))
	encodedRequest, err := types.EncodeTeeAttestationRequest(&request)
	require.NoError(t, err)

	dataFixed := instruction.DataFixed{
		InstructionID:   common.HexToHash("0x7777777777777777777777777777777777777777777777777777777777777777"),
		TeeID:           teeID,
		RewardEpochID:   epochID,
		OPType:          op.Reg.Hash(),
		OPCommand:       op.TEEAttestation.Hash(),
		OriginalMessage: encodedRequest,
	}

	return &processor, dataFixed, [32]byte(challengeHash)
}
