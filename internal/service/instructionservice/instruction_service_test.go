package instructionservice_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"tee-node/internal/policy"
	"tee-node/internal/service/instructionservice"
	"tee-node/internal/utils"
	"testing"

	testutils "tee-node/tests"

	api "tee-node/api/types"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const mockWallet = "wallet1"

// Send enough signatures for the payment hash, to pass the threshold.
func TestSendManyPaymentInstructions(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	_ = privKeys

	testutils.CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	instructionService := instructionservice.NewService()

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	thresholdIdx := -1
	for i := 0; i < len(privKeys); i++ {

		instruction, err := testutils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
			privKeys[i],
			"1234",
			hex.EncodeToString(instructionIdBytes),
		)
		require.NoError(t, err)

		response, err := instructionService.SendSignedInstruction(context.Background(), instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			thresholdIdx = i
			break
		}
	}

	if thresholdIdx == -1 {
		t.Fatalf("Threshold should have been reached")
	}

}

// Query the instruction result before and after the threshold was reached and verify the results
func TestGetInstructionResult(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	thresholdIdx, _ := testutils.GetTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)

	instructionService := instructionservice.NewService()

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	var instruction *api.Instruction
	var err error
	for i := 0; i < thresholdIdx; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
			privKeys[i],
			"1234",
			hex.EncodeToString(instructionIdBytes),
		)
		require.NoError(t, err)

		response, err := instructionService.SendSignedInstruction(context.Background(), instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")

		}
	}

	instructionQuery := api.InstructionResultRequest{
		Challenge:     instruction.Challenge,
		InstructionId: instruction.Data.InstructionId,
	}
	_, err = instructionService.InstructionResult(context.Background(), &instructionQuery)

	// Convert error to RPC status and  error code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected RPC error status")
	}
	if st.Code() != codes.NotFound || st.Message() != "request not finalized" {
		t.Errorf("expected NotFound, got %v", st.Code())
		t.Fatalf("expected 'request not finalized', got %v", st.Message())
	}

	// Sign the payment hash with the last voter to reach the threshold
	instruction, err = testutils.BuildMockInstruction("XRP",
		"PAY",
		api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
		privKeys[thresholdIdx],
		"1234",
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	response, err := instructionService.SendSignedInstruction(context.Background(), instruction)
	require.NoError(t, err)

	if !response.Finalized {
		t.Fatalf("Threshold should Have been reached ")
	}

	// Get the instruction result after the threshold was reached
	resp, err := instructionService.InstructionResult(context.Background(), &instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)
}

func TestGetInstructionStatus(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	thresholdIdx, thresholdWeight := testutils.GetTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)

	instructionService := instructionservice.NewService()

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	var instruction *api.Instruction
	var err error
	for i := 0; i < thresholdIdx; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
			privKeys[i],
			"1234",
			hex.EncodeToString(instructionIdBytes),
		)
		require.NoError(t, err)

		response, err := instructionService.SendSignedInstruction(context.Background(), instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")

		}
	}

	instructionQuery := api.InstructionResultRequest{
		Challenge:     instruction.Challenge,
		InstructionId: instruction.Data.InstructionId,
	}
	resp, err := instructionService.InstructionStatus(context.Background(), &instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)
	require.Equal(t, "inProgress", resp.Data.Status)
	require.Equal(t, 1, len(resp.Data.VoteResults))

	// Sign the payment hash with the last voter to reach the threshold
	instruction, err = testutils.BuildMockInstruction("XRP",
		"PAY",
		api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
		privKeys[thresholdIdx],
		"1234",
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	response, err := instructionService.SendSignedInstruction(context.Background(), instruction)
	require.NoError(t, err)

	if !response.Finalized {
		t.Fatalf("Threshold should Have been reached ")
	}

	// Get the instruction status after the threshold was reached
	resp, err = instructionService.InstructionStatus(context.Background(), &instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)
	require.Equal(t, "success", resp.Data.Status)
	require.Equal(t, 1, len(resp.Data.VoteResults))
	require.Equal(t, thresholdIdx+1, int(resp.Data.VoteResults[0].NumberOfVotes))
	require.Equal(t, thresholdWeight, resp.Data.VoteResults[0].TotalWeight)

}

func TestGetResultWithDifferentInstructionForSameId(t *testing.T) {

	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, mockWallet, privKeys)

	paymentHash1 := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	paymentHash2 := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	paymentHash3 := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	instructionService := instructionservice.NewService()

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	thresholdIdx, thresholdWeight := testutils.GetTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)

	var instruction *api.Instruction
	var err error

	// Loop up to the threshold index and sign the first payment hash
	voterWeight1 := 0
	for i := 0; i < thresholdIdx; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash1},
			privKeys[i],
			"1234",
			hex.EncodeToString(instructionIdBytes),
		)
		require.NoError(t, err)

		voterWeight1 += int(testutils.GetSignerWeight(&privKeys[i].PublicKey, policy.ActiveSigningPolicy))

		response, err := instructionService.SendSignedInstruction(context.Background(), instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")

		}
	}

	midPoint := thresholdIdx + (len(privKeys)-thresholdIdx)/2

	// Loop from the index after the treshold index up to some midpoint (leave the threshold index out)
	// and sign the second payment hash
	voterWeight2 := 0
	for i := thresholdIdx + 1; i < midPoint; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash2},
			privKeys[i],
			"1234",
			hex.EncodeToString(instructionIdBytes),
		)
		require.NoError(t, err)

		voterWeight2 += int(testutils.GetSignerWeight(&privKeys[i].PublicKey, policy.ActiveSigningPolicy))

		response, err := instructionService.SendSignedInstruction(context.Background(), instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")
		}
	}

	// Loop to the end and sign the third payment hash
	voterWeight3 := 0
	for i := midPoint; i < len(privKeys); i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash3},
			privKeys[i],
			"1234",
			hex.EncodeToString(instructionIdBytes),
		)
		require.NoError(t, err)

		voterWeight3 += int(testutils.GetSignerWeight(&privKeys[i].PublicKey, policy.ActiveSigningPolicy))

		response, err := instructionService.SendSignedInstruction(context.Background(), instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")
		}
	}

	instructionQuery := api.InstructionResultRequest{
		Challenge:     instruction.Challenge,
		InstructionId: instruction.Data.InstructionId,
	}
	resp, err := instructionService.InstructionStatus(context.Background(), &instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)

	require.Equal(t, "inProgress", resp.Data.Status)
	require.Equal(t, 3, len(resp.Data.VoteResults))

	require.Equal(t, voterWeight1, int(resp.Data.VoteResults[0].TotalWeight))
	require.Equal(t, voterWeight2, int(resp.Data.VoteResults[1].TotalWeight))
	require.Equal(t, voterWeight3, int(resp.Data.VoteResults[2].TotalWeight))

	_, err = instructionService.InstructionResult(context.Background(), &instructionQuery)

	// Convert error to RPC status and  error code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected RPC error status")
	}
	if st.Code() != codes.NotFound || st.Message() != "request not finalized" {
		t.Errorf("expected NotFound, got %v", st.Code())
		t.Fatalf("expected 'request not finalized', got %v", st.Message())
	}

	// Sign the payment hash with the last voter to reach the threshold for the first payment hash
	instruction, err = testutils.BuildMockInstruction("XRP",
		"PAY",
		api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash1},
		privKeys[thresholdIdx],
		"1234",
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	response, err := instructionService.SendSignedInstruction(context.Background(), instruction)
	require.NoError(t, err)

	if !response.Finalized {
		t.Fatalf("Threshold should have been reached")
	}

	resp2, err := instructionService.InstructionStatus(context.Background(), &instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp2.Status)
	require.Equal(t, "success", resp2.Data.Status)
	require.Equal(t, thresholdWeight, resp2.Data.VoteResults[0].TotalWeight)

	resp3, err := instructionService.InstructionResult(context.Background(), &instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp3.Status)

	var paymentSigResponse api.GetPaymentSignatureResponse
	err = json.Unmarshal(resp3.Data, &paymentSigResponse)
	if err != nil {
		log.Fatalf("could not get thepayment signature : %v", err)
	}

	require.Equal(t, paymentHash1, paymentSigResponse.PaymentHash)

}
