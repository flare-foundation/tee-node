package instructionservice_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	"tee-node/pkg/service/instructionservice"
	"tee-node/pkg/service/policyservice"
	"tee-node/pkg/utils"
	"testing"

	testutils "tee-node/tests"

	api "tee-node/api/types"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/registry"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = big.NewInt(1)

// Send enough signatures for the payment hash, to pass the threshold.
func TestSendManyPaymentInstructions(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId.Id, mockWalletId, mockKeyId.String(), privKeys, policy.GetActiveSigningPolicy().RewardEpochId)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	thresholdIdx := -1
	for i := 0; i < len(privKeys); i++ {

		instruction, err := testutils.BuildMockInstruction("XRP",
			"PAY",
			testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash,
				KeyId:       mockKeyId,
			},
			privKeys[i],
			myNodeId.Id,
			hex.EncodeToString(instructionIdBytes),
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		require.NoError(t, err)

		response, err := instructionservice.SendSignedInstruction(instruction)

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
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId.Id, mockWalletId, mockKeyId.String(), privKeys, policy.GetActiveSigningPolicy().RewardEpochId)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	thresholdIdx, _ := testutils.GetTresholdRechedVoterIndex(policy.GetActiveSigningPolicy(), privKeys)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	var instruction *instruction.Instruction

	for i := 0; i < thresholdIdx; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash,
				KeyId:       mockKeyId,
			}, privKeys[i],
			myNodeId.Id,
			hex.EncodeToString(instructionIdBytes),
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		require.NoError(t, err)

		response, err := instructionservice.SendSignedInstruction(instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")

		}
	}

	instructionQuery := api.InstructionResultRequest{
		Challenge:     instruction.Challenge.String(),
		InstructionId: hex.EncodeToString(instruction.Data.InstructionID[:]),
	}
	_, err = instructionservice.InstructionResult(&instructionQuery)

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
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: paymentHash,
			KeyId:       mockKeyId,
		},
		privKeys[thresholdIdx],
		myNodeId.Id,
		hex.EncodeToString(instructionIdBytes),
		policy.GetActiveSigningPolicy().RewardEpochId,
	)
	require.NoError(t, err)

	response, err := instructionservice.SendSignedInstruction(instruction)
	require.NoError(t, err)

	if !response.Finalized {
		t.Fatalf("Threshold should Have been reached ")
	}

	// Get the instruction result after the threshold was reached
	resp, err := instructionservice.InstructionResult(&instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)
}

func TestGetInstructionStatus(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId.Id, mockWalletId, mockKeyId.String(), privKeys, policy.GetActiveSigningPolicy().RewardEpochId)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	thresholdIdx, thresholdWeight := testutils.GetTresholdRechedVoterIndex(policy.GetActiveSigningPolicy(), privKeys)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	var instruction *instruction.Instruction
	for i := 0; i < thresholdIdx; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash,
				KeyId:       mockKeyId,
			},
			privKeys[i],
			myNodeId.Id,
			hex.EncodeToString(instructionIdBytes),
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		require.NoError(t, err)

		response, err := instructionservice.SendSignedInstruction(instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")

		}
	}

	instructionQuery := api.InstructionResultRequest{
		Challenge:     instruction.Challenge.String(),
		InstructionId: hex.EncodeToString(instruction.Data.InstructionID[:]),
	}
	resp, err := instructionservice.InstructionStatus(&instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)
	require.Equal(t, "inProgress", resp.Data.Status)
	require.Equal(t, 1, len(resp.Data.VoteResults))

	// Sign the payment hash with the last voter to reach the threshold
	instruction, err = testutils.BuildMockInstruction("XRP",
		"PAY",
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: paymentHash,
			KeyId:       mockKeyId,
		},
		privKeys[thresholdIdx],
		myNodeId.Id,
		hex.EncodeToString(instructionIdBytes),
		policy.GetActiveSigningPolicy().RewardEpochId,
	)
	require.NoError(t, err)

	response, err := instructionservice.SendSignedInstruction(instruction)
	require.NoError(t, err)

	if !response.Finalized {
		t.Fatalf("Threshold should Have been reached ")
	}

	// Get the instruction status after the threshold was reached
	resp, err = instructionservice.InstructionStatus(&instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)
	require.Equal(t, "success", resp.Data.Status)
	require.Equal(t, 1, len(resp.Data.VoteResults))
	require.Equal(t, thresholdIdx+1, int(resp.Data.VoteResults[0].NumberOfVotes))
	require.Equal(t, thresholdWeight, resp.Data.VoteResults[0].TotalWeight)

}

func TestGetResultWithDifferentInstructionForSameId(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId.Id, mockWalletId, mockKeyId.String(), privKeys, policy.GetActiveSigningPolicy().RewardEpochId)

	paymentHash1 := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	paymentHash2 := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	paymentHash3 := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	thresholdIdx, thresholdWeight := testutils.GetTresholdRechedVoterIndex(policy.GetActiveSigningPolicy(), privKeys)

	var instruction *instruction.Instruction
	// Loop up to the threshold index and sign the first payment hash
	voterWeight1 := 0
	for i := 0; i < thresholdIdx; i++ {
		instruction, err = testutils.BuildMockInstruction("XRP",
			"PAY",
			testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash1,
				KeyId:       mockKeyId,
			},
			privKeys[i],
			myNodeId.Id,
			hex.EncodeToString(instructionIdBytes),
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		require.NoError(t, err)

		voterWeight1 += int(testutils.GetSignerWeight(&privKeys[i].PublicKey, policy.GetActiveSigningPolicy()))

		response, err := instructionservice.SendSignedInstruction(instruction)

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
			testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash2,
				KeyId:       mockKeyId,
			},
			privKeys[i],
			myNodeId.Id,
			hex.EncodeToString(instructionIdBytes),
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		require.NoError(t, err)

		voterWeight2 += int(testutils.GetSignerWeight(&privKeys[i].PublicKey, policy.GetActiveSigningPolicy()))

		response, err := instructionservice.SendSignedInstruction(instruction)

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
			testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash3,
				KeyId:       mockKeyId,
			},
			privKeys[i],
			myNodeId.Id,
			hex.EncodeToString(instructionIdBytes),
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		require.NoError(t, err)

		voterWeight3 += int(testutils.GetSignerWeight(&privKeys[i].PublicKey, policy.GetActiveSigningPolicy()))

		response, err := instructionservice.SendSignedInstruction(instruction)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.Finalized {
			t.Fatalf("Threshold should not be reached yet")
		}
	}

	instructionQuery := api.InstructionResultRequest{
		Challenge:     instruction.Challenge.String(),
		InstructionId: hex.EncodeToString(instruction.Data.InstructionID[:]),
	}
	resp, err := instructionservice.InstructionStatus(&instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp.Status)

	require.Equal(t, "inProgress", resp.Data.Status)
	require.Equal(t, 3, len(resp.Data.VoteResults))

	require.Equal(t, voterWeight1, int(resp.Data.VoteResults[0].TotalWeight))
	require.Equal(t, voterWeight2, int(resp.Data.VoteResults[1].TotalWeight))
	require.Equal(t, voterWeight3, int(resp.Data.VoteResults[2].TotalWeight))

	_, err = instructionservice.InstructionResult(&instructionQuery)

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
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: paymentHash1,
			KeyId:       mockKeyId,
		},
		privKeys[thresholdIdx],
		myNodeId.Id,
		hex.EncodeToString(instructionIdBytes),
		policy.GetActiveSigningPolicy().RewardEpochId,
	)
	require.NoError(t, err)

	response, err := instructionservice.SendSignedInstruction(instruction)
	require.NoError(t, err)

	if !response.Finalized {
		t.Fatalf("Threshold should have been reached")
	}

	resp2, err := instructionservice.InstructionStatus(&instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp2.Status)
	require.Equal(t, "success", resp2.Data.Status)
	require.Equal(t, thresholdWeight, resp2.Data.VoteResults[0].TotalWeight)

	resp3, err := instructionservice.InstructionResult(&instructionQuery)
	require.NoError(t, err)

	require.Equal(t, "OK", resp3.Status)

	var paymentSigResponse api.GetPaymentSignatureResponse
	err = json.Unmarshal(resp3.Data, &paymentSigResponse)
	if err != nil {
		log.Fatalf("could not get thepayment signature : %v", err)
	}

	require.Equal(t, paymentHash1, paymentSigResponse.PaymentHash)

}

func TestSignNewPolicy(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	epochId, randSeed := uint32(1), int64(12345)

	numVoters := 100
	_, initialPolicyBytes, voters, privKeys, pubKeys, err := testutils.GenerateRandomValidPolicyAndSigners(epochId, randSeed, numVoters)
	if err != nil {
		t.Fatalf("Failed to generate the initial policy")
	}

	// Set the initial policy hash in the config
	testutils.SetMockInitialPolicy(initialPolicyBytes)

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		NewPolicyRequests:      nil,
		LatestPolicyPublicKeys: pubKeys,
	}

	_, err = policyservice.InitializePolicy(req)
	if err != nil {
		t.Fatalf("Failed to initialize the policy: %v", err)
	}

	numPolicies := 1
	policySignaturesArray, err := testutils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, voters, privKeys, numPolicies)
	if err != nil {
		t.Fatalf("Failed to generate the policy signatures")
	}
	instructionIdBytes, _ := utils.GenerateRandomBytes(32)
	// Sign the instruction with one signer
	instruction, err := testutils.BuildMockInstruction("POLICY",
		"UPDATE_POLICY",
		// originalMessage empty for now
		[]byte{},
		// entire MultiSignedPolicy struct encoded in AdditionalFixedMessage
		api.UpdatePolicyRequest{
			NewPolicyRequest:       policySignaturesArray[0],
			LatestPolicyPublicKeys: pubKeys,
		},
		privKeys[0],
		myNodeId.Id,
		hex.EncodeToString(instructionIdBytes),
		epochId,
	)
	require.NoError(t, err)
	_, err = instructionservice.SendSignedInstruction(instruction)

	if err != nil {
		t.Fatalf("Failed to update policy: %v", err)
	}
	// * ----------------------------------------------------------------

	// prevPolicyHashString := hex.EncodeToString(policy.SigningPolicyHash(initialPolicyBytes))
	newPolicyHashString := hex.EncodeToString(policy.SigningPolicyBytesToHash(policySignaturesArray[0].PolicyBytes))
	activePolicyHash, err := policy.SigningPolicyToHash(policy.GetActiveSigningPolicy())
	require.NoError(t, err)

	require.Equal(t, newPolicyHashString, hex.EncodeToString(activePolicyHash))
}

func TestDecodeAbiInstruction(t *testing.T) {
	arg := registry.MessageArguments[registry.ToPauseForUpgrade]

	id := common.HexToAddress("6e656b69")

	pre := registry.ITeeRegistryPauseForUpgrade{TeeId: id}

	encoded, err := abi.Arguments{arg}.Pack(pre)
	require.NoError(t, err)

	var unpacked registry.ITeeRegistryPauseForUpgrade

	err = structs.DecodeTo(arg, encoded, &unpacked)
	require.NoError(t, err)

	require.Equal(t, pre, unpacked)

}

func TestDecodeAbiInstructionWallet(t *testing.T) {
	arg := wallet.MessageArguments[wallet.KeyGenerate]

	id := common.HexToAddress("6e656b69")
	walletId := [32]byte{1, 2, 3}
	keyId := big.NewInt(1)
	OpType := utils.StringToOpHash("WALLET")

	pre := wallet.ITeeWalletManagerKeyGenerate{TeeId: id, WalletId: walletId, KeyId: keyId, OpType: OpType}

	encoded, err := abi.Arguments{arg}.Pack(pre)
	require.NoError(t, err)

	var unpacked wallet.ITeeWalletManagerKeyGenerate

	err = structs.DecodeTo(arg, encoded, &unpacked)
	require.NoError(t, err)

	fmt.Println("unpacked.TeeId", unpacked.TeeId)
	fmt.Println("unpacked.WalletId", unpacked.WalletId)
	fmt.Println("unpacked.KeyId", unpacked.KeyId)
	fmt.Println("unpacked.OpType", unpacked.OpType)
}
