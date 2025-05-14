package instructionservice_test

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	"tee-node/pkg/service/actionservice/governanceactions"
	"tee-node/pkg/service/actionservice/policyactions"
	"tee-node/pkg/service/instructionservice"
	"tee-node/pkg/utils"
	"testing"

	testutils "tee-node/tests"

	"tee-node/api/types"
	api "tee-node/api/types"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/registry"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = uint64(1)

// Send enough signatures for the payment hash, to pass the threshold.
func TestSendManyPaymentInstructions(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetTeeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys, nil, nil)

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
			myNodeId,
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
	myNodeId := node.GetTeeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys, nil, nil)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	thresholdIdx, _ := testutils.GetThresholdReachedVoterIndex(policy.GetActiveSigningPolicy(), privKeys)

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
			myNodeId,
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
	require.Equal(t, "request not finalized", err.Error())

	// Sign the payment hash with the last voter to reach the threshold
	instruction, err = testutils.BuildMockInstruction("XRP",
		"PAY",
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: paymentHash,
			KeyId:       mockKeyId,
		},
		privKeys[thresholdIdx],
		myNodeId,
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
	myNodeId := node.GetTeeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys, nil, nil)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	thresholdIdx, thresholdWeight := testutils.GetThresholdReachedVoterIndex(policy.GetActiveSigningPolicy(), privKeys)

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
			myNodeId,
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
		myNodeId,
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
	myNodeId := node.GetTeeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys, nil, nil)

	paymentHash1 := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	paymentHash2 := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	paymentHash3 := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	thresholdIdx, thresholdWeight := testutils.GetThresholdReachedVoterIndex(policy.GetActiveSigningPolicy(), privKeys)

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
			myNodeId,
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
			myNodeId,
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
			myNodeId,
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
	require.Equal(t, "request not finalized", err.Error())

	// Sign the payment hash with the last voter to reach the threshold for the first payment hash
	instruction, err = testutils.BuildMockInstruction("XRP",
		"PAY",
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: paymentHash1,
			KeyId:       mockKeyId,
		},
		privKeys[thresholdIdx],
		myNodeId,
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
	myNodeId := node.GetTeeId()

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
	action, err := testutils.BuildMockInitializePolicyAction(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy action: %v", err)
	}

	err = policyactions.InitializePolicy(action.Data.Message)
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
		api.UpdatePolicyAdditionalFixedMessage{
			NewPolicyRequest:       policySignaturesArray[0],
			LatestPolicyPublicKeys: pubKeys,
		},
		privKeys[0],
		myNodeId,
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
	keyId := uint64(1)
	OpType := utils.StringToOpHash("WALLET")
	adminPrivKey := crypto.ToECDSAUnsafe(big.NewInt(1).Bytes())
	adminPubKey := wallet.PublicKey{}
	copy(adminPubKey.X[:], adminPrivKey.PublicKey.X.Bytes())
	copy(adminPubKey.Y[:], adminPrivKey.PublicKey.Y.Bytes())
	pre := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    id,
		WalletId: walletId, KeyId: keyId, OpType: OpType,
		OpTypeConstants:    make([]byte, 0),
		AdminsPublicKeys:   []wallet.PublicKey{adminPubKey},
		AdminsThreshold:    1,
		Cosigners:          make([]common.Address, 0),
		CosignersThreshold: 0}

	encoded, err := abi.Arguments{arg}.Pack(pre)
	require.NoError(t, err)

	var unpacked wallet.ITeeWalletKeyManagerKeyGenerate

	err = structs.DecodeTo(arg, encoded, &unpacked)
	require.NoError(t, err)
}

func TestPauseTeeAndRejectInstructions(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	defer node.DestroyState()

	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetTeeId()

	// Setup initial policy
	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	// Create mock wallet
	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys, nil, nil)

	// Pause the TEE
	pausers, pauserPrivKeys, _ := testutils.GenerateRandomVoters(1)
	pausingNonce := governanceactions.GetTeePausingNonce()
	node.PausingAddressesStorage.TeePauserAddresses = pausers

	// Create a valid message
	validMessage := types.PauseTeeMessage{
		TeeId:        myNodeId,
		PausingNonce: pausingNonce,
	}

	// Create a valid signature
	messageHash, err := validMessage.Hash()
	require.NoError(t, err)

	signature, err := utils.Sign(messageHash[:], pauserPrivKeys[0])
	require.NoError(t, err)

	// Test successful pause
	err = governanceactions.Pause(validMessage, [][]byte{signature})
	require.NoError(t, err)
	assert.NotNil(t, pausingNonce)

	// Verify TEE is paused
	require.True(t, governanceactions.IsTeePaused())

	// Try to send an instruction while TEE is paused
	instructionIdBytes, _ := utils.GenerateRandomBytes(32)
	instruction, err := testutils.BuildMockInstruction("XRP",
		"PAY",
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4",
			KeyId:       mockKeyId,
		},
		privKeys[0],
		myNodeId,
		hex.EncodeToString(instructionIdBytes),
		policy.GetActiveSigningPolicy().RewardEpochId,
	)
	require.NoError(t, err)

	// Attempt to send instruction should fail because TEE is paused
	_, err = instructionservice.SendSignedInstruction(instruction)
	require.Error(t, err)
	require.Equal(t, err.Error(), "TEE is paused")
}
