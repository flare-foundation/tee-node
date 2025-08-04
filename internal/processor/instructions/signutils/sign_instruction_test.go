package signutils_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/processor/instructions/signutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/op"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
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
		InstructionId:          instructionId,
		TeeId:                  myNodeId,
		RewardEpochId:          epochId,
		OpType:                 op.XRP.Hash(),
		OpCommand:              op.Pay.Hash(),
		OriginalMessage:        testutils.BuildMockPaymentOriginalMessage(t, mockWalletId, myNodeId, mockKeyId),
		AdditionalFixedMessage: nil,
	}

	// todo: check response
	_, err = signutils.SignPaymentTransaction(&instructionDataFixed, nil, nil)
	require.NoError(t, err, "response")
}

// // Query the signature before and after the threshold was reached and verify the results
// func TestGetSignatureApi(t *testing.T) {
// 	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
// 	err := node.InitNode()
// 	require.NoError(t, err)
// 	myNodeId := node.GetTeeId()

// 	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
// 	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

// 	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys[0], nil, nil)

// 	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

// 	hashBytes, _ := hex.DecodeString(paymentHash)
// 	// thresholdIdx := getTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)

// 	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

// 	instruction, err := testutils.BuildMockInstruction("XRP",
// 		"PAY",
// 		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
// 		api.SignPaymentAdditionalFixedMessage{PaymentHash: paymentHash, KeyId: mockKeyId},
// 		privKeys[0],
// 		common.HexToAddress("0x1234"),
// 		hex.EncodeToString(instructionIdBytes),
// 		policy.GetActiveSigningPolicy().RewardEpochId,
// 	)
// 	require.NoError(t, err)

// 	signature, err := SignPaymentTransaction(&instruction.Data.DataFixed)
// 	if err != nil {
// 		t.Fatalf("Failed to sign the payment transaction: %v", err)
// 	}

// 	// Get the signature after the threshold was reached
// 	resp, err := GetPaymentSignature(&instruction.Data.DataFixed, signature)
// 	require.NoError(t, err)

// 	require.Equal(t, paymentHash, resp.PaymentHash)

// 	valid := verifyPaymentRequestSignature(t, hashBytes, resp.TxnSignature, mockWalletId, mockKeyId)
// 	if !valid {
// 		t.Fatalf("The signature is not valid")
// 	}
// }

// func TestSigning(t *testing.T) {
// 	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

// 	const privKeyString = "089287075791EC70BE4A61B8768825148FF38660C00EEFDE029C0AD173610B16"

// 	ecdsaPrivKey, err := crypto.HexToECDSA(privKeyString)
// 	require.NoError(t, err)

// 	ecdsaPubKey := ecdsaPrivKey.Public().(*ecdsa.PublicKey)

// 	txnSignature := utils.XrpSign([]byte("123"), ecdsaPrivKey)

// 	valid, _ := utils.XrpVerifySig([]byte("123"), txnSignature, ecdsaPubKey)
// 	require.True(t, valid)
// }

// // * —————————————————————————————————————————————————————————————————————————————————————————— * //

// func verifyPaymentRequestSignature(t *testing.T, paymentHash []byte, txnSignature []byte, walletId common.Hash, keyId uint64) bool {
// 	pubKey, err := wallets.GetPublicKey(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
// 	require.NoError(t, err)

// 	valid, err := utils.XrpVerifySig(paymentHash, txnSignature, pubKey)
// 	require.NoError(t, err)

// 	return valid
// }

// func TestSigningPausedWallet(t *testing.T) {
// 	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
// 	err := node.InitNode()
// 	require.NoError(t, err)
// 	myNodeId := node.GetTeeId()

// 	// Setup initial policy and wallet
// 	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
// 	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

// 	testutils.CreateMockWallet(t, myNodeId, mockWalletId, mockKeyId, policy.GetActiveSigningPolicy().RewardEpochId, privKeys[0], nil, nil)

// 	// Pause the wallet
// 	wallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: mockWalletId, KeyId: mockKeyId})
// 	require.NoError(t, err)
// 	wallet.IsWalletPaused = true

// 	// Verify wallet is paused
// 	isPaused, err := walletactions.IsWalletPaused(mockWalletId, mockKeyId)
// 	require.NoError(t, err)
// 	require.True(t, isPaused)

// 	// Try to sign a payment transaction
// 	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c5"
// 	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

// 	instruction, err := testutils.BuildMockInstruction("XRP",
// 		"PAY",
// 		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
// 		api.SignPaymentAdditionalFixedMessage{PaymentHash: paymentHash, KeyId: mockKeyId},
// 		privKeys[0],
// 		common.HexToAddress("0x1234"),
// 		hex.EncodeToString(instructionIdBytes),
// 		policy.GetActiveSigningPolicy().RewardEpochId,
// 	)
// 	require.NoError(t, err)

// 	// Attempt to sign should fail
// 	_, err = SignPaymentTransaction(&instruction.Data.DataFixed)
// 	require.Error(t, err)
// 	require.Equal(t, err.Error(), "wallet is paused")
// }
