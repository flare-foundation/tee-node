package signinginstruction

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	"tee-node/pkg/node"
	"tee-node/pkg/policy"
	"tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	testutils "tee-node/tests"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	api "tee-node/api/types"
)

var mockWalletId = common.HexToHash("0xabcdef")
var mockKeyId = big.NewInt(1)

// Send enough signatures for the payment hash, to pass the threshold.
func TestSendManyPaymentSignatures(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId.Id, mockWalletId, mockKeyId.String(), privKeys, policy.GetActiveSigningPolicy().RewardEpochId)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)
	instruction, err := testutils.BuildMockInstruction("XRP",
		"PAY",
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{PaymentHash: paymentHash, KeyId: mockKeyId},
		privKeys[0],
		common.HexToAddress("0x1234"),
		hex.EncodeToString(instructionIdBytes),
		policy.GetActiveSigningPolicy().RewardEpochId,
	)
	require.NoError(t, err)

	response, err := SignPaymentTransaction(&instruction.Data.DataFixed)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	// todo: check response
	_ = response
}

// Query the signature before and after the threshold was reached and verify the results
func TestGetSignatureApi(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test
	err := node.InitNode()
	require.NoError(t, err)
	myNodeId := node.GetNodeId()

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, myNodeId.Id, mockWalletId, mockKeyId.String(), privKeys, policy.GetActiveSigningPolicy().RewardEpochId)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	hashBytes, _ := hex.DecodeString(paymentHash)
	// thresholdIdx := getTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instruction, err := testutils.BuildMockInstruction("XRP",
		"PAY",
		testutils.BuildMockPaymentOriginalMessage(t, mockWalletId.Hex()),
		api.SignPaymentAdditionalFixedMessage{PaymentHash: paymentHash, KeyId: mockKeyId},
		privKeys[0],
		common.HexToAddress("0x1234"),
		hex.EncodeToString(instructionIdBytes),
		policy.GetActiveSigningPolicy().RewardEpochId,
	)
	require.NoError(t, err)

	signature, err := SignPaymentTransaction(&instruction.Data.DataFixed)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	// Get the signature after the threshold was reached
	resp, err := GetPaymentSignature(&instruction.Data.DataFixed, signature)
	require.NoError(t, err)

	require.Equal(t, paymentHash, resp.PaymentHash)

	valid := verifyPaymentRequestSignature(t, hashBytes, resp.TxnSignature, mockWalletId, mockKeyId)
	if !valid {
		t.Fatalf("The signature is not valid")
	}
}

func TestSigning(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	const privKeyString = "089287075791EC70BE4A61B8768825148FF38660C00EEFDE029C0AD173610B16"

	ecdsaPrivKey, err := crypto.HexToECDSA(privKeyString)
	require.NoError(t, err)

	ecdsaPubKey := ecdsaPrivKey.Public().(*ecdsa.PublicKey)

	txnSignature := utils.XrpSign([]byte("123"), ecdsaPrivKey)

	valid, _ := utils.XrpVerifySig([]byte("123"), txnSignature, ecdsaPubKey)
	require.True(t, valid)
}

// * —————————————————————————————————————————————————————————————————————————————————————————— * //

func verifyPaymentRequestSignature(t *testing.T, paymentHash []byte, txnSignature []byte, walletId common.Hash, keyId *big.Int) bool {
	pubKey, err := wallets.GetPublicKey(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)

	valid, err := utils.XrpVerifySig(paymentHash, txnSignature, pubKey)
	require.NoError(t, err)

	return valid
}
