package signingservice

import (
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	testutils "tee-node/tests"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	api "tee-node/api/types"
)

const mockWallet = "wallet1"

// Send enough signatures for the payment hash, to pass the threshold.
func TestSendManyPaymentSignatures(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)
	instruction, err := testutils.BuildMockInstruction("XRP",
		"PAY",
		api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
		privKeys[0],
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	response, err := SignPaymentTransaction(instruction.Data)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	// todo: check response
	_ = response
}

// Query the signature before and after the threshold was reached and verify the results
func TestGetSignatureApi(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	testutils.CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	hashBytes, _ := hex.DecodeString(paymentHash)
	// thresholdIdx := getTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instruction, err := testutils.BuildMockInstruction("XRP",
		"PAY",
		api.SignPaymentRequest{WalletName: mockWallet, PaymentHash: paymentHash},
		privKeys[0],
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	signature, err := SignPaymentTransaction(instruction.Data)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	// Get the signature after the threshold was reached
	resp, err := GetPaymentSignature(instruction.Data, signature)
	require.NoError(t, err)

	require.Equal(t, paymentHash, resp.PaymentHash)

	valid := verifyPaymentRequestSignature(t, hashBytes, resp.TxnSignature, mockWallet)
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

func verifyPaymentRequestSignature(t *testing.T, paymentHash []byte, txnSignature []byte, walletName string) bool {

	pubKey, err := wallets.GetPublicKey(walletName)
	require.NoError(t, err)

	valid, err := utils.XrpVerifySig(paymentHash, txnSignature, pubKey)
	require.NoError(t, err)

	return valid
}
