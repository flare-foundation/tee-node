package signingservice_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"tee-node/internal/policy"
	"tee-node/internal/requests"
	"tee-node/internal/service/signingservice"
	"tee-node/internal/service/walletsservice"
	"tee-node/internal/signing"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	testutils "tee-node/tests"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	api "tee-node/api/types"
)

const mockWallet = "wallet1"

// Send enough signatures for the payment hash, to pass the threshold.
func TestSendManyPaymentSignatures(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	_ = privKeys

	CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	sigReq, err := signing.NewSignPaymentRequest(mockWallet, paymentHash)
	require.NoError(t, err)

	signingService := signingservice.NewService()

	hashBytes, _ := hex.DecodeString(paymentHash)
	thresholdIdx := -1
	for i := 0; i < len(privKeys); i++ {
		req, err := buildPaymentTxRequest(t, mockWallet, hashBytes, privKeys[i], &sigReq)
		require.NoError(t, err)

		response, err := signingService.SignPaymentTransaction(context.Background(), req)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.ThresholdReached {
			thresholdIdx = i
			break
		}
	}

	if thresholdIdx == -1 {
		t.Fatalf("Threshold should have been reached")
	}

}

// Query the signature before and after the threshold was reached and verify the results
func TestGetSignatureApi(t *testing.T) {
	defer testutils.ResetTEEState() // Reset the state of the TEE after the test

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	CreateMockWallet(t, mockWallet, privKeys)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"

	sigReq, err := signing.NewSignPaymentRequest(mockWallet, paymentHash)
	require.NoError(t, err)

	signingService := signingservice.NewService()

	hashBytes, _ := hex.DecodeString(paymentHash)
	thresholdIdx := getTresholdRechedVoterIndex(policy.ActiveSigningPolicy, privKeys)
	for i := 0; i < thresholdIdx; i++ {
		req, err := buildPaymentTxRequest(t, mockWallet, hashBytes, privKeys[i], &sigReq)
		require.NoError(t, err)

		response, err := signingService.SignPaymentTransaction(context.Background(), req)

		if err != nil {
			t.Fatalf("Failed to sign the payment transaction: %v", err)
		}

		if response.ThresholdReached {
			t.Fatalf("Threshold should not be reached yet")

		}
	}

	// Get the signature before the threshold was reached
	nonceBytes, _ := utils.GenerateRandomBytes(32)
	req := &api.GetPaymentSignatureRequest{
		WalletName:  mockWallet,
		PaymentHash: paymentHash,
		Challenge:   hex.EncodeToString(nonceBytes),
	}

	_, err = signingService.GetPaymentSignature(context.Background(), req)

	// Convert error to RPC status and  error code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC error status")
	}
	if st.Code() != codes.NotFound || st.Message() != "request uncompleted" {
		t.Errorf("expected NotFound, got %v", st.Code())
		t.Errorf("expected 'request uncompleted', got %v", st.Message())
	}

	// Sign the payment hash with the last voter to reach the threshold
	req2, err := buildPaymentTxRequest(t, mockWallet, hashBytes, privKeys[thresholdIdx], &sigReq)
	require.NoError(t, err)

	response, err := signingService.SignPaymentTransaction(context.Background(), req2)
	require.NoError(t, err)

	if !response.ThresholdReached {
		t.Fatalf("Threshold should Have been reached ")
	}

	// Get the signature after the threshold was reached
	resp, err := signingService.GetPaymentSignature(context.Background(), req)
	require.NoError(t, err)

	valid := VerifyRequestSignature(t, hashBytes, resp.TxnSignature, mockWallet)
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

func VerifyRequestSignature(t *testing.T, paymentHash []byte, txnSignature []byte, walletName string) bool {

	pubKey, err := wallets.GetPublicKey(walletName)
	require.NoError(t, err)

	valid, err := utils.XrpVerifySig(paymentHash, txnSignature, pubKey)
	require.NoError(t, err)

	return valid
}

func CreateMockWallet(t *testing.T, walletName string, privKeys []*ecdsa.PrivateKey) {
	newWalletRequest := wallets.NewNewWalletRequest(walletName)

	walletService := walletsservice.NewService()

	for _, privKey := range privKeys {
		signature, err := requests.Sign(newWalletRequest, privKey)
		require.NoError(t, err)

		nonceBytes, err := utils.GenerateRandomBytes(32)
		require.NoError(t, err)

		// _, err = wallets.NewWallet(walletName, hex.EncodeToString(nonceBytes), signature)
		// require.NoError(t, err)

		req := &api.NewWalletRequest{
			Name:      walletName,
			Nonce:     hex.EncodeToString(nonceBytes),
			Signature: signature,
		}

		resp, err := walletService.NewWallet(context.Background(), req)

		require.NoError(t, err)

		if resp.Finalized {
			break
		}
	}
}

func buildPaymentTxRequest(t *testing.T, walletName string, hashBytes []byte, ithPrivKey *ecdsa.PrivateKey, sigReq *signing.SignPaymentRequest) (*api.SignPaymentTransactionRequest, error) {

	hashSignature, err := requests.Sign(sigReq, ithPrivKey)
	require.NoError(t, err)

	nonceBytes, _ := utils.GenerateRandomBytes(32)
	req := api.SignPaymentTransactionRequest{
		WalletName:  walletName,
		PaymentHash: hex.EncodeToString(hashBytes),
		Signature:   hashSignature,
		Challenge:   hex.EncodeToString(nonceBytes),
	}

	return &req, nil
}

// Loop through the voters and weights and calculate the total weight
// return the index of the voter at which the accumulaterd voterWeight passes the threshold
func getTresholdRechedVoterIndex(nextPolicy *policy.SigningPolicy, voterPrivKeys []*ecdsa.PrivateKey) int {

	var weightSum uint16 = 0
	for i := 0; i < len(voterPrivKeys); i++ {

		pubKey := voterPrivKeys[i].PublicKey
		voterWeight := policy.GetSignerWeight(&pubKey, nextPolicy)

		weightSum += voterWeight

		if weightSum >= nextPolicy.Threshold {
			return i
		}

	}

	return len(voterPrivKeys) - 1
}
