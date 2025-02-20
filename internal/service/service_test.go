package service

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"strconv"

	api "tee-node/api/types"
	utilsserver "tee-node/internal/utils"

	"tee-node/internal/policy"
	"tee-node/internal/requests"
	"tee-node/internal/wallets"
	utils "tee-node/tests"
	"testing"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestServiceEndToEnd(t *testing.T) {
	ctx := context.Background()

	go LaunchServer(8545)
	go LaunchWSServer(50061)

	client, err := rpc.Dial("http://0.0.0.0:8545")
	if err != nil {
		log.Fatalf("failed to create client connection: %v", err)
	}

	providersBytes, err := os.ReadFile("../../tests/test_providers.json")
	if err != nil {
		log.Fatalf("%v", err)
	}
	providers, err := utils.UnmarshalProviders(providersBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// initialize random policies
	numPolicies := 5
	initializePolicy(t, numPolicies, client, providers, ctx)

	// generate a new wallet
	walletName := "newWallet"
	createWallet(t, walletName, client, providers, ctx)

	// get address
	address := getAddress(t, walletName, client, ctx)

	// backup wallet to yourself
	backups := []string{"ws://localhost:50061", "ws://localhost:50061"}
	threshold := len(backups)
	backupWallet(t, walletName, backups, threshold, client, providers, ctx)

	// delete wallet
	deleteWallet(t, walletName, client, providers, ctx)

	// recover key
	recoverWallet(t, walletName, address, backups, threshold, client, providers, ctx)

	// get recovered address
	recoveredAddress := getAddress(t, walletName, client, ctx)

	require.Equal(t, address, recoveredAddress)
}

func initializePolicy(t *testing.T, numPolicies int, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	// initialize policy
	epochId, randSeed := uint32(1), int64(12345)
	initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	require.NoError(t, err)

	policySignaturesArray, err := utils.GenerateRandomSignNewPolicyRequestArrays(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
	require.NoError(t, err, "could not generate random policy policy")

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	var resp api.InitializePolicyResponse
	err = client.CallContext(ctx, &resp, "policyservice_initializePolicy", req)
	require.NoError(t, err, "could not initialize policy")
}

func createWallet(t *testing.T, walletName string, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	newWalletRequest := wallets.NewNewWalletRequest(walletName)
	for i := 0; i < 2; i++ {
		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(newWalletRequest, providerPrivKey)
		require.NoError(t, err)

		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		require.NoError(t, err)

		var resp api.NewWalletResponse
		err = client.CallContext(ctx, &resp, "walletsservice_newWallet", &api.NewWalletRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes), Signature: signature})
		require.NoError(t, err, "could not create a new wallet")

		logger.Infof("sent request to create wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)
	}
}

func getAddress(t *testing.T, walletName string, client *rpc.Client, ctx context.Context) string {
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	var pubKeyResp api.PublicKeyResponse
	err = client.CallContext(ctx, &pubKeyResp, "walletsservice_publicKey", &api.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
	require.NoError(t, err, "could not obtain the address")

	logger.Infof("ethAddress: %s, public key: %s, attestation token %s", pubKeyResp.EthAddress, pubKeyResp.PublicKey, pubKeyResp.Token)

	return pubKeyResp.EthAddress
}

func backupWallet(t *testing.T, walletName string, backups []string, threshold int, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	for i := 0; i < 2; i++ {
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		require.NoError(t, err)

		newSplitWalletRequest, err := wallets.NewSplitWalletRequest(walletName, make([]string, threshold), backups, threshold)
		require.NoError(t, err)

		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(newSplitWalletRequest, providerPrivKey)
		require.NoError(t, err)

		var resp api.SplitWalletResponse
		err = client.CallContext(
			ctx,
			&resp,
			"walletsservice_splitWallet",
			&api.SplitWalletRequest{
				Name:      walletName,
				TeeIds:    newSplitWalletRequest.IDs,
				Hosts:     newSplitWalletRequest.Hosts,
				Threshold: int64(newSplitWalletRequest.Threshold),
				Signature: signature,
				Nonce:     hex.EncodeToString(nonceBytes),
			},
		)
		require.NoError(t, err, "could not split a wallet")

		logger.Infof("sent request to split wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)
	}
}

func deleteWallet(t *testing.T, walletName string, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	deleteWalletRequest := wallets.NewDeleteWalletRequest(walletName)
	for i := 0; i < 2; i++ {
		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(deleteWalletRequest, providerPrivKey)
		require.NoError(t, err)

		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		require.NoError(t, err)

		var resp api.NewWalletResponse
		err = client.CallContext(ctx, &resp, "walletsservice_deleteWallet", &api.DeleteWalletRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes), Signature: signature})
		require.NoError(t, err, "could not delete a wallet")

		logger.Infof("sent request to delete wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)
	}

	// check that it was deleted
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	var pubKeyResp api.PublicKeyResponse
	err = client.CallContext(ctx, &pubKeyResp, "walletsservice_publicKey", &api.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
	require.Error(t, err)
}

func recoverWallet(t *testing.T, walletName string, address string, backups []string, threshold int, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	for i := 0; i < 2; i++ {
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		require.NoError(t, err)

		shareIds := make([]string, threshold)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}

		newRecoverWalletRequest, err := wallets.NewRecoverWalletRequest(walletName, make([]string, threshold), backups, shareIds)
		require.NoError(t, err)

		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(newRecoverWalletRequest, providerPrivKey)
		require.NoError(t, err)

		var resp api.RecoverWalletResponse
		err = client.CallContext(
			ctx,
			&resp,
			"walletsservice_recoverWallet",
			&api.RecoverWalletRequest{
				Name:      walletName,
				TeeIds:    newRecoverWalletRequest.IDs,
				Hosts:     newRecoverWalletRequest.Hosts,
				ShareIds:  newRecoverWalletRequest.ShareIds,
				Address:   address,
				Threshold: int64(threshold),
				Signature: signature,
				Nonce:     hex.EncodeToString(nonceBytes),
			},
		)
		require.NoError(t, err, "could not recover a wallet")

		logger.Infof("sent request to recover wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)
	}
}
