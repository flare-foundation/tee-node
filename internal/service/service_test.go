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

	// initialize policy
	epochId, randSeed := uint32(1), int64(12345)
	initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		log.Fatalf("%v", err)
	}

	numPolicies := 5
	policySignaturesArray, err := utils.GenerateRandomSignNewPolicyRequestArrays(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
	if err != nil {
		log.Fatalf("could not generate random policy policy: %v", err)
	}

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	var resp api.InitializePolicyResponse
	err = client.Call(&resp, "policyservice_initializePolicy", req)
	if err != nil {
		log.Fatalf("could not initialize policy: %v", err)
	}

	// generate a new wallet
	walletName := "newWallet"

	newWalletRequest := wallets.NewNewWalletRequest(walletName)

	for i := 0; i < 2; i++ {
		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(newWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		var resp api.NewWalletResponse
		err = client.CallContext(ctx, &resp, "walletsservice_newWallet", &api.NewWalletRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes), Signature: signature})
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to create wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)
	}

	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var pubKeyResp api.PublicKeyResponse
	err = client.CallContext(ctx, &pubKeyResp, "walletsservice_publicKey", &api.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
	if err != nil {
		log.Fatalf("could not create a new wallet: %v", err)
	}
	logger.Infof("public key: %s, attestation token %s", pubKeyResp.Address, pubKeyResp.Token)

	// backup wallet to yourself
	backups := []string{"ws://localhost:50061", "ws://localhost:50061"}
	numBackups := len(backups)
	for i := 0; i < 2; i++ {
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		newSplitWalletRequest, err := wallets.NewSplitWalletRequest(walletName, make([]string, numBackups), backups, numBackups)
		if err != nil {
			log.Fatalf("%v", err)
		}

		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(newSplitWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

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
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to split wallet, is finalized %v, attestation token %s", resp.Success, resp.Token)
	}

	// todo: delete key

	// recover key
	for i := 0; i < 2; i++ {
		nonceBytes, err := utilsserver.GenerateRandomBytes(32)
		if err != nil {
			log.Fatalf("%v", err)
		}

		shareIds := make([]string, numBackups)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}

		newRecoverWalletRequest, err := wallets.NewRecoverWalletRequest(walletName, make([]string, numBackups), backups, shareIds)
		if err != nil {
			log.Fatalf("%v", err)
		}

		providerPrivKey := providers.PrivKeys[i]
		signature, err := requests.Sign(newRecoverWalletRequest, providerPrivKey)
		if err != nil {
			log.Fatalf("%v", err)
		}

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
				Address:   pubKeyResp.Address,
				Threshold: int64(numBackups),
				Signature: signature,
				Nonce:     hex.EncodeToString(nonceBytes),
			},
		)
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to recover wallet, is finalized %v, attestation token %s", resp.Success, resp.Token)
	}

	nonceBytes, err = utilsserver.GenerateRandomBytes(32)
	if err != nil {
		log.Fatalf("%v", err)
	}
	var finalPubKeyResp api.PublicKeyResponse
	err = client.CallContext(ctx, &finalPubKeyResp, "walletsservice_publicKey", &api.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
	if err != nil {
		log.Fatalf("could not create a new wallet: %v", err)
	}

	require.Equal(t, pubKeyResp.Address, finalPubKeyResp.Address)
}
