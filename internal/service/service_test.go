package service

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"strconv"
	policyv1 "tee-node/gen/go/policy/v1"
	walletsv1 "tee-node/gen/go/wallets/v1"
	utilsserver "tee-node/internal/utils"

	"tee-node/internal/policy"
	"tee-node/internal/requests"
	"tee-node/internal/wallets"
	utils "tee-node/tests"
	"testing"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestServiceEndToEnd(t *testing.T) {
	ctx := context.Background()

	go LaunchServer(50060)
	go LaunchWSServer(50061)

	clientConn, err := utils.NewGRPCClient("localhost:50060")
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

	req := &policyv1.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	policyClient := policyv1.NewPolicyServiceClient(clientConn)

	_, err = policyClient.InitializePolicy(ctx, req)
	if err != nil {
		log.Fatalf("could not initialize policy: %v", err)
	}

	// generate a new wallet
	walletName := "newWallet"
	walletClient := walletsv1.NewWalletsServiceClient(clientConn)

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

		resp, err := walletClient.NewWallet(ctx, &walletsv1.NewWalletRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes), Signature: signature})
		if err != nil {
			log.Fatalf("could not create a new wallet: %v", err)
		}

		logger.Infof("sent request to create wallet, is finalized %v, attestation token %s", resp.Finalized, resp.Token)
	}

	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	if err != nil {
		log.Fatalf("%v", err)
	}
	pubKeyResp, err := walletClient.PublicKey(ctx, &walletsv1.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
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

		resp, err := walletClient.SplitWallet(
			ctx,
			&walletsv1.SplitWalletRequest{
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

		resp, err := walletClient.RecoverWallet(
			ctx,
			&walletsv1.RecoverWalletRequest{
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
	finalPubKeyResp, err := walletClient.PublicKey(ctx, &walletsv1.PublicKeyRequest{Name: walletName, Nonce: hex.EncodeToString(nonceBytes)})
	if err != nil {
		log.Fatalf("could not create a new wallet: %v", err)
	}

	require.Equal(t, pubKeyResp.Address, finalPubKeyResp.Address)
}
