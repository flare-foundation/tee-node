package service

// TODO: These test now need to be adapted, because the services are only available through the InstructionService

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"strconv"

	api "tee-node/api/types"
	"tee-node/internal/node"
	utilsserver "tee-node/internal/utils"

	"tee-node/internal/policy"
	utils "tee-node/tests"
	"testing"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestServiceEndToEnd(t *testing.T) {
	err := node.InitNode()
	if err != nil {
		log.Fatalf("failed to init node: %v", err)
	}

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

	nodeId, pubKey := getNodeInfo(t, client, ctx)

	// generate a new wallet
	walletName := "newWallet"
	createWallet(t, nodeId, walletName, client, providers, ctx)
	// get address
	address := getAddress(t, walletName, client, ctx)

	// backup wallet to yourself
	ids := []string{nodeId, nodeId}
	backups := []string{"ws://localhost:50061", "ws://localhost:50061"}
	pubKeys := []string{pubKey, pubKey}
	threshold := len(backups)
	backupWallet(t, nodeId, walletName, ids, backups, pubKeys, threshold, client, providers, ctx)

	// delete wallet
	deleteWallet(t, nodeId, walletName, client, providers, ctx)

	// recover key
	recoverWallet(t, nodeId, walletName, address, ids, backups, pubKey, threshold, client, providers, ctx)

	// get recovered address
	recoveredAddress := getAddress(t, walletName, client, ctx)
	require.Equal(t, address, recoveredAddress)

	// sign transaction
	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	instructionId := signTransaction(t, nodeId, walletName, paymentHash, client, providers, ctx)
	getSignatureResult(t, instructionId, client, ctx)
}

func initializePolicy(t *testing.T, numPolicies int, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	// initialize policy
	epochId, randSeed := uint32(1), int64(12345)
	initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	require.NoError(t, err)

	policySignaturesArray, err := utils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
	require.NoError(t, err, "could not generate random policy policy")

	req := &api.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicyBytes,
		NewPolicyRequests:  policySignaturesArray,
	}

	var resp api.InitializePolicyResponse
	err = client.CallContext(ctx, &resp, "policyservice_initializePolicy", req)
	require.NoError(t, err, "could not initialize policy")
}

func createWallet(t *testing.T, nodeId, walletName string, client *rpc.Client, providers *utils.Providers, ctx context.Context) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)

	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_GENERATE",
			api.NewWalletRequest{Name: walletName},
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.CallContext(ctx, &resp, "instructionservice_sendSignedInstruction", instruction)
		require.NoError(t, err, "could not create a new wallet")

		logger.Infof("sent request to create wallet, status %v", resp.Status)
	}
}

func getNodeInfo(t *testing.T, client *rpc.Client, ctx context.Context) (string, string) {
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	var nodeResp api.GetNodeInfoResponse
	err = client.CallContext(ctx, &nodeResp, "nodeservice_getNodeInfo", &api.GetNodeInfoRequest{Nonce: hex.EncodeToString(nonceBytes)})
	require.NoError(t, err, "could not obtain node info")

	logger.Infof("NodeId: %s, attestation token %s", nodeResp.Data.Uuid, nodeResp.Token)

	return nodeResp.Data.Uuid, nodeResp.Data.EncryptionPublicKey
}

func getAddress(t *testing.T, walletName string, client *rpc.Client, ctx context.Context) string {
	instructionId, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	var pubKeyResp api.WalletInfoResponse
	err = client.CallContext(ctx, &pubKeyResp, "instructionservice_walletInfo", &api.WalletInfoRequest{Name: walletName, Challenge: hex.EncodeToString(instructionId)})
	require.NoError(t, err, "could not obtain the address")

	logger.Infof("ethAddress: %s, public key: %s, attestation token %s", pubKeyResp.EthAddress, pubKeyResp.EthPublicKey.X, pubKeyResp.Token)

	return pubKeyResp.EthAddress
}

func backupWallet(t *testing.T, nodeId, walletName string, ids, backups, pubKeys []string, threshold int, client *rpc.Client, providers *utils.Providers, ctx context.Context) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		instruction, err := utils.BuildMockInstruction("WALLET", "KEY_MACHINE_BACKUP", api.SplitWalletRequest{
			Name:       walletName,
			TeeIds:     ids,
			Hosts:      backups,
			PublicKeys: pubKeys,
			Threshold:  int64(threshold),
		}, providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.CallContext(
			ctx,
			&resp,
			"instructionservice_sendSignedInstruction",
			instruction,
		)
		require.NoError(t, err, "could not split a wallet")

		logger.Infof("sent request to split wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func deleteWallet(t *testing.T, nodeId, walletName string, client *rpc.Client, providers *utils.Providers, ctx context.Context) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		instruction, err := utils.BuildMockInstruction("WALLET", "KEY_DELETE", api.DeleteWalletRequest{
			Name: walletName,
		}, providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.CallContext(ctx, &resp, "instructionservice_sendSignedInstruction", instruction)
		require.NoError(t, err, "could not delete a wallet")

		logger.Infof("sent request to delete wallet, status %v", resp.Status)
	}

	// check that it was deleted
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	var pubKeyResp api.WalletInfoResponse
	err = client.CallContext(ctx, &pubKeyResp, "instructionservice_walletInfo", &api.WalletInfoRequest{Name: walletName, Challenge: hex.EncodeToString(nonceBytes)})
	require.Error(t, err)
}

func recoverWallet(t *testing.T, nodeId, walletName string, address string, ids, backups []string, pubKey string, threshold int, client *rpc.Client, providers *utils.Providers, ctx context.Context) {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		shareIds := make([]string, threshold)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}

		providerPrivKey := providers.PrivKeys[i]

		instruction, err := utils.BuildMockInstruction("WALLET", "KEY_MACHINE_RESTORE", api.RecoverWalletRequest{
			Name:      walletName,
			TeeIds:    ids,
			Hosts:     backups,
			ShareIds:  shareIds,
			PublicKey: pubKey,
			Address:   address,
			Threshold: int64(threshold),
		}, providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.CallContext(
			ctx,
			&resp,
			"instructionservice_sendSignedInstruction",
			instruction,
		)
		require.NoError(t, err, "could not recover a wallet")

		logger.Infof("sent request to recover wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func signTransaction(t *testing.T, nodeId, walletName, paymentHash string, client *rpc.Client, providers *utils.Providers, ctx context.Context) string {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		instruction, err := utils.BuildMockInstruction("XRP",
			"PAY",
			api.SignPaymentRequest{WalletName: walletName, PaymentHash: paymentHash},
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
		)

		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		var resp api.InstructionResponse
		err = client.CallContext(
			ctx,
			&resp,
			"instructionservice_sendSignedInstruction",
			instruction,
		)
		require.NoError(t, err, "could not recover a wallet")

		logger.Infof("sent request to sign transaction, status %v, attestation token %s", resp.Status, resp.Token)
	}

	return hex.EncodeToString(instructionId)
}

func getSignatureResult(t *testing.T, instructionId string, client *rpc.Client, ctx context.Context) {
	var resp api.InstructionResultResponse

	instruction := api.InstructionResultRequest{
		Challenge:     "blablabla",
		InstructionId: instructionId,
	}

	err := client.CallContext(
		ctx,
		&resp,
		"instructionservice_instructionResult",
		instruction,
	)
	require.NoError(t, err, "could not get a signature")

	logger.Infof("sent request to get signature of transaction, status %v, attestation token %s, result: %s", resp.Status, resp.Token, string(resp.Data))

	// todo: check signature
}
