package service

// TODO: These test now need to be adapted, because the services are only available through the InstructionService

import (
	"context"
	"encoding/hex"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"

	api "tee-node/api/types"
	"tee-node/pkg/node"
	utilsserver "tee-node/pkg/utils"

	"tee-node/pkg/policy"
	utils "tee-node/tests"

	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

var walletId = hex.EncodeToString(common.HexToHash("0xabcdef").Bytes())
var keyId = big.NewInt(1).String()
var backupId = big.NewInt(1).String()

var hostPort = 8565
var hostUrl = "http://localhost:" + strconv.Itoa(hostPort)

func TestServiceEndToEnd(t *testing.T) {
	err := node.InitNode()
	if err != nil {
		log.Fatalf("failed to init node: %v", err)
	}

	ctx := context.Background()

	go LaunchServer(hostPort)
	go LaunchWSServer(50061)
	time.Sleep(time.Second)

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
	initializePolicy(t, numPolicies, providers, ctx)

	nodeId, pubKey := getNodeInfo(t, ctx)

	// generate a new wallet
	createWallet(t, nodeId, walletId, keyId, providers, ctx)
	// get address
	address := getAddress(t, walletId, keyId, ctx)

	// backup wallet to yourself
	ids := []string{nodeId, nodeId}
	backups := []string{"ws://localhost:50061", "ws://localhost:50061"}
	pubKeys := []string{pubKey, pubKey}
	threshold := len(backups)
	backupWallet(t, nodeId, walletId, keyId, backupId, ids, backups, pubKeys, threshold, providers, ctx)

	// delete wallet
	deleteWallet(t, nodeId, walletId, keyId, providers, ctx)

	time.Sleep(time.Second)

	// recover key
	recoverWallet(t, nodeId, walletId, keyId, backupId, address, ids, backups, pubKey, threshold, providers, ctx)

	// get recovered address
	recoveredAddress := getAddress(t, walletId, keyId, ctx)
	require.Equal(t, address, recoveredAddress)

	// sign transaction
	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	instructionId := signTransaction(t, nodeId, walletId, keyId, paymentHash, providers, ctx)
	getSignatureResult(t, instructionId, ctx)
}

func initializePolicy(t *testing.T, numPolicies int, providers *utils.Providers, ctx context.Context) {
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

	resp, err := utils.Post[api.InitializePolicyResponse](hostUrl+"/policies/initialize", req)
	require.NoError(t, err)

	logger.Infof("sent request to initialize policy, token %v", resp.Token)
}

func createWallet(t *testing.T, nodeId string, walletId string, keyId string, providers *utils.Providers, ctx context.Context) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)

	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		// TODO: keyId parameter should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(keyId, 10, 32)
		require.NoError(t, err)

		originalMessage := wallet.ITeeWalletManagerKeyGenerate{
			TeeId:    common.HexToAddress("1234"),
			WalletId: common.HexToHash(walletId),
			KeyId:    big.NewInt(int64(keyIdParsed)),
			OpType:   utilsserver.StringToOpHash("WALLET"),
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
		require.NoError(t, err)

		instruction, err := utils.BuildMockInstruction("WALLET",
			"KEY_GENERATE",
			originalMessageEncoded,
			interface{}(nil),
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
			policy.ActiveSigningPolicy.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to create wallet, status %v", resp.Status)
	}
}

func getNodeInfo(t *testing.T, ctx context.Context) (string, string) {
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	req := api.GetNodeInfoRequest{
		Nonce: hex.EncodeToString(nonceBytes),
	}
	nodeResp, err := utils.Post[api.GetNodeInfoResponse](hostUrl+"/info", req)
	require.NoError(t, err)

	logger.Infof("NodeId: %s, attestation token %s", nodeResp.Data.Id, nodeResp.Token)

	return nodeResp.Data.Id, nodeResp.Data.EncryptionPublicKey
}

func getAddress(t *testing.T, walletId, keyId string, ctx context.Context) string {
	instructionId, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	req := api.WalletInfoRequest{
		WalletId:  walletId,
		KeyId:     keyId,
		Challenge: hex.EncodeToString(instructionId),
	}
	pubKeyResp, err := utils.Post[api.WalletInfoResponse](hostUrl+"/wallet", req)
	require.NoError(t, err)

	logger.Infof("ethAddress: %s, public key: %s, attestation token %s", pubKeyResp.EthAddress, pubKeyResp.EthPublicKey.X, pubKeyResp.Token)

	return pubKeyResp.EthAddress
}

func backupWallet(t *testing.T, nodeId string, walletId string, keyId string, backupId string, ids, backups, pubKeys []string, threshold int, providers *utils.Providers, ctx context.Context) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		backupTeeMachines := make([]wallet.ITeeRegistryTeeMachineWithAttestationData, len(ids))
		for i, id := range ids {
			backupTeeMachines[i] = wallet.ITeeRegistryTeeMachineWithAttestationData{
				TeeId: common.HexToAddress(id),
				Url:   backups[i],
			}
		}
		// TODO: keyId and backupIdParsed parameter should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(keyId, 10, 32)
		require.NoError(t, err)
		backupIdParsed, err := strconv.ParseUint(backupId, 10, 32)
		require.NoError(t, err)

		originalMessage := wallet.ITeeWalletBackupManagerKeyMachineBackup{
			TeeMachine:        wallet.ITeeRegistryTeeMachineWithAttestationData{},
			WalletId:          common.HexToHash(walletId),
			KeyId:             big.NewInt(int64(keyIdParsed)),
			BackupId:          big.NewInt(int64(backupIdParsed)),
			ShamirThreshold:   big.NewInt(int64(threshold)),
			BackupTeeMachines: backupTeeMachines,
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyMachineBackup]}.Pack(originalMessage)
		require.NoError(t, err)

		additionalFixedMessage := api.SplitWalletAdditionalFixedMessage{
			PublicKeys: pubKeys,
		}
		instruction, err := utils.BuildMockInstruction(
			"WALLET",
			"KEY_MACHINE_BACKUP",
			originalMessageEncoded,
			additionalFixedMessage,
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
			policy.ActiveSigningPolicy.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to split wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func deleteWallet(t *testing.T, nodeId, walletId, keyId string, providers *utils.Providers, ctx context.Context) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]
		// TODO: keyId parameter should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(keyId, 10, 32)
		require.NoError(t, err)

		originalMessage := wallet.ITeeWalletManagerKeyDelete{
			TeeId:    common.HexToAddress("1234"),
			WalletId: common.HexToHash(walletId),
			KeyId:    big.NewInt(int64(keyIdParsed)),
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyDelete]}.Pack(originalMessage)
		require.NoError(t, err)

		instruction, err := utils.BuildMockInstruction(
			"WALLET",
			"KEY_DELETE",
			originalMessageEncoded,
			interface{}(nil),
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
			policy.ActiveSigningPolicy.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to delete wallet, status %v", resp.Status)
	}

	// check that it was deleted
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	req := api.WalletInfoRequest{
		WalletId:  walletId,
		KeyId:     keyId,
		Challenge: hex.EncodeToString(nonceBytes),
	}

	_, err = utils.Post[api.WalletInfoResponse](hostUrl+"/wallet", req)
	require.Error(t, err)
}

func recoverWallet(t *testing.T, nodeId string, walletId string, keyId string, backupId string, address string, ids []string, backups []string, pubKey string, threshold int, providers *utils.Providers, ctx context.Context) {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		shareIds := make([]string, threshold)
		for i := range shareIds {
			shareIds[i] = strconv.Itoa(i + 1)
		}

		providerPrivKey := providers.PrivKeys[i]

		backupTeeMachines := make([]wallet.ITeeRegistryTeeMachineWithAttestationData, len(backups))
		for i := range len(ids) {
			backupTeeMachines[i] = wallet.ITeeRegistryTeeMachineWithAttestationData{
				TeeId:    common.HexToAddress(nodeId),
				Owner:    common.HexToAddress("0x123"),
				Url:      backups[i],
				CodeHash: common.HexToHash("0x123"),
				Platform: common.HexToHash("0x123"),
			}
		}
		// TODO: keyId and backupIdParsed parameters should probably be big.Int or uint32
		keyIdParsed, err := strconv.ParseUint(keyId, 10, 32)
		require.NoError(t, err)
		backupIdParsed, err := strconv.ParseUint(backupId, 10, 32)
		require.NoError(t, err)

		originalMessage := wallet.ITeeWalletBackupManagerKeyMachineRestore{
			TeeMachine:        wallet.ITeeRegistryTeeMachineWithAttestationData{},
			WalletId:          common.HexToHash(walletId),
			KeyId:             big.NewInt(int64(keyIdParsed)),
			BackupId:          big.NewInt(int64(backupIdParsed)),
			OpType:            utilsserver.StringToOpHash("WALLET"),
			PublicKey:         common.Hex2Bytes(pubKey),
			BackupTeeMachines: backupTeeMachines,
		}
		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyMachineRestore]}.Pack(originalMessage)
		require.NoError(t, err)

		instruction, err := utils.BuildMockInstruction(
			"WALLET",
			"KEY_MACHINE_RESTORE",
			originalMessageEncoded,
			api.RecoverWalletRequestAdditionalFixedMessage{
				TeeIds:    ids,
				ShareIds:  shareIds,
				Address:   address,
				Threshold: int64(threshold),
			},
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
			policy.ActiveSigningPolicy.RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to recover wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func signTransaction(t *testing.T, nodeId, walletId, keyId, paymentHash string, providers *utils.Providers, ctx context.Context) string {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
			WalletId:           common.HexToHash(walletId),
			SenderAddress:      "0x123",
			RecipientAddress:   "0x456",
			Amount:             big.NewInt(1000000000),
			PaymentReference:   [32]byte{},
			Nonce:              big.NewInt(0),
			SubNonce:           big.NewInt(0),
			MaxFee:             big.NewInt(0),
			MaxFeeTolerancePPM: big.NewInt(0),
			BatchEndTs:         big.NewInt(0),
		}

		originalMessageEncoded, err := abi.Arguments{commonpayment.MessageArguments[commonpayment.Pay]}.Pack(originalMessage)
		require.NoError(t, err)

		instruction, err := utils.BuildMockInstruction("XRP",
			"PAY",
			originalMessageEncoded,
			api.SignPaymentAdditionalFixedMessage{
				PaymentHash: paymentHash,
				KeyId:       keyId,
			},
			providerPrivKey,
			nodeId,
			hex.EncodeToString(instructionId),
			policy.ActiveSigningPolicy.RewardEpochId,
		)

		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to sign transaction, status %v, attestation token %s", resp.Status, resp.Token)
	}

	return hex.EncodeToString(instructionId)
}

func getSignatureResult(t *testing.T, instructionId string, ctx context.Context) {
	var resp api.InstructionResultResponse

	instruction := api.InstructionResultRequest{
		Challenge:     "blablabla",
		InstructionId: instructionId,
	}

	resp, err := utils.Post[api.InstructionResultResponse](hostUrl+"/instruction/result", instruction)
	require.NoError(t, err)

	logger.Infof("sent request to get signature of transaction, status %v, attestation token %s, result: %s", resp.Status, resp.Token, string(resp.Data))

	// todo: check signature
}

func TestHttpServerRequestSizeLimit(t *testing.T) {
	// This test uses server launched with go LaunchServer
	// which was lauched in the previous test TestServiceEndToEnd
	providersBytes, err := os.ReadFile("../../tests/test_providers.json")
	if err != nil {
		log.Fatalf("%v", err)
	}
	providers, err := utils.UnmarshalProviders(providersBytes)
	if err != nil {
		log.Fatalf("%v", err)
	}
	tooLargePayload, err := utilsserver.GenerateRandomBytes(1000 * 1024)
	require.NoError(t, err)
	instructionId, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	instruction, err := utils.BuildMockInstruction("XRP",
		"PAY",
		tooLargePayload,
		api.SignPaymentAdditionalFixedMessage{
			PaymentHash: "0x1234",
			KeyId:       "1",
		},
		providers.PrivKeys[0],
		"0x123",
		hex.EncodeToString(instructionId),
		1,
	)
	require.NoError(t, err)

	_, err = utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Request too large")
}
