package service

// TODO: These test now need to be adapted, because the services are only available through the InstructionService

import (
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

var walletId = common.HexToHash("0xabcdef")
var keyId = big.NewInt(1)
var backupId = big.NewInt(1)

var hostPort = 8565
var hostUrl = "http://localhost:" + strconv.Itoa(hostPort)

func TestServiceEndToEnd(t *testing.T) {
	err := node.InitNode()
	if err != nil {
		log.Fatalf("failed to init node: %v", err)
	}

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
	initializePolicy(t, numPolicies, providers)

	nodeId, pubKey := getNodeInfo(t)

	// generate a new wallet
	createWallet(t, nodeId, walletId, keyId, providers)
	// get address
	address := getAddress(t, walletId, keyId)

	// backup wallet to yourself
	ids := []common.Address{nodeId, nodeId}
	backups := []string{"ws://localhost:50061", "ws://localhost:50061"}
	pubKeys := []string{pubKey, pubKey}
	threshold := len(backups)
	backupWallet(t, nodeId, walletId, keyId, backupId, ids, backups, pubKeys, threshold, providers)

	// delete wallet
	deleteWallet(t, nodeId, walletId, keyId, providers)

	time.Sleep(time.Second)

	// recover key
	recoverWallet(t, nodeId, walletId, keyId, backupId, address, ids, backups, pubKey, threshold, providers)

	// get recovered address
	recoveredAddress := getAddress(t, walletId, keyId)
	require.Equal(t, address, recoveredAddress)

	// sign transaction
	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	instructionId := signTransaction(t, nodeId, walletId, keyId, paymentHash, providers)
	getSignatureResult(t, instructionId)
}

func initializePolicy(t *testing.T, numPolicies int, providers *utils.Providers) {
	// initialize policy
	epochId, randSeed := uint32(1), int64(12345)
	initialPolicy := utils.GenerateRandomPolicyData(epochId, providers.Voters, randSeed)
	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	require.NoError(t, err)

	policySignaturesArray, err := utils.GenerateRandomMultiSignedPolicyArray(epochId, randSeed, providers.Voters, providers.PrivKeys, numPolicies)
	require.NoError(t, err, "could not generate random policy policy")
	pubKeys := make([]api.ECDSAPublicKey, len(providers.PrivKeys))
	for i, voter := range providers.PrivKeys {
		pubKeys[i] = api.ECDSAPublicKey{
			X: voter.PublicKey.X.String(),
			Y: voter.PublicKey.Y.String(),
		}
	}
	req := &api.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		NewPolicyRequests:      policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}

	resp, err := utils.Post[api.InitializePolicyResponse](hostUrl+"/policies/initialize", req)
	require.NoError(t, err)

	logger.Infof("sent request to initialize policy, token %v", resp.Token)
}

func createWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId *big.Int, providers *utils.Providers) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)

	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		originalMessage := wallet.ITeeWalletManagerKeyGenerate{
			TeeId:    common.HexToAddress("1234"),
			WalletId: walletId,
			KeyId:    keyId,
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
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to create wallet, status %v", resp.Status)
	}
}

func getNodeInfo(t *testing.T) (common.Address, string) {
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

func getAddress(t *testing.T, walletId common.Hash, keyId *big.Int) string {
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

func backupWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId *big.Int, backupId *big.Int, ids []common.Address, backups []string, pubKeys []string, threshold int, providers *utils.Providers) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		backupTeeMachines := make([]wallet.ITeeRegistryTeeMachineWithAttestationData, len(ids))
		for i, id := range ids {
			backupTeeMachines[i] = wallet.ITeeRegistryTeeMachineWithAttestationData{
				TeeId: id,
				Url:   backups[i],
			}
		}

		originalMessage := wallet.ITeeWalletBackupManagerKeyMachineBackup{
			TeeMachine:        wallet.ITeeRegistryTeeMachineWithAttestationData{},
			WalletId:          walletId,
			KeyId:             keyId,
			BackupId:          backupId,
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
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to split wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func deleteWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId *big.Int, providers *utils.Providers) {

	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		originalMessage := wallet.ITeeWalletManagerKeyDelete{
			TeeId:    common.HexToAddress("1234"),
			WalletId: walletId,
			KeyId:    keyId,
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
			policy.GetActiveSigningPolicy().RewardEpochId,
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

func recoverWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId *big.Int, backupId *big.Int, address string, ids []common.Address, backups []string, pubKey string, threshold int, providers *utils.Providers) {
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
				TeeId:    ids[i],
				Owner:    common.HexToAddress("0x123"),
				Url:      backups[i],
				CodeHash: common.HexToHash("0x123"),
				Platform: common.HexToHash("0x123"),
			}
		}

		originalMessage := wallet.ITeeWalletBackupManagerKeyMachineRestore{
			TeeMachine:        wallet.ITeeRegistryTeeMachineWithAttestationData{},
			WalletId:          walletId,
			KeyId:             keyId,
			BackupId:          backupId,
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
			policy.GetActiveSigningPolicy().RewardEpochId,
		)
		if err != nil {
			log.Fatalf("could not initialize policy: %v", err)
		}

		resp, err := utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
		require.NoError(t, err)

		logger.Infof("sent request to recover wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func signTransaction(t *testing.T, nodeId common.Address, walletId common.Hash, keyId *big.Int, paymentHash string, providers *utils.Providers) string {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providers.PrivKeys[i]

		originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
			WalletId:           walletId,
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
			policy.GetActiveSigningPolicy().RewardEpochId,
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

func getSignatureResult(t *testing.T, instructionId string) {
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
			KeyId:       keyId,
		},
		providers.PrivKeys[0],
		common.HexToAddress("0x123"),
		hex.EncodeToString(instructionId),
		1,
	)
	require.NoError(t, err)

	_, err = utils.Post[api.InstructionResponse](hostUrl+"/instruction", instruction)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Request too large")
}
