package service

// TODO: These test now need to be adapted, because the services are only available through the InstructionService

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"

	api "tee-node/api/types"
	"tee-node/pkg/node"
	utilsserver "tee-node/pkg/utils"
	"tee-node/pkg/wallets"

	"tee-node/pkg/policy"
	utils "tee-node/tests"

	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	commonpayment "github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var walletId = common.HexToHash("0xabcdef")
var keyId = uint64(1)

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
	assert.NoError(t, err)

	providers, err := utils.UnmarshalProviders(providersBytes)
	assert.NoError(t, err)

	numAdmins := 3
	adminsPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminsPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins - 1 {
		adminsPrivKeys[i], err = crypto.GenerateKey()
		assert.NoError(t, err)
		adminsPubKeys[i] = &adminsPrivKeys[i].PublicKey
	}

	// make one provider also admin
	adminsPrivKeys[numAdmins-1] = providers.PrivKeys[0]
	adminsPubKeys[numAdmins-1] = &providers.PrivKeys[0].PublicKey

	// initialize random policies
	numPolicies := 5
	initializePolicy(t, numPolicies, providers)

	nodeId := getNodeInfo(t)

	// generate a new wallet
	createWallet(t, nodeId, walletId, keyId, providers.PrivKeys, adminsPubKeys)
	// get address
	walletPubKey := getWalletInfo(t, walletId, keyId)

	backupWallet := getWalletBackup(t, nodeId, walletId, keyId, walletPubKey)
	rewardEpochIdAtBackup := policy.GetActiveSigningPolicy().RewardEpochId
	fmt.Println("backup size", len(backupWallet))

	// delete wallet
	deleteWallet(t, nodeId, walletId, keyId, providers.PrivKeys)

	time.Sleep(time.Second)

	// recover key
	recoverWalletInit(t, nodeId, walletId, keyId, rewardEpochIdAtBackup, walletPubKey, providers.PrivKeys)
	recoverUploadWalletBackup(t, backupWallet)
	recoverDownloadUploadShare(t, nodeId, walletId, keyId, rewardEpochIdAtBackup, walletPubKey, providers.PrivKeys)
	recoverDownloadUploadShare(t, nodeId, walletId, keyId, rewardEpochIdAtBackup, walletPubKey, adminsPrivKeys[:numAdmins-1]) // the last admin is part of the providers

	recoveredWalletPublicKey := getWalletInfo(t, walletId, keyId)
	require.Equal(t, walletPubKey, recoveredWalletPublicKey)

	// sign transaction
	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	instructionId := signTransaction(t, nodeId, walletId, keyId, paymentHash, providers.PrivKeys)
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
		pubKeys[i] = api.PubKeyToBytes(&voter.PublicKey)
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

func createWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId uint64, providersPrivKeys []*ecdsa.PrivateKey, adminPubKeys []*ecdsa.PublicKey) {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)

	adminsWalletPublicKeys := make([]wallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		adminsWalletPublicKeys[i] = wallet.PublicKey{}
		copy(adminsWalletPublicKeys[i].X[:], pubKey.X.Bytes())
		copy(adminsWalletPublicKeys[i].Y[:], pubKey.Y.Bytes())
	}

	for i := range 2 {
		providerPrivKey := providersPrivKeys[i]

		originalMessage := wallet.ITeeWalletKeyManagerKeyGenerate{
			TeeId:              common.HexToAddress("1234"),
			WalletId:           walletId,
			KeyId:              keyId,
			OpType:             utilsserver.StringToOpHash("WALLET"),
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminsWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminsWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
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

func getNodeInfo(t *testing.T) common.Address {
	nonceBytes, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	req := api.GetNodeInfoRequest{
		Nonce: hex.EncodeToString(nonceBytes),
	}
	nodeResp, err := utils.Post[api.GetNodeInfoResponse](hostUrl+"/info", req)
	require.NoError(t, err)

	logger.Infof("NodeId: %s, attestation token %s", nodeResp.Data.TeeId, nodeResp.Token)

	return nodeResp.Data.TeeId
}

func getWalletInfo(t *testing.T, walletId common.Hash, keyId uint64) api.ECDSAPublicKey {
	instructionId, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	req := api.WalletInfoRequest{
		WalletId:  walletId,
		KeyId:     keyId,
		Challenge: hex.EncodeToString(instructionId),
	}
	pubKeyResp, err := utils.Post[api.WalletInfoResponse](hostUrl+"/wallet", req)
	require.NoError(t, err)

	logger.Infof("ethAddress: %s, public key: (%s, %s), attestation token %s",
		pubKeyResp.EthAddress, hex.EncodeToString(pubKeyResp.PublicKey.X[:]), hex.EncodeToString(pubKeyResp.PublicKey.Y[:]), pubKeyResp.Token)

	return pubKeyResp.PublicKey
}

func getWalletBackup(t *testing.T, teeId common.Address, walletId common.Hash, keyId uint64, pubKey api.ECDSAPublicKey) []byte {
	instructionId, err := utilsserver.GenerateRandomBytes(32)
	require.NoError(t, err)

	req := api.WalletGetBackupRequest{
		ITeeWalletBackupManagerKeyDataProviderRestore: wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
			TeeId:         teeId,
			WalletId:      walletId,
			KeyId:         keyId,
			OpType:        utilsserver.StringToOpHash("WALLET"),
			PublicKey:     append(pubKey.X[:], pubKey.Y[:]...),
			RewardEpochId: big.NewInt(int64(policy.GetActiveSigningPolicy().RewardEpochId)),
		},
		Challenge: hex.EncodeToString(instructionId),
	}
	backupResp, err := utils.Post[api.WalletGetBackupResponse](hostUrl+"/wallet/get-backup", req)
	require.NoError(t, err)

	logger.Infof("obtained wallet backup")

	return backupResp.WalletBackup
}

func deleteWallet(t *testing.T, nodeId common.Address, walletId common.Hash, keyId uint64, providersPrivKeys []*ecdsa.PrivateKey) {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providersPrivKeys[i]

		originalMessage := wallet.ITeeWalletKeyManagerKeyDelete{
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

func signTransaction(t *testing.T, nodeId common.Address, walletId common.Hash, keyId uint64, paymentHash string, providersPrivKeys []*ecdsa.PrivateKey) string {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providersPrivKeys[i]

		originalMessage := commonpayment.ITeePaymentsPaymentInstructionMessage{
			WalletId:           walletId,
			SenderAddress:      "0x123",
			RecipientAddress:   "0x456",
			Amount:             big.NewInt(1000000000),
			PaymentReference:   [32]byte{},
			Nonce:              0,
			SubNonce:           0,
			MaxFee:             big.NewInt(0),
			MaxFeeTolerancePPM: 0,
			BatchEndTs:         0,
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
	challengeBytes, _ := utilsserver.GenerateRandomBytes(32)

	instruction := api.InstructionResultRequest{
		Challenge:     hex.EncodeToString(challengeBytes),
		InstructionId: instructionId,
	}

	resp, err := utils.Post[api.InstructionResultResponse](hostUrl+"/instruction/result", instruction)
	require.NoError(t, err)

	logger.Infof("sent request to get signature of transaction, status %v, attestation token %s, result: %s", resp.Status, resp.Token, string(resp.Data))

	// todo: check signature
}

func recoverWalletInit(
	t *testing.T, nodeId common.Address, walletId common.Hash, keyId uint64,
	rewardEpochIdAtBackup uint32, pubKey api.ECDSAPublicKey, providersPrivKeys []*ecdsa.PrivateKey,
) {
	instructionId, _ := utilsserver.GenerateRandomBytes(32)
	for i := range 2 {
		providerPrivKey := providersPrivKeys[i]

		originalMessage := wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
			TeeId:         nodeId,
			WalletId:      walletId,
			KeyId:         keyId,
			OpType:        utilsserver.StringToOpHash("WALLET"),
			PublicKey:     append(pubKey.X[:], pubKey.Y[:]...),
			RewardEpochId: big.NewInt(int64(rewardEpochIdAtBackup)),
		}

		originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyDataProviderRestore]}.Pack(originalMessage)
		require.NoError(t, err)

		instruction, err := utils.BuildMockInstruction(
			"WALLET",
			"KEY_DATA_PROVIDER_RESTORE_INIT",
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

		logger.Infof("sent request to initialize recover wallet, status %v, attestation token %s", resp.Status, resp.Token)
	}
}

func recoverUploadWalletBackup(t *testing.T, backup []byte) {
	challengeBytes, _ := utilsserver.GenerateRandomBytes(32)
	req := api.WalletUploadBackupRequest{
		WalletBackup: backup,
		Challenge:    hex.EncodeToString(challengeBytes),
	}
	backupResp, err := utils.Post[api.WalletUploadBackupResponse](hostUrl+"/wallet/upload-backup-package", req)
	require.NoError(t, err)

	logger.Infof("uploaded wallet backup, token %s", backupResp.Token)
}

func recoverDownloadUploadShare(t *testing.T, teeId common.Address, walletId common.Hash, keyId uint64, rewardEpochIdAtBackup uint32, pubKey api.ECDSAPublicKey, privKeys []*ecdsa.PrivateKey) {
	for i := range privKeys {
		providerPrivKey := privKeys[i]
		challengeBytes, _ := utilsserver.GenerateRandomBytes(32)

		request := api.WalletGetBackupShareRequest{
			ITeeWalletBackupManagerKeyDataProviderRestore: wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
				TeeId:         teeId,
				WalletId:      walletId,
				KeyId:         keyId,
				OpType:        utilsserver.StringToOpHash("WALLET"),
				PublicKey:     append(pubKey.X[:], pubKey.Y[:]...),
				RewardEpochId: big.NewInt(int64(rewardEpochIdAtBackup)),
			},
			OwnerPublicKey: api.PubKeyToBytes(&providerPrivKey.PublicKey),
			Challenge:      hex.EncodeToString(challengeBytes),
		}

		resp, err := utils.Post[api.WalletGetBackupShareResponse](hostUrl+"/wallet/get-backup-shares", request)
		require.NoError(t, err)

		if len(resp.AdminEncryptedWalletSplit) > 0 {
			challengeBytes, _ = utilsserver.GenerateRandomBytes(32)
			keySplit, err := wallets.DecryptSplit(resp.AdminEncryptedWalletSplit, providerPrivKey)
			require.NoError(t, err)

			decryptedWalletSplit, err := json.Marshal(keySplit)
			require.NoError(t, err)

			uploadShareRequest := api.WalletUploadBackupShareRequest{
				ITeeWalletBackupManagerKeyDataProviderRestore: wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
					TeeId:         teeId,
					WalletId:      walletId,
					KeyId:         keyId,
					OpType:        utilsserver.StringToOpHash("WALLET"),
					PublicKey:     append(pubKey.X[:], pubKey.Y[:]...),
					RewardEpochId: big.NewInt(int64(rewardEpochIdAtBackup)),
				},
				DecryptedWalletSplit: decryptedWalletSplit,
				Challenge:            hex.EncodeToString(challengeBytes),
				IsAdmin:              true,
			}
			_, err = utils.Post[api.WalletUploadBackupShareResponse](hostUrl+"/wallet/upload-backup-shares", uploadShareRequest)
			require.NoError(t, err)
		}
		if len(resp.ProviderEncryptedWalletSplit) > 0 {
			challengeBytes, _ = utilsserver.GenerateRandomBytes(32)

			keySplit, err := wallets.DecryptSplit(resp.ProviderEncryptedWalletSplit, providerPrivKey)
			require.NoError(t, err)

			decryptedWalletSplit, err := json.Marshal(keySplit)
			require.NoError(t, err)

			uploadShareRequest := api.WalletUploadBackupShareRequest{
				ITeeWalletBackupManagerKeyDataProviderRestore: wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
					TeeId:         teeId,
					WalletId:      walletId,
					KeyId:         keyId,
					OpType:        utilsserver.StringToOpHash("WALLET"),
					PublicKey:     append(pubKey.X[:], pubKey.Y[:]...),
					RewardEpochId: big.NewInt(int64(rewardEpochIdAtBackup)),
				},
				DecryptedWalletSplit: decryptedWalletSplit,
				Challenge:            hex.EncodeToString(challengeBytes),
				IsAdmin:              false,
			}
			_, err = utils.Post[api.WalletUploadBackupShareResponse](hostUrl+"/wallet/upload-backup-shares", uploadShareRequest)
			require.NoError(t, err)
		}
	}
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
