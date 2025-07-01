package processor

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"

	commonwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

const proxyPort = 5500

// todo: add cosigners to commonwallet, check xrp signature, verify signer sequence data (vote hash)
func TestProcessorEndToEnd(t *testing.T) {
	err := node.InitNode()
	require.NoError(t, err)

	numVoters, numPolicies, startingEpochId := 100, 10, uint32(1)
	finalEpochId := startingEpochId + uint32(numPolicies)

	providersAddresses, providersPrivKeys, _ := testutils.GenerateRandomKeys(numVoters)

	numAdmins := 3
	adminsPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminsPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins - 1 {
		adminsPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminsPubKeys[i] = &adminsPrivKeys[i].PublicKey
	}

	// make one provider also admin
	adminsPrivKeys[numAdmins-1] = providersPrivKeys[0]
	adminsPubKeys[numAdmins-1] = &providersPrivKeys[0].PublicKey

	// change type
	adminsWalletPublicKeys := make([]commonwallet.PublicKey, len(adminsPubKeys))
	for i, pubKey := range adminsPubKeys {
		adminsWalletPublicKeys[i] = commonwallet.PublicKey(types.PubKeyToStruct(pubKey))
	}

	mainActionInfoChan := make(chan *types.ActionInfo, 100)
	readActionInfoChan := make(chan *types.ActionInfo, 100)
	actionResponseChan := make(chan *types.ActionResponse, 100)
	actionMap := make(map[types.ActionInfo]*types.Action)
	go MockProxy(t, mainActionInfoChan, readActionInfoChan, actionMap, actionResponseChan)

	go RunTeeProcessor("http://localhost:" + strconv.Itoa(proxyPort))

	time.Sleep(1 * time.Second)

	actionId := big.NewInt(0)
	initializePolicy(t, mainActionInfoChan, actionMap, actionResponseChan, providersPrivKeys, providersAddresses,
		actionId, numPolicies, startingEpochId)

	teeId, teePubKey := getTeeInfo(t, readActionInfoChan, actionMap, actionResponseChan, actionId)
	actionId.Add(actionId, common.Big1)

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)
	walletProof := generateWallet(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId,
		providersPrivKeys, adminsWalletPublicKeys, finalEpochId, actionId)
	require.Equal(t, walletProof.Restored, false)
	actionId.Add(actionId, common.Big1)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	signTransaction(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId, providersPrivKeys, finalEpochId, actionId, paymentHash)
	actionId.Add(actionId, common.Big1)

	walletBackup := getBackup(t, readActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId, actionId)
	actionId.Add(actionId, common.Big1)

	nonce := big.NewInt(1)
	deleteWallet(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId, providersPrivKeys, finalEpochId, actionId, nonce)
	actionId.Add(actionId, common.Big1)
	nonce.Add(actionId, common.Big1)

	recoveredWalletProof := recoverWallet(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, teePubKey, walletId, keyId,
		providersPrivKeys, adminsPrivKeys, finalEpochId, actionId, nonce, walletBackup)
	walletProof.Restored = true
	actionId.Add(actionId, common.Big1)

	walletProof.Nonce = nonce
	require.Equal(t, walletProof, recoveredWalletProof)

	getTeeAttestation(t, mainActionInfoChan, actionMap, actionResponseChan, teeId,
		providersPrivKeys, finalEpochId, actionId)

	// todo: update policy
}

func initializePolicy(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, privKeys []*ecdsa.PrivateKey, addresses []common.Address,
	actionId *big.Int, numPolicies int, startingEpochId uint32) {
	// initialize policy
	randSeed := int64(12345)
	initialPolicy := testutils.GenerateRandomPolicyData(startingEpochId, addresses, randSeed)
	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	require.NoError(t, err)

	policySignaturesArray, err := testutils.GenerateRandomMultiSignedPolicyArray(startingEpochId, randSeed, addresses, privKeys, numPolicies)
	require.NoError(t, err, "could not generate random policy policy")
	pubKeys := make([]types.ECDSAPublicKey, len(privKeys))
	for i, voter := range privKeys {
		pubKeys[i] = types.PubKeyToStruct(&voter.PublicKey)
	}
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		Policies:               policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}

	action, err := testutils.BuildMockQueuedActionAction("POLICY", "INITIALIZE_POLICY", req)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)
}

func getTeeInfo(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, actionId *big.Int) (common.Address, *ecdsa.PublicKey) {

	challenge, err := utils.GenerateRandom()
	require.NoError(t, err)
	req := &types.TeeInfoRequest{Challenge: challenge}
	action, err := testutils.BuildMockQueuedActionAction("GET", "TEE_INFO", req)

	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "read", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.PublicKey)
	require.NoError(t, err)

	teeId := crypto.PubkeyToAddress(*teePubKey)

	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	return teeId, teePubKey
}

func generateWallet(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	adminsWalletPublicKeys []commonwallet.PublicKey, rewardEpochId uint32, actionId *big.Int) *commonwallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := commonwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
		ConfigConstants: commonwallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminsWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminsWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0), // todo: add cosigners
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{commonwallet.MessageArguments[constants.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_GENERATE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.Threshold,
	)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := structs.Decode[commonwallet.ITeeWalletKeyManagerKeyExistence](commonwallet.KeyExistenceStructArg, actionResponse.Result.ResultData.Message)
	require.NoError(t, err)

	newWallet, err := wallets.Storage.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)

	require.Equal(t, newWallet.XrpAddress, walletExistenceProof.AddressStr)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_GENERATE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.End,
	)
	require.NoError(t, err)

	actionInfo = &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return &walletExistenceProof
}

func signTransaction(t *testing.T, actionInfoChan chan *types.ActionInfo,
	actionMap map[types.ActionInfo]*types.Action, actionResponseChan chan *types.ActionResponse,
	teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32, actionId *big.Int, paymentHash string) {
	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         walletId,
		TeeIdKeyIdPairs:  []payment.TeeIdKeyIdPair{{TeeId: teeId, KeyId: keyId}},
		SenderAddress:    "0x123",
		RecipientAddress: "0x456",
		Amount:           big.NewInt(1000000000),
		Fee:              big.NewInt(10),
		PaymentReference: [32]byte{},
		Nonce:            0,
		SubNonce:         0,
		BatchEndTs:       0,
	}

	originalMessageEncoded, err := abi.Arguments{payment.MessageArguments[constants.Pay]}.Pack(originalMessage)
	require.NoError(t, err)

	additionalFixedMessage := types.SignPaymentAdditionalFixedMessage{
		PaymentHash: paymentHash,
		KeyId:       keyId,
	}

	action, err := testutils.BuildMockQueuedActionInstruction(
		"XRP", "PAY", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessage, nil, types.Threshold,
	)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signatureData types.GetPaymentSignatureResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signatureData)
	require.NoError(t, err)

	// todo: check result
	// fmt.Println("check sig", signatureData)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"XRP", "PAY", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessage, nil, types.End,
	)
	require.NoError(t, err)

	actionInfo = &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func deleteWallet(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, walletId [32]byte, keyId uint64,
	privKeys []*ecdsa.PrivateKey, rewardEpochId uint32, actionId, nonce *big.Int) {
	originalMessage := commonwallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{commonwallet.MessageArguments[constants.KeyDelete]}.Pack(originalMessage)
	require.NoError(t, err)

	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DELETE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.Threshold,
	)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)

	_, err = wallets.Storage.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.Error(t, err)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DELETE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.End,
	)
	require.NoError(t, err)

	actionInfo = &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func getBackup(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, walletId [32]byte, keyId uint64, actionId *big.Int) *backup.WalletBackup {
	message := wallets.WalletKeyIdPair{
		WalletId: walletId,
		KeyId:    keyId,
	}

	action, err := testutils.BuildMockQueuedActionAction(
		"GET", "TEE_BACKUP", message,
	)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "read", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var backupResponse types.WalletGetBackupResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &backupResponse)
	require.NoError(t, err)

	// fmt.Println("backup size", len(backupResponse.WalletBackup))

	var backup backup.WalletBackup
	err = json.Unmarshal(backupResponse.WalletBackup, &backup)
	require.NoError(t, err)

	return &backup
}

func recoverWallet(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, teePubKey *ecdsa.PublicKey, walletId [32]byte, keyId uint64,
	providersPrivKeys, adminsPrivKeys []*ecdsa.PrivateKey, rewardEpochId uint32, actionId, nonce *big.Int,
	walletBackup *backup.WalletBackup) *commonwallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := commonwallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeeId:     teeId,
		BackupUrl: "blabla",
		Nonce:     nonce,
		BackupId: commonwallet.ITeeWalletBackupManagerBackupId{
			TeeId:         teeId,
			WalletId:      walletId,
			KeyId:         keyId,
			OpType:        utils.StringToOpHash("WALLET"),
			PublicKey:     append(walletBackup.PublicKey.X[:], walletBackup.PublicKey.Y[:]...),
			RewardEpochId: big.NewInt(int64(rewardEpochId)),
			RandomNonce:   new(big.Int).SetBytes(walletBackup.RandomNonce[:]),
		},
	}

	originalMessageEncoded, err := abi.Arguments{commonwallet.MessageArguments[constants.KeyDataProviderRestore]}.Pack(originalMessage)
	require.NoError(t, err)

	additionalFixedMessage := walletBackup.WalletBackupMetaData

	adminAndProvider := make(map[common.Address]int)
	for j, privKey1 := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(privKey1.PublicKey)
		for _, privKey2 := range providersPrivKeys {
			if address == crypto.PubkeyToAddress(privKey2.PublicKey) {
				adminAndProvider[address] = j
			}
		}
	}

	teeEciesPubKey := ecies.ImportECDSAPublic(teePubKey)
	additionalVariableMessages := make([]interface{}, 0)
	privKeys := make([]*ecdsa.PrivateKey, 0)
	for i, privKey := range providersPrivKeys {
		keySplit, err := backup.DecryptSplit(walletBackup.ProvidersEncryptedParts.Splits[i], privKey)
		require.NoError(t, err)

		address := crypto.PubkeyToAddress(privKey.PublicKey)
		j, check := adminAndProvider[address]
		var plaintext []byte
		if !check {
			plaintext, err = json.Marshal(keySplit)
			require.NoError(t, err)
		} else {
			keySplitAdmin, err := backup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[j], privKey)
			require.NoError(t, err)
			var twoKeySplits [2]backup.KeySplit
			twoKeySplits[0] = *keySplit
			twoKeySplits[1] = *keySplitAdmin
			plaintext, err = json.Marshal(twoKeySplits)
			require.NoError(t, err)
		}

		cipher, err := ecies.Encrypt(rand.Reader, teeEciesPubKey, plaintext, nil, nil)
		require.NoError(t, err)

		additionalVariableMessages = append(additionalVariableMessages, cipher)
		privKeys = append(privKeys, privKey)
	}

	for i, privKey := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(privKey.PublicKey)
		_, check := adminAndProvider[address]
		if check {
			continue
		}

		keySplit, err := backup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[i], privKey)
		require.NoError(t, err)

		plaintext, err := json.Marshal(keySplit)
		require.NoError(t, err)

		cipher, err := ecies.Encrypt(rand.Reader, teeEciesPubKey, plaintext, nil, nil)
		require.NoError(t, err)

		additionalVariableMessages = append(additionalVariableMessages, cipher)
		privKeys = append(privKeys, privKey)
	}

	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DATA_PROVIDER_RESTORE", originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages,
		types.Threshold,
	)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := structs.Decode[commonwallet.ITeeWalletKeyManagerKeyExistence](commonwallet.KeyExistenceStructArg, actionResponse.Result.ResultData.Message)
	require.NoError(t, err)

	// check that commonwallet is actually on the tee
	commonwallet, err := wallets.Storage.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)
	require.Equal(t, walletId[:], commonwallet.WalletId[:])
	require.Equal(t, keyId, commonwallet.KeyId)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DATA_PROVIDER_RESTORE", originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages,
		types.End,
	)
	require.NoError(t, err)

	actionInfo = &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return &walletExistenceProof
}

func getTeeAttestation(t *testing.T, actionInfoChan chan *types.ActionInfo, actionMap map[types.ActionInfo]*types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32, actionId *big.Int) {

	challenge, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))
	require.NoError(t, err)

	originalMessage := verification.ITeeVerificationTeeAttestation{
		TeeMachine: verification.ITeeRegistryTeeMachineWithAttestationData{
			TeeId:        teeId,
			InitialTeeId: common.Address{},
			Url:          "bla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
		Challenge: challenge,
	}
	originalMessageEncoded, err := abi.Arguments{verification.MessageArguments[constants.TEEAttestation]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action, err := testutils.BuildMockQueuedActionInstruction(
		"REG", "TEE_ATTESTATION", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.Threshold,
	)
	require.NoError(t, err)

	actionInfo := &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.PublicKey)
	require.NoError(t, err)

	receivedTeeId := crypto.PubkeyToAddress(*teePubKey)

	require.Equal(t, receivedTeeId, teeId)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"REG", "TEE_ATTESTATION", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.End,
	)
	require.NoError(t, err)

	actionInfo = &types.ActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func MockProxy(t *testing.T, mainActionInfoChan, readActionInfoChan chan *types.ActionInfo,
	actionMap map[types.ActionInfo]*types.Action, actionResponseChan chan *types.ActionResponse) {
	router := mux.NewRouter()

	router.HandleFunc("/queue/main", func(w http.ResponseWriter, r *http.Request) {
		var actionInfo types.ActionInfo
		select {
		case x := <-mainActionInfoChan:
			actionInfo = *x
		default:
			actionInfo = types.ActionInfo{}
		}

		response, err := json.Marshal(actionInfo)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	}).Methods("GET")

	router.HandleFunc("/queue/read", func(w http.ResponseWriter, r *http.Request) {
		var actionInfo types.ActionInfo
		select {
		case x := <-readActionInfoChan:
			actionInfo = *x
		default:
			actionInfo = types.ActionInfo{}
		}

		response, err := json.Marshal(actionInfo)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	}).Methods("GET")

	router.HandleFunc("/dequeue", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionInfo types.ActionInfo
		err = json.Unmarshal(body, &actionInfo)
		require.NoError(t, err)

		action, ok := actionMap[actionInfo]
		require.True(t, ok)

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
		err = r.Body.Close()
		require.NoError(t, err)
	}).Methods("POST")

	router.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionResponse types.ActionResponse
		err = json.Unmarshal(body, &actionResponse)
		require.NoError(t, err)

		actionResponseChan <- &actionResponse
		err = r.Body.Close()
		require.NoError(t, err)
	}).Methods("POST")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), router))
}
