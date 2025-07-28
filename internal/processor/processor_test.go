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
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/tee"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"

	commonwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/node"
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
	err := node.InitNode(types.State{
		Status: big.NewInt(1234),
	})
	require.NoError(t, err)

	numVoters, startingEpochId := 100, uint32(1)
	finalEpochId := startingEpochId + 1

	providerAddresses, providerPrivKeys, _ := testutils.GenerateRandomKeys(numVoters)

	numAdmins := 3
	adminPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins - 1 {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminPubKeys[i] = &adminPrivKeys[i].PublicKey
	}

	// make one provider also admin
	adminPrivKeys[numAdmins-1] = providerPrivKeys[0]
	adminPubKeys[numAdmins-1] = &providerPrivKeys[0].PublicKey

	// change type
	adminWalletPublicKeys := make([]commonwallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		adminWalletPublicKeys[i] = commonwallet.PublicKey(types.PubKeyToStruct(pubKey))
	}

	mainActionInfoChan := make(chan *types.Action, 100)
	readActionInfoChan := make(chan *types.Action, 100)
	actionResponseChan := make(chan *types.ActionResponse, 100)
	go MockProxy(t, mainActionInfoChan, readActionInfoChan, actionResponseChan)

	go RunTeeProcessor("http://localhost:" + strconv.Itoa(proxyPort))

	time.Sleep(1 * time.Second)

	teeId, teePubKey := getTeeInfo(t, readActionInfoChan, actionResponseChan)

	initializePolicy(t, mainActionInfoChan, actionResponseChan, providerPrivKeys, providerAddresses,
		startingEpochId)

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)
	walletProof := generateWallet(t, mainActionInfoChan, actionResponseChan, teeId, walletId, keyId,
		providerPrivKeys, adminWalletPublicKeys, finalEpochId)
	require.Equal(t, walletProof.Restored, false)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	signTransaction(t, mainActionInfoChan, actionResponseChan, teeId, walletId, keyId, providerPrivKeys, finalEpochId, paymentHash)

	walletBackup := getBackup(t, readActionInfoChan, actionResponseChan, teeId, walletId, keyId)

	nonce := big.NewInt(1)
	deleteWallet(t, mainActionInfoChan, actionResponseChan, teeId, walletId, keyId, providerPrivKeys, finalEpochId, nonce)
	nonce.Add(nonce, common.Big1)

	recoveredWalletProof := recoverWallet(t, mainActionInfoChan, actionResponseChan, teeId, teePubKey, walletId, keyId,
		providerPrivKeys, adminPrivKeys, finalEpochId, nonce, walletBackup)
	walletProof.Restored = true

	walletProof.Nonce = nonce
	require.Equal(t, walletProof, recoveredWalletProof)

	getTeeAttestation(t, mainActionInfoChan, actionResponseChan, teeId,
		providerPrivKeys, finalEpochId)

	ftdcProve(t, mainActionInfoChan, actionResponseChan, teeId, providerPrivKeys, adminPrivKeys, finalEpochId)

	// todo: update policy
}

func initializePolicy(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, privKeys []*ecdsa.PrivateKey, addresses []common.Address,
	startingEpochId uint32) {
	// initialize policy
	randSeed := int64(12345)

	nextPolicy, err := testutils.GenerateRandomPolicyData(startingEpochId+1, addresses, randSeed)
	require.NoError(t, err)

	pubKeys := make([]tee.PublicKey, len(privKeys))
	for i, voter := range privKeys {
		pubKeys[i] = types.PubKeyToStruct(&voter.PublicKey)
	}
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: nextPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}

	action := testutils.BuildMockQueuedAction(t, "POLICY", "INITIALIZE_POLICY", req)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
}

func getTeeInfo(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
) (common.Address, *ecdsa.PublicKey) {
	challenge, err := utils.GenerateRandom()
	require.NoError(t, err)
	req := &types.TeeInfoRequest{
		Challenge: common.Hash(challenge),
	}
	action := testutils.BuildMockQueuedAction(t, "GET", "TEE_INFO", req)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan

	require.True(t, actionResponse.Result.Status)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.Data, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.TeeInfo.PublicKey)
	require.NoError(t, err)

	teeId := crypto.PubkeyToAddress(*teePubKey)

	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	return teeId, teePubKey
}

func generateWallet(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	adminWalletPublicKeys []commonwallet.PublicKey, rewardEpochId uint32) *commonwallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := commonwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
		ConfigConstants: commonwallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0), // todo: add cosigners
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{commonwallet.MessageArguments[constants.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_GENERATE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := structs.Decode[commonwallet.ITeeWalletKeyManagerKeyExistence](commonwallet.KeyExistenceStructArg, actionResponse.Result.Data)
	require.NoError(t, err)

	newWallet, err := wallets.Storage.GetWallet(types.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)

	require.Equal(t, newWallet.XrpAddress, walletExistenceProof.AddressStr)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_GENERATE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return &walletExistenceProof
}

func signTransaction(t *testing.T, actionInfoChan chan *types.Action, actionResponseChan chan *types.ActionResponse,
	teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32, paymentHash string) {
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
		"XRP", "PAY", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessage, nil, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signatureData types.GetPaymentSignatureResponse
	err = json.Unmarshal(actionResponse.Result.Data, &signatureData)
	require.NoError(t, err)

	// todo: check result
	// fmt.Println("check sig", signatureData)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"XRP", "PAY", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessage, nil, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func deleteWallet(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, walletId [32]byte, keyId uint64,
	privKeys []*ecdsa.PrivateKey, rewardEpochId uint32, nonce *big.Int) {
	originalMessage := commonwallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{commonwallet.MessageArguments[constants.KeyDelete]}.Pack(originalMessage)
	require.NoError(t, err)

	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DELETE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)

	_, err = wallets.Storage.GetWallet(types.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.Error(t, err)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DELETE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func getBackup(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, walletId [32]byte, keyId uint64) *backup.WalletBackup {
	message := types.WalletKeyIdPair{
		WalletId: walletId,
		KeyId:    keyId,
	}

	action := testutils.BuildMockQueuedAction(t, "GET", "TEE_BACKUP", message)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err := utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var backupResponse types.WalletGetBackupResponse
	err = json.Unmarshal(actionResponse.Result.Data, &backupResponse)
	require.NoError(t, err)

	// fmt.Println("backup size", len(backupResponse.WalletBackup))

	var backup backup.WalletBackup
	err = json.Unmarshal(backupResponse.WalletBackup, &backup)
	require.NoError(t, err)

	return &backup
}

func recoverWallet(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, teePubKey *ecdsa.PublicKey, walletId [32]byte, keyId uint64,
	providersPrivKeys, adminsPrivKeys []*ecdsa.PrivateKey, rewardEpochId uint32, nonce *big.Int,
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
	for j, adminPrivKey := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(adminPrivKey.PublicKey)
		for _, providerPrivKey := range providersPrivKeys {
			if address == crypto.PubkeyToAddress(providerPrivKey.PublicKey) {
				adminAndProvider[address] = j
			}
		}
	}

	teeEciesPubKey := ecies.ImportECDSAPublic(teePubKey)
	additionalVariableMessages := make([]interface{}, 0)
	privKeys := make([]*ecdsa.PrivateKey, 0)
	for i, privKey := range providersPrivKeys {
		keySplit, err := backup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[i], privKey)
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
		types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := structs.Decode[commonwallet.ITeeWalletKeyManagerKeyExistence](commonwallet.KeyExistenceStructArg, actionResponse.Result.Data)
	require.NoError(t, err)

	// check that commonwallet is actually on the tee
	commonwallet, err := wallets.Storage.GetWallet(types.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)
	require.Equal(t, walletId[:], commonwallet.WalletId[:])
	require.Equal(t, keyId, commonwallet.KeyId)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DATA_PROVIDER_RESTORE", originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages,
		types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return &walletExistenceProof
}

func getTeeAttestation(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeId common.Address,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32,
) {
	ch, err := testutils.GenerateRandomBytes(32)
	require.NoError(t, err)
	challenge := [32]byte(ch)

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
		"REG", "TEE_ATTESTATION", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.Data, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.TeeInfo.PublicKey)
	require.NoError(t, err)

	receivedTeeId := crypto.PubkeyToAddress(*teePubKey)

	require.Equal(t, receivedTeeId, teeId)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"REG", "TEE_ATTESTATION", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func ftdcProve(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeId common.Address,
	providerPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32,
) {
	cosignerAddresses := make([]common.Address, len(cosignerPrivKeys))
	cosignerAndProvider := make(map[common.Address]bool)
	for j, cosignerPrivKey := range cosignerPrivKeys {
		cosignerAddresses[j] = utils.PubkeyToAddress(&cosignerPrivKey.PublicKey)
		for _, providerPrivKey := range providerPrivKeys {
			if cosignerAddresses[j] == crypto.PubkeyToAddress(providerPrivKey.PublicKey) {
				cosignerAndProvider[cosignerAddresses[j]] = true
			}
		}
	}

	originalMessage := connector.IFtdcHubFtdcAttestationRequest{
		Header: connector.IFtdcHubFtdcRequestHeader{
			AttestationType:    [32]byte{},
			SourceId:           common.Hash{},
			ThresholdBIPS:      uint16(testutils.TotalWeight * 0.6),
			Cosigners:          cosignerAddresses,
			CosignersThreshold: uint64(len(cosignerAddresses) / 2),
		},
		RequestBody: make([]byte, 10),
	}

	originalMessageEncoded, err := types.EncodeFTDCRequest(originalMessage)
	require.NoError(t, err)

	challenge, err := testutils.GenerateRandomBytes(32)
	require.NoError(t, err)

	additionalFixedMessage := verification.ITeeVerificationTeeAttestation{
		TeeMachine: verification.ITeeRegistryTeeMachineWithAttestationData{
			TeeId:        teeId,
			InitialTeeId: common.Address{},
			Url:          "blabla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
		Challenge: [32]byte(challenge),
	}
	// types.EncodeTeeAttestationRequest(originalMessage)

	additionalFixedMessageEncoded, err := types.EncodeTeeAttestationRequest(&additionalFixedMessage)
	require.NoError(t, err)

	timestamp := uint64(time.Now().Unix())
	ftdcMsgHash, _, err := types.HashFTDCMessage(originalMessage, additionalFixedMessageEncoded, timestamp)
	require.NoError(t, err)

	variableMessages := make([]interface{}, 0)
	privKeys := make([]*ecdsa.PrivateKey, 0)
	for _, privKey := range providerPrivKeys {
		variableMessage, err := utils.Sign(ftdcMsgHash[:], privKey)
		require.NoError(t, err)

		variableMessages = append(variableMessages, variableMessage)
		privKeys = append(privKeys, privKey)
	}
	for _, privKey := range cosignerPrivKeys {
		if _, check := cosignerAndProvider[utils.PubkeyToAddress(&privKey.PublicKey)]; check {
			continue
		}
		variableMessage, err := utils.Sign(ftdcMsgHash[:], privKey)
		require.NoError(t, err)

		variableMessages = append(variableMessages, variableMessage)
		privKeys = append(privKeys, privKey)
	}

	action, err := testutils.BuildMockQueuedActionInstruction(
		"FTDC", "PROVE", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessageEncoded, variableMessages, types.Threshold, timestamp,
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var ftdcResponse types.FTDCProveResponse
	err = json.Unmarshal(actionResponse.Result.Data, &ftdcResponse)
	require.NoError(t, err)

	// ftdcResponse, err := types.DecodeFTDCResponse(actionResponse.Result.Data)
	// require.NoError(t, err)

	err = utils.VerifySignature(ftdcMsgHash.Bytes(), ftdcResponse.TEESignature, teeId)
	require.NoError(t, err)
	require.Equal(t, len(ftdcResponse.DataProviderSignatures), len(providerPrivKeys))
	for i, signature := range ftdcResponse.DataProviderSignatures {
		err = utils.VerifySignature(ftdcMsgHash.Bytes(), signature, crypto.PubkeyToAddress(providerPrivKeys[i].PublicKey))
		require.NoError(t, err)
	}
	require.Equal(t, len(ftdcResponse.CosignerSignatures), len(cosignerPrivKeys))
	for _, signature := range ftdcResponse.CosignerSignatures {
		_, err = utils.CheckSignature(ftdcMsgHash.Bytes(), signature, cosignerAddresses)
		require.NoError(t, err)
	}
	require.Equal(t, ftdcResponse.ResponseBody, additionalFixedMessageEncoded)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"FTDC", "PROVE", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessageEncoded, variableMessages, types.End, timestamp,
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func MockProxy(t *testing.T, mainActionInfoChan, readActionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse) {
	router := mux.NewRouter()

	router.HandleFunc("/queue/main", func(w http.ResponseWriter, r *http.Request) {
		var action types.Action
		select {
		case x := <-mainActionInfoChan:
			action = *x
		default:
			action = types.Action{}
		}

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	}).Methods("POST")

	router.HandleFunc("/queue/read", func(w http.ResponseWriter, r *http.Request) {
		var action types.Action
		select {
		case x := <-readActionInfoChan:
			action = *x
		default:
			action = types.Action{}
		}

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
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
