package processors_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"

	cwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

// todo: add cosigners to commonwallet, check xrp signature, verify signer sequence data (vote hash), verify encoded data provider signatures in FTDC
func TestProcessorsEndToEnd(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, startingEpochId := 100, uint32(1)
	finalEpochId := startingEpochId + 1

	providerAddresses, providerPrivKeys, _ := testutils.GenerateRandomKeys(numVoters)

	numAdmins := 3
	adminPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	var err error
	for i := range numAdmins - 1 {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminPubKeys[i] = &adminPrivKeys[i].PublicKey
	}

	// make one provider also admin
	adminPrivKeys[numAdmins-1] = providerPrivKeys[0]
	adminPubKeys[numAdmins-1] = &providerPrivKeys[0].PublicKey

	// change type
	adminWalletPublicKeys := make([]cwallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		pk := types.PubKeyToStruct(pubKey)
		adminWalletPublicKeys[i] = cwallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	mainActionInfoChan := make(chan *types.Action, 100)
	readActionInfoChan := make(chan *types.Action, 100)
	actionResponseChan := make(chan *types.ActionResponse, 100)
	proxyPort := 5501
	go MockProxy(t, proxyPort, mainActionInfoChan, readActionInfoChan, actionResponseChan)

	proxyConfigureServerPort := 5502
	go settings.ProxyURLConfigServer(proxyConfigureServerPort)

	r := router.NewPMWRouter(testNode, pStorage, wStorage)

	go r.Run(testNode)
	time.Sleep(1 * time.Second)

	setProxyUrl(t, proxyPort, proxyConfigureServerPort)

	teeId, teePubKey := getTeeInfo(t, readActionInfoChan, actionResponseChan)

	initializePolicy(t, mainActionInfoChan, actionResponseChan, providerPrivKeys, providerAddresses,
		startingEpochId)

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)
	walletProof := generateWallet(t, mainActionInfoChan, actionResponseChan, teeId, walletId, keyId,
		providerPrivKeys, adminWalletPublicKeys, finalEpochId, wStorage)
	require.False(t, walletProof.Restored)

	signTransaction(t, mainActionInfoChan, actionResponseChan, teeId, walletId, keyId, providerPrivKeys, finalEpochId)

	walletBackup := getBackup(t, readActionInfoChan, actionResponseChan, teeId, walletId, keyId)

	nonce := big.NewInt(1)
	deleteWallet(t, mainActionInfoChan, actionResponseChan, teeId, walletId, keyId, providerPrivKeys, finalEpochId, nonce, wStorage)
	nonce.Add(nonce, common.Big1)

	recoveredWalletProof := recoverWallet(t, mainActionInfoChan, actionResponseChan, teeId, teePubKey, walletId, keyId,
		providerPrivKeys, adminPrivKeys, finalEpochId, nonce, walletBackup, wStorage)
	walletProof.Restored = true

	walletProof.Nonce = nonce
	require.Equal(t, walletProof, recoveredWalletProof)

	getTeeAttestation(t, mainActionInfoChan, actionResponseChan, teeId,
		providerPrivKeys, finalEpochId)

	ftdcProve(t, mainActionInfoChan, actionResponseChan, teeId, providerPrivKeys, adminPrivKeys, finalEpochId)

	// todo: update policy
}

func setProxyUrl(t *testing.T, proxyPort, setProxyPort int) {
	request := types.ConfigureProxyUrlRequest{
		Url: fmt.Sprintf("http://localhost:%d", proxyPort),
	}

	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	requestBody, err := json.Marshal(request)
	require.NoError(t, err)

	r, err := client.Post(fmt.Sprintf("http://localhost:%d/configure", setProxyPort), "application/json", bytes.NewBuffer(requestBody))
	require.NoError(t, err)
	require.Equal(t, r.StatusCode, http.StatusOK)
}

func initializePolicy(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, privKeys []*ecdsa.PrivateKey, addresses []common.Address,
	startingEpochId uint32) {
	// initialize policy
	randSeed := int64(12345)

	nextPolicy, err := testutils.GenerateRandomPolicyData(startingEpochId+1, addresses, randSeed)
	require.NoError(t, err)

	pubKeys := make([]types.PublicKey, len(privKeys))
	for i, voter := range privKeys {
		pubKeys[i] = types.PubKeyToStruct(&voter.PublicKey)
	}
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: nextPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}

	action := testutils.BuildMockDirectAction(t, op.Policy, op.InitializePolicy, req)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
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
	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEInfo, req)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan

	require.Equal(t, uint8(1), actionResponse.Result.Status)

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

func generateWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeId common.Address,
	walletId [32]byte,
	keyId uint64,
	privKeys []*ecdsa.PrivateKey,
	adminWalletPublicKeys []cwallet.PublicKey,
	rewardEpochId uint32,
	wStorage *wallets.Storage) *cwallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := cwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   op.XRP.Hash(),
		ConfigConstants: cwallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0), // todo: add cosigners
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action, err := testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyGenerate, originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	response := <-actionResponseChan
	t.Log(response.Result.Log)
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response.Result.Data)
	require.NoError(t, err)

	newWallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletId, KeyID: keyId})
	require.NoError(t, err)

	require.Equal(t, newWallet.ExternalAddress, walletExistenceProof.AddressStr)

	// generate action sent when voting closed
	action, err = testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyGenerate, originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	response = <-actionResponseChan

	t.Log(response.Result.Log)
	require.Equal(t, uint8(1), response.Result.Status)

	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(response.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return walletExistenceProof
}

func signTransaction(t *testing.T, actionInfoChan chan *types.Action, actionResponseChan chan *types.ActionResponse,
	teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32) {
	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         walletId,
		TeeIdKeyIdPairs:  []payment.TeeIdKeyIdPair{{TeeId: teeId, KeyId: keyId}},
		SenderAddress:    "ravbaTwRkNqecy9Zdw8zwrw4uK5awjqhFd",
		RecipientAddress: "rrrrrrrrrrrrrrrrrNAMEtxvNvQ",
		Amount:           big.NewInt(1000000000),
		Fee:              big.NewInt(10),
		PaymentReference: [32]byte{},
		Nonce:            0,
		SubNonce:         0,
		BatchEndTs:       0,
	}

	originalMessageEncoded, err := abi.Arguments{payment.MessageArguments[op.Pay]}.Pack(originalMessage)
	require.NoError(t, err)

	action, err := testutils.BuildMockInstructionAction(
		op.XRP, op.Pay, originalMessageEncoded, privKeys, teeId, rewardEpochId, []byte{}, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	// generate action sent when voting closed
	action, err = testutils.BuildMockInstructionAction(
		op.XRP, op.Pay, originalMessageEncoded, privKeys, teeId, rewardEpochId, []byte{}, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
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
	privKeys []*ecdsa.PrivateKey, rewardEpochId uint32, nonce *big.Int, wStorage *wallets.Storage) {
	originalMessage := cwallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyDelete]}.Pack(originalMessage)
	require.NoError(t, err)

	action, err := testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyDelete, originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)

	_, err = wStorage.Get(wallets.KeyIDPair{WalletID: walletId, KeyID: keyId})
	require.Error(t, err)

	// generate action sent when voting closed
	action, err = testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyDelete, originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
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
	message := wallets.KeyIDPair{
		WalletID: walletId,
		KeyID:    keyId,
	}

	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEBackup, message)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err := utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var backupResponse wallets.TEEBackupResponse
	err = json.Unmarshal(actionResponse.Result.Data, &backupResponse)
	require.NoError(t, err)

	var backup backup.WalletBackup
	err = json.Unmarshal(backupResponse.WalletBackup, &backup)
	require.NoError(t, err)

	return &backup
}

func recoverWallet(t *testing.T, actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse, teeId common.Address, teePubKey *ecdsa.PublicKey, walletId [32]byte, keyId uint64,
	providersPrivKeys, adminsPrivKeys []*ecdsa.PrivateKey, rewardEpochId uint32, nonce *big.Int,
	walletBackup *backup.WalletBackup, wStorage *wallets.Storage) *cwallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := cwallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeeId:     teeId,
		BackupUrl: "blabla",
		Nonce:     nonce,
		BackupId: cwallet.ITeeWalletBackupManagerBackupId{
			TeeId:         teeId,
			WalletId:      walletId,
			KeyId:         keyId,
			OpType:        op.XRP.Hash(),
			PublicKey:     append(walletBackup.PublicKey.X[:], walletBackup.PublicKey.Y[:]...),
			RewardEpochId: big.NewInt(int64(rewardEpochId)),
			RandomNonce:   new(big.Int).SetBytes(walletBackup.RandomNonce[:]),
		},
	}

	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyDataProviderRestore]}.Pack(originalMessage)
	require.NoError(t, err)

	additionalFixedMessage := walletBackup.WalletBackupMetaData

	adminAndProvider := make(map[common.Address]int)
	adminAddresses := make([]common.Address, len(adminsPrivKeys))
	for j, adminPrivKey := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(adminPrivKey.PublicKey)
		for _, providerPrivKey := range providersPrivKeys {
			if address == crypto.PubkeyToAddress(providerPrivKey.PublicKey) {
				adminAndProvider[address] = j
			}
		}
		adminAddresses[j] = address
	}
	adminsThreshold := uint64(len(adminAddresses))

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

	action, err := testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyDataProviderRestore, originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages, adminAddresses, adminsThreshold,
		types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	response := <-actionResponseChan
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response.Result.Data)
	require.NoError(t, err)

	// check that commonwallet is actually on the tee
	commonwallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletId, KeyID: keyId})
	require.NoError(t, err)
	require.Equal(t, walletId[:], commonwallet.WalletID[:])
	require.Equal(t, keyId, commonwallet.KeyID)

	// generate action sent when voting closed
	action, err = testutils.BuildMockInstructionAction(
		op.Wallet, op.KeyDataProviderRestore, originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages, adminAddresses, adminsThreshold,
		types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	response = <-actionResponseChan
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(response.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return walletExistenceProof
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
		Challenge: challenge,
		TeeMachine: verification.ITeeMachineRegistryTeeMachineWithAttestationData{
			TeeId:        teeId,
			InitialTeeId: teeId,
			Url:          "bla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
	}

	originalMessageEncoded, err := abi.Arguments{verification.MessageArguments[op.TEEAttestation]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action, err := testutils.BuildMockInstructionAction(
		op.Reg, op.TEEAttestation, originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
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
	action, err = testutils.BuildMockInstructionAction(
		op.Reg, op.TEEAttestation, originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
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
		cosignerAddresses[j] = crypto.PubkeyToAddress(cosignerPrivKey.PublicKey)
		for _, providerPrivKey := range providerPrivKeys {
			if cosignerAddresses[j] == crypto.PubkeyToAddress(providerPrivKey.PublicKey) {
				cosignerAndProvider[cosignerAddresses[j]] = true
			}
		}
	}
	cosignersThreshold := uint64(len(cosignerAddresses) / 2)
	originalMessage := connector.IFtdcHubFtdcAttestationRequest{
		Header: connector.IFtdcHubFtdcRequestHeader{
			AttestationType: [32]byte{},
			SourceId:        common.Hash{},
			ThresholdBIPS:   uint16(testutils.TotalWeight * 0.6),
		},
		RequestBody: make([]byte, 10),
	}

	originalMessageEncoded, err := ftdc.EncodeRequest(originalMessage)
	require.NoError(t, err)

	challenge, err := testutils.GenerateRandomBytes(32)
	require.NoError(t, err)

	additionalFixedMessage := verification.ITeeVerificationTeeAttestation{
		TeeMachine: verification.ITeeMachineRegistryTeeMachineWithAttestationData{
			TeeId:        teeId,
			InitialTeeId: common.Address{},
			Url:          "blabla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
		Challenge: [32]byte(challenge),
	}

	additionalFixedMessageEncoded, err := types.EncodeTeeAttestationRequest(&additionalFixedMessage)
	require.NoError(t, err)

	timestamp := uint64(time.Now().Unix())
	ftdcMsgHash, _, _, err := ftdc.HashMessage(originalMessage, additionalFixedMessageEncoded, cosignerAddresses, cosignersThreshold, timestamp)
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
		if _, check := cosignerAndProvider[crypto.PubkeyToAddress(privKey.PublicKey)]; check {
			continue
		}
		variableMessage, err := utils.Sign(ftdcMsgHash[:], privKey)
		require.NoError(t, err)

		variableMessages = append(variableMessages, variableMessage)
		privKeys = append(privKeys, privKey)
	}

	action, err := testutils.BuildMockInstructionAction(
		op.FTDC, op.Prove, originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessageEncoded, variableMessages, cosignerAddresses, cosignersThreshold, types.Threshold, timestamp,
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var ftdcResponse ftdc.ProveResponse
	err = json.Unmarshal(actionResponse.Result.Data, &ftdcResponse)
	require.NoError(t, err)

	err = utils.VerifySignature(ftdcMsgHash.Bytes(), ftdcResponse.TEESignature, teeId)
	require.NoError(t, err)

	require.Equal(t, len(ftdcResponse.CosignerSignatures), len(cosignerPrivKeys))
	for _, signature := range ftdcResponse.CosignerSignatures {
		_, err = utils.CheckSignature(ftdcMsgHash.Bytes(), signature, cosignerAddresses)
		require.NoError(t, err)
	}
	require.Equal(t, ftdcResponse.ResponseBody, additionalFixedMessageEncoded)

	// generate action sent when voting closed
	action, err = testutils.BuildMockInstructionAction(
		op.FTDC, op.Prove, originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessageEncoded, variableMessages, cosignerAddresses, cosignersThreshold, types.End, timestamp,
	)
	require.NoError(t, err)

	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func MockProxy(t *testing.T, proxyPort int, mainActionInfoChan, readActionInfoChan chan *types.Action,
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

	router.HandleFunc("/queue/direct", func(w http.ResponseWriter, r *http.Request) {
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
