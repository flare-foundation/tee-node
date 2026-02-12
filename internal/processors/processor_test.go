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
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"

	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/flare-foundation/tee-node/internal/router"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/ftdc"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/flare-foundation/tee-node/pkg/wallets"

	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/stretchr/testify/require"
)

// todo: add cosigners to commonwallet, check xrp signature, verify signer sequence data (vote hash), verify encoded data provider signatures in FTDC
func TestProcessorsEndToEnd(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, startingEpochID := 100, uint32(1)
	finalEpochID := startingEpochID + 1

	providerAddresses, providerPrivKeys, _ := testutils.GenerateRandomKeys(t, numVoters)

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
	adminWalletPublicKeys := make([]wallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		pk := types.PubKeyToStruct(pubKey)
		adminWalletPublicKeys[i] = wallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	mainActionInfoChan := make(chan *types.Action, 100)
	readActionInfoChan := make(chan *types.Action, 100)
	actionResponseChan := make(chan *types.ActionResponse, 100)
	proxyPort := 8008 // Use different port for MockProxy
	go MockProxy(t, proxyPort, mainActionInfoChan, readActionInfoChan, actionResponseChan)

	pc := settings.NewConfigServer(settings.ConfigPort, testNode) // Use original port for ProxyConfigureServer

	go pc.Serve() //nolint:errcheck

	r := router.NewPMWRouter(testNode, wStorage, pStorage, pc.ProxyURL)

	go r.Run(testNode)
	time.Sleep(1 * time.Second)

	setProxyURL(t, proxyPort, settings.ConfigPort)

	teeID, teePubKey := getTeeInfo(t, readActionInfoChan, actionResponseChan)

	initializePolicy(t, mainActionInfoChan, actionResponseChan, providerPrivKeys, providerAddresses,
		startingEpochID)

	var walletID = common.HexToHash("0xabcdef")
	var keyID = uint64(1)
	walletProof := generateWallet(t, mainActionInfoChan, actionResponseChan, teeID, walletID, keyID,
		providerPrivKeys, adminWalletPublicKeys, finalEpochID, wStorage)
	require.False(t, walletProof.Restored)

	signTransaction(t, mainActionInfoChan, actionResponseChan, teeID, walletID, keyID, providerPrivKeys, finalEpochID)

	walletBackup := getBackup(t, readActionInfoChan, actionResponseChan, teeID, walletID, keyID)

	nonce := big.NewInt(1)
	deleteWallet(t, mainActionInfoChan, actionResponseChan, teeID, walletID, keyID, providerPrivKeys, finalEpochID, nonce, wStorage)
	nonce.Add(nonce, common.Big1)

	recoveredWalletProof := recoverWallet(t, mainActionInfoChan, actionResponseChan, teeID, teePubKey, walletID, keyID,
		providerPrivKeys, adminPrivKeys, finalEpochID, nonce, walletBackup, wStorage)
	walletProof.Restored = true

	walletProof.Nonce = nonce
	require.Equal(t, walletProof, recoveredWalletProof)

	getTeeAttestation(t, mainActionInfoChan, actionResponseChan, teeID,
		providerPrivKeys, finalEpochID)

	ftdcProve(t, mainActionInfoChan, actionResponseChan, teeID, providerPrivKeys, adminPrivKeys, finalEpochID)

	// todo: update policy
}

func setProxyURL(t *testing.T, proxyPort, setProxyPort int) {
	t.Helper()

	url := fmt.Sprintf("http://localhost:%d", proxyPort)
	request := types.ConfigureProxyURLRequest{
		URL: &url,
	}

	client := http.Client{
		Timeout: settings.ProxyTimeout,
	}
	requestBody, err := json.Marshal(request)
	require.NoError(t, err)

	r, err := client.Post(fmt.Sprintf("http://localhost:%d%s", setProxyPort, settings.SetProxyURLEndpoint), "application/json", bytes.NewBuffer(requestBody))
	require.NoError(t, err)
	require.Equal(t, r.StatusCode, http.StatusOK)

	err = r.Body.Close()
	require.NoError(t, err)
}

func initializePolicy(t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	privKeys []*ecdsa.PrivateKey,
	addresses []common.Address,
	startingEpochID uint32,
) {
	t.Helper()

	// initialize policy
	randSeed := int64(12345)

	nextPolicy := testutils.GenerateRandomPolicyData(t, startingEpochID+1, addresses, randSeed)

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
	require.Equal(t, uint8(1), actionResponse.Result.Status, actionResponse.Result.Log)
}

func getTeeInfo(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
) (common.Address, *ecdsa.PublicKey) {
	t.Helper()

	challenge, err := random.Hash()
	require.NoError(t, err)
	req := &types.TeeInfoRequest{
		Challenge: challenge,
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

	teeID := crypto.PubkeyToAddress(*teePubKey)

	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	return teeID, teePubKey
}

func generateWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	privKeys []*ecdsa.PrivateKey,
	adminWalletPublicKeys []wallet.PublicKey,
	rewardEpochID uint32,
	wStorage *wallets.Storage) *wallet.ITeeWalletKeyManagerKeyExistence {
	t.Helper()

	originalMessage := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:       teeID,
		WalletId:    walletID,
		KeyId:       keyID,
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPAlgo,
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0), // todo: add cosigners
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[op.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyGenerate, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response := <-actionResponseChan
	t.Log(response.Result.Log)
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeID)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response.Result.Data, teeID)
	require.NoError(t, err)

	newWallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)

	require.Equal(t, newWallet.WalletID, common.Hash(walletExistenceProof.WalletId))
	require.Equal(t, newWallet.KeyID, walletExistenceProof.KeyId)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyGenerate, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response = <-actionResponseChan

	t.Log(response.Result.Log)
	require.Equal(t, uint8(1), response.Result.Status)

	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(response.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)

	return walletExistenceProof
}

func signTransaction(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
) {
	t.Helper()

	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         walletID,
		TeeIdKeyIdPairs:  []payment.TeeIdKeyIdPair{{TeeId: teeID, KeyId: keyID}},
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

	action := testutils.BuildMockInstructionAction(
		t, op.XRP, op.Pay, originalMessageEncoded, privKeys, teeID, rewardEpochID, []byte{}, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.XRP, op.Pay, originalMessageEncoded, privKeys, teeID, rewardEpochID, []byte{}, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func deleteWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
	nonce *big.Int,
	wStorage *wallets.Storage,
) {
	t.Helper()

	originalMessage := wallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    teeID,
		WalletId: walletID,
		KeyId:    keyID,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[op.KeyDelete]}.Pack(originalMessage)
	require.NoError(t, err)

	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDelete, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)

	_, err = wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.Error(t, err)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDelete, originalMessageEncoded, privKeys, teeID, rewardEpochID, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func getBackup(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	walletID [32]byte,
	keyID uint64,
) *backup.WalletBackup {
	t.Helper()

	message := wallets.KeyIDPair{
		WalletID: walletID,
		KeyID:    keyID,
	}

	action := testutils.BuildMockDirectAction(t, op.Get, op.TEEBackup, message)

	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err := utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var backupResponse wallets.TEEBackupResponse
	err = json.Unmarshal(actionResponse.Result.Data, &backupResponse)
	require.NoError(t, err)

	var backup backup.WalletBackup
	err = json.Unmarshal(backupResponse.WalletBackup, &backup)
	require.NoError(t, err)

	backupHash, err := backup.HashForSigning()
	require.NoError(t, err)
	err = utils.VerifySignature(backupHash[:], backup.TEESignature, teeID)
	require.NoError(t, err)

	backupPubKey, err := types.ParsePubKeyBytes(backup.PublicKey)
	require.NoError(t, err)
	err = utils.VerifySignature(backupHash[:], backup.Signature, crypto.PubkeyToAddress(*backupPubKey))
	require.NoError(t, err)

	return &backup
}

func recoverWallet(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	teePubKey *ecdsa.PublicKey,
	walletID [32]byte,
	keyID uint64,
	providersPrivKeys,
	adminsPrivKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
	nonce *big.Int,
	walletBackup *backup.WalletBackup,
	wStorage *wallets.Storage,
) *wallet.ITeeWalletKeyManagerKeyExistence {
	t.Helper()

	teePubKeyParsed := types.PubKeyToStruct(teePubKey)

	originalMessage := wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeePublicKey: wallet.PublicKey{X: teePubKeyParsed.X, Y: teePubKeyParsed.Y},
		BackupUrl:    "blabla",
		Nonce:        nonce,
		BackupId: wallet.ITeeWalletBackupManagerBackupId{
			TeeId:         teeID,
			WalletId:      walletID,
			KeyId:         keyID,
			KeyType:       wallets.XRPType,
			SigningAlgo:   wallets.XRPAlgo,
			PublicKey:     walletBackup.PublicKey,
			RewardEpochId: rewardEpochID,
			RandomNonce:   walletBackup.RandomNonce,
		},
	}

	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[op.KeyDataProviderRestore]}.Pack(originalMessage)
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

	teeEciesPubKey, err := utils.ECDSAPubKeyToECIES(teePubKey)
	require.NoError(t, err)

	additionalVariableMessages := make([][]byte, 0, len(providersPrivKeys)+len(adminsPrivKeys))
	privKeys := make([]*ecdsa.PrivateKey, 0, len(providersPrivKeys)+len(adminsPrivKeys))
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

	action := testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDataProviderRestore, originalMessageEncoded, privKeys, teeID,
		rewardEpochID, additionalFixedMessage, additionalVariableMessages, adminAddresses, adminsThreshold,
		types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response := <-actionResponseChan
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeID)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response.Result.Data, teeID)
	require.NoError(t, err)

	// check that commonwallet is actually on the tee
	commonwallet, err := wStorage.Get(wallets.KeyIDPair{WalletID: walletID, KeyID: keyID})
	require.NoError(t, err)
	require.Equal(t, walletID[:], commonwallet.WalletID[:])
	require.Equal(t, keyID, commonwallet.KeyID)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Wallet, op.KeyDataProviderRestore, originalMessageEncoded, privKeys, teeID,
		rewardEpochID, additionalFixedMessage, additionalVariableMessages, adminAddresses, adminsThreshold,
		types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	response = <-actionResponseChan
	require.Equal(t, uint8(1), response.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(response.Result.Data), response.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(response.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)

	return walletExistenceProof
}

func getTeeAttestation(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32,
) {
	t.Helper()

	challenge, err := random.Hash()
	require.NoError(t, err)

	originalMessage := verification.ITeeVerificationTeeAttestation{
		Challenge: challenge,
		TeeMachine: verification.ITeeMachineRegistryTeeMachineWithAttestationData{
			TeeId:        teeID,
			InitialTeeId: teeID,
			Url:          "bla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
	}

	originalMessageEncoded, err := abi.Arguments{verification.MessageArguments[op.TEEAttestation]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action := testutils.BuildMockInstructionAction(
		t, op.Reg, op.TEEAttestation, originalMessageEncoded, privKeys, teeID, rewardEpochId, nil, nil, nil, 0, types.Threshold, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.Data, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.TeeInfo.PublicKey)
	require.NoError(t, err)

	receivedTeeID := crypto.PubkeyToAddress(*teePubKey)
	require.Equal(t, receivedTeeID, teeID)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.Reg, op.TEEAttestation, originalMessageEncoded, privKeys, teeID, rewardEpochId, nil, nil, nil, 0, types.End, uint64(time.Now().Unix()),
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func ftdcProve(
	t *testing.T,
	actionInfoChan chan *types.Action,
	actionResponseChan chan *types.ActionResponse,
	teeID common.Address,
	providerPrivKeys, cosignerPrivKeys []*ecdsa.PrivateKey,
	rewardEpochID uint32,
) {
	t.Helper()

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
			ThresholdBIPS:   6000,
		},
		RequestBody: make([]byte, 10),
	}

	originalMessageEncoded, err := ftdc.EncodeRequest(originalMessage)
	require.NoError(t, err)

	challenge, err := random.Hash()
	require.NoError(t, err)

	additionalFixedMessage := verification.ITeeVerificationTeeAttestation{
		TeeMachine: verification.ITeeMachineRegistryTeeMachineWithAttestationData{
			TeeId:        teeID,
			InitialTeeId: common.Address{},
			Url:          "blabla",
			CodeHash:     [32]byte{},
			Platform:     [32]byte{},
		},
		Challenge: challenge,
	}

	additionalFixedMessageEncoded, err := types.EncodeTeeAttestationRequest(&additionalFixedMessage)
	require.NoError(t, err)

	timestamp := uint64(time.Now().Unix())
	ftdcMsgHash, _, _, err := ftdc.HashMessage(originalMessage, additionalFixedMessageEncoded, cosignerAddresses, cosignersThreshold, timestamp)
	require.NoError(t, err)

	variableMessages := make([][]byte, 0, len(providerPrivKeys)+len(cosignerPrivKeys))
	privKeys := make([]*ecdsa.PrivateKey, 0, len(providerPrivKeys)+len(cosignerPrivKeys))
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

	action := testutils.BuildMockInstructionAction(
		t, op.FTDC, op.Prove, originalMessageEncoded, privKeys, teeID, rewardEpochID,
		additionalFixedMessageEncoded, variableMessages, cosignerAddresses, cosignersThreshold,
		types.Threshold, timestamp,
	)
	actionInfoChan <- action

	actionResponse := <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var ftdcResponse ftdc.ProveResponse
	err = json.Unmarshal(actionResponse.Result.Data, &ftdcResponse)
	require.NoError(t, err)

	err = utils.VerifySignature(ftdcMsgHash.Bytes(), ftdcResponse.TEESignature, teeID)
	require.NoError(t, err)

	require.Equal(t, len(ftdcResponse.CosignerSignatures), len(cosignerPrivKeys))
	for _, signature := range ftdcResponse.CosignerSignatures {
		_, err = utils.CheckSignature(ftdcMsgHash.Bytes(), signature, cosignerAddresses)
		require.NoError(t, err)
	}
	require.Equal(t, ftdcResponse.ResponseBody, additionalFixedMessageEncoded)

	// generate action sent when voting closed
	action = testutils.BuildMockInstructionAction(
		t, op.FTDC, op.Prove, originalMessageEncoded, privKeys, teeID, rewardEpochID,
		additionalFixedMessageEncoded, variableMessages, cosignerAddresses, cosignersThreshold,
		types.End, timestamp,
	)
	actionInfoChan <- action

	actionResponse = <-actionResponseChan
	require.Equal(t, uint8(1), actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.Data), actionResponse.Signature, teeID)
	require.NoError(t, err)

	var signerSequence types.RewardingData
	err = json.Unmarshal(actionResponse.Result.Data, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.VoteSequence.VoteHash[:], signerSequence.Signature, teeID)
	require.NoError(t, err)
}

func MockProxy(t *testing.T, proxyPort int, mainChan, readChan chan *types.Action, respChan chan *types.ActionResponse) {
	t.Helper()

	router := http.NewServeMux()

	router.HandleFunc("POST /queue/main", func(w http.ResponseWriter, r *http.Request) {
		var action types.Action
		select {
		case x := <-mainChan:
			action = *x
		default:
			action = types.Action{}
		}

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	})

	router.HandleFunc("POST /queue/direct", func(w http.ResponseWriter, r *http.Request) {
		var action types.Action
		select {
		case x := <-readChan:
			action = *x
		default:
			action = types.Action{}
		}

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	})

	router.HandleFunc("POST /result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionResponse types.ActionResponse
		err = json.Unmarshal(body, &actionResponse)
		require.NoError(t, err)
		respChan <- &actionResponse
		err = r.Body.Close()
		require.NoError(t, err)
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), router))
}
