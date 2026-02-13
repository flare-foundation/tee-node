package walletutils_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/flare-foundation/tee-node/internal/processors/instructions/walletutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	commonpolicy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"github.com/flare-foundation/go-flare-common/pkg/random"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	cwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

// * ========================== KEY GENERATE ========================== *

// keyGenerateTestSetup holds common test setup data for key generation tests
type keyGenerateTestSetup struct {
	testNode              *node.Node
	pStorage              *policy.Storage
	wStorage              *wallets.Storage
	walletID              common.Hash
	keyID                 uint64
	teeID                 common.Address
	adminPubKeys          []*ecdsa.PublicKey
	adminPrivKeys         []*ecdsa.PrivateKey
	adminWalletPublicKeys []cwallet.PublicKey
	cosignerPrivKeys      []*ecdsa.PrivateKey
	cosigners             []common.Address
	epochID               uint32
	processor             walletutils.Processor
}

// setupKeyGenerateTest creates a standard test environment for key generation tests
func setupKeyGenerateTest(t *testing.T) *keyGenerateTestSetup {
	t.Helper()

	testNode, pStorage, wStorage := testutils.Setup(t)

	numAdmins := 3
	adminPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	var err error
	for i := range numAdmins {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminPubKeys[i] = &adminPrivKeys[i].PublicKey
	}
	adminWalletPublicKeys := make([]cwallet.PublicKey, len(adminPubKeys))
	for i, pubKey := range adminPubKeys {
		pk := types.PubKeyToStruct(pubKey)
		adminWalletPublicKeys[i] = cwallet.PublicKey{
			X: pk.X,
			Y: pk.Y,
		}
	}

	numCosigners := 10
	cosignerPrivKeys := make([]*ecdsa.PrivateKey, numCosigners)
	cosigners := make([]common.Address, numCosigners)
	for i := range numCosigners {
		cosignerPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		cosigners[i] = crypto.PubkeyToAddress(cosignerPrivKeys[i].PublicKey)
	}

	numVoters, randSeed, epochID := 100, int64(12345), uint32(1)
	testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)
	require.NoError(t, err)

	return &keyGenerateTestSetup{
		testNode:              testNode,
		pStorage:              pStorage,
		wStorage:              wStorage,
		walletID:              common.HexToHash("0xabcdef"),
		keyID:                 1,
		teeID:                 testNode.TeeID(),
		adminPubKeys:          adminPubKeys,
		adminPrivKeys:         adminPrivKeys,
		adminWalletPublicKeys: adminWalletPublicKeys,
		cosignerPrivKeys:      cosignerPrivKeys,
		cosigners:             cosigners,
		epochID:               epochID,
		processor:             walletutils.NewProcessor(testNode, pStorage, wStorage),
	}
}

// buildKeyGenerateInstruction creates a key generation instruction with the given parameters
func (s *keyGenerateTestSetup) buildKeyGenerateInstruction(t *testing.T, msg cwallet.ITeeWalletKeyManagerKeyGenerate) *instruction.DataFixed {
	t.Helper()

	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyGenerate]}.Pack(msg)
	require.NoError(t, err)

	instructionID, err := random.Hash()
	require.NoError(t, err)

	return &instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  s.teeID,
		RewardEpochID:          s.epochID,
		OPType:                 op.Wallet.Hash(),
		OPCommand:              op.KeyGenerate.Hash(),
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: nil,
	}
}

// defaultKeyGenerateMessage creates a valid key generation message with default parameters
func (s *keyGenerateTestSetup) defaultKeyGenerateMessage() cwallet.ITeeWalletKeyManagerKeyGenerate {
	return cwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:       s.teeID,
		WalletId:    s.walletID,
		KeyId:       s.keyID,
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPAlgo,
		ConfigConstants: cwallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   s.adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(s.adminWalletPublicKeys)),
			Cosigners:          s.cosigners,
			CosignersThreshold: uint64(len(s.cosigners)),
		},
	}
}

func TestKeyGenerate(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	response, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.NoError(t, err)

	walletExistenceProof, err := wallets.ExtractKeyExistence(response, setup.teeID)
	require.NoError(t, err)

	require.Equal(t, setup.teeID, walletExistenceProof.TeeId)
	require.Equal(t, [32]byte(setup.walletID), walletExistenceProof.WalletId)
	require.Equal(t, setup.keyID, walletExistenceProof.KeyId)
	require.Equal(t, "0", walletExistenceProof.Nonce.String())
	require.Equal(t, false, walletExistenceProof.Restored)
	require.Equal(t, [32]byte(wallets.XRPAlgo), walletExistenceProof.SigningAlgo)
	require.Equal(t, [32]byte(wallets.XRPType), walletExistenceProof.KeyType)

	setup.wStorage.RLock()
	defer setup.wStorage.RUnlock()

	allWallets := setup.wStorage.GetWallets()
	require.Len(t, allWallets, 1)
}

func TestKeyGenerateNoCosigners(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.ConfigConstants.Cosigners = []common.Address{}
	msg.ConfigConstants.CosignersThreshold = 0
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.NoError(t, err)
}

func TestKeyGenerateInvalidTeeID(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.TeeId = common.HexToAddress("0x1234567890123456789012345678901234567890") // Wrong TEE ID
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "teeID does not match")
}

func TestKeyGenerateNoAdminPublicKeys(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.ConfigConstants.AdminsPublicKeys = []cwallet.PublicKey{} // Empty admin keys
	msg.ConfigConstants.AdminsThreshold = 0
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no admin public keys")
}

func TestKeyGenerateUnsupportedSigningAlgo(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.SigningAlgo = utils.ToHash("BLS") // Unsupported algorithm
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signing algorithm not supported")
}

func TestKeyGenerateDuplicateWallet(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	// First generation should succeed
	response, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Second generation with same wallet ID and key ID should fail
	_, _, err = setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestKeyGenerateAfterDeleteSameWalletFails(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	generateMsg := setup.defaultKeyGenerateMessage()
	generateInstruction := setup.buildKeyGenerateInstruction(t, generateMsg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, generateInstruction, nil, nil, nil)
	require.NoError(t, err)

	deleteMsg := cwallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    setup.teeID,
		WalletId: setup.walletID,
		KeyId:    setup.keyID,
		Nonce:    big.NewInt(1),
	}
	deleteInstructionBuilder := &keyDeleteTestSetup{
		teeID:   setup.teeID,
		epochID: setup.epochID,
	}
	deleteInstruction := deleteInstructionBuilder.buildKeyDeleteInstruction(t, deleteMsg)

	_, _, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction, nil, nil, nil)
	require.NoError(t, err)

	_, _, err = setup.processor.KeyGenerate(types.Threshold, generateInstruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "permanent record")
}

func TestKeyGenerateThresholdExceedsAdmins(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.ConfigConstants.AdminsThreshold = uint64(len(setup.adminWalletPublicKeys) + 10) // Threshold exceeds number of admins
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "admins threshold cannot be greater than the number of admins")
}

func TestKeyGenerateZeroThreshold(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.ConfigConstants.AdminsThreshold = 0 // Zero threshold
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "admins threshold cannot be zero")
}

func TestKeyGenerateThresholdExceedsCosigners(t *testing.T) {
	setup := setupKeyGenerateTest(t)

	msg := setup.defaultKeyGenerateMessage()
	msg.ConfigConstants.CosignersThreshold = uint64(len(setup.cosigners) + 10) // Threshold exceeds number of admins
	instruction := setup.buildKeyGenerateInstruction(t, msg)

	_, _, err := setup.processor.KeyGenerate(types.Threshold, instruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cosigners threshold cannot be greater than the number of cosigners")
}

func TestParseKeyGenerateNilData(t *testing.T) {
	instructionData := &instruction.DataFixed{
		OriginalMessage: nil,
	}

	_, err := wallets.ParseKeyGenerate(instructionData)
	require.Error(t, err)
}

func TestParseKeyGenerateEmptyData(t *testing.T) {
	instructionData := &instruction.DataFixed{
		OriginalMessage: []byte{},
	}

	_, err := wallets.ParseKeyGenerate(instructionData)
	require.Error(t, err)
}

func TestParseKeyGenerateInvalidData(t *testing.T) {
	randomData, err := random.Bytes(928)
	require.NoError(t, err)

	instructionData := &instruction.DataFixed{
		OriginalMessage: randomData,
	}

	_, err = wallets.ParseKeyGenerate(instructionData)
	require.Error(t, err)
}

// * ========================== KEY DELETE ========================== *

// keyDeleteTestSetup holds common test setup data for key deletion tests
type keyDeleteTestSetup struct {
	testNode     *node.Node
	pStorage     *policy.Storage
	wStorage     *wallets.Storage
	walletID     common.Hash
	keyID        uint64
	teeID        common.Address
	adminPrivKey *ecdsa.PrivateKey
	epochID      uint32
	processor    walletutils.Processor
}

// setupKeyDeleteTest creates a standard test environment for key deletion tests
func setupKeyDeleteTest(t *testing.T) *keyDeleteTestSetup {
	t.Helper()

	testNode, pStorage, wStorage := testutils.Setup(t)

	numVoters, randSeed, epochID := 50, int64(6789), uint32(3)
	testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)

	adminPrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	walletID := common.HexToHash("0xdeadbeef")
	var keyID uint64 = 7

	// Create a mock wallet to delete
	testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, epochID, []*ecdsa.PrivateKey{adminPrivKey}, nil)

	return &keyDeleteTestSetup{
		testNode:     testNode,
		pStorage:     pStorage,
		wStorage:     wStorage,
		walletID:     walletID,
		keyID:        keyID,
		teeID:        testNode.TeeID(),
		adminPrivKey: adminPrivKey,
		epochID:      epochID,
		processor:    walletutils.NewProcessor(testNode, pStorage, wStorage),
	}
}

// buildKeyDeleteInstruction creates a key deletion instruction with the given parameters
func (s *keyDeleteTestSetup) buildKeyDeleteInstruction(t *testing.T, msg cwallet.ITeeWalletKeyManagerKeyDelete) *instruction.DataFixed {
	t.Helper()

	encodedDeleteReq, err := abi.Arguments{cwallet.MessageArguments[op.KeyDelete]}.Pack(msg)
	require.NoError(t, err)

	instructionID, err := random.Hash()
	require.NoError(t, err)

	return &instruction.DataFixed{
		InstructionID:   instructionID,
		TeeID:           s.teeID,
		RewardEpochID:   s.epochID,
		OPType:          op.Wallet.Hash(),
		OPCommand:       op.KeyDelete.Hash(),
		OriginalMessage: encodedDeleteReq,
	}
}

// defaultKeyDeleteMessage creates a valid key deletion message with default parameters
func (s *keyDeleteTestSetup) defaultKeyDeleteMessage(nonce uint64) cwallet.ITeeWalletKeyManagerKeyDelete {
	return cwallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    s.teeID,
		WalletId: s.walletID,
		KeyId:    s.keyID,
		Nonce:    big.NewInt(int64(nonce)),
	}
}

func TestKeyDelete(t *testing.T) {
	setup := setupKeyDeleteTest(t)

	// check the nonce is zero
	nonce, err := setup.wStorage.Nonce(wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID})
	require.NoError(t, err)
	require.Equal(t, uint64(0), nonce)

	msg := setup.defaultKeyDeleteMessage(1)
	deleteInstruction := setup.buildKeyDeleteInstruction(t, msg)

	encID, status, err := setup.processor.KeyDelete(types.Threshold, deleteInstruction, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, status)

	var idPair wallets.KeyIDPair
	err = json.Unmarshal(encID, &idPair)
	require.NoError(t, err)

	require.Equal(t, idPair.KeyID, setup.keyID)
	require.Equal(t, idPair.WalletID, setup.walletID)

	// check that the wallet is deleted
	require.False(t, setup.wStorage.WalletExists(idPair))
	_, err = setup.wStorage.Get(idPair)
	require.Error(t, err)
	require.Equal(t, wallets.ErrWalletNonExistent, err)

	// check that the nonce is updated (the wallet status is persisted)
	nonce, err = setup.wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(1), nonce)

	// reapply not possible
	resp, status, err := setup.processor.KeyDelete(types.End, deleteInstruction, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Nil(t, status)

	// delete already deleted key
	msg = setup.defaultKeyDeleteMessage(2)

	deleteInstruction = setup.buildKeyDeleteInstruction(t, msg)

	encID, status, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("key not stored"), status)

	var idPair2 wallets.KeyIDPair
	err = json.Unmarshal(encID, &idPair2)
	require.NoError(t, err)

	require.Equal(t, idPair2.KeyID, setup.keyID)
	require.Equal(t, idPair2.WalletID, setup.walletID)

	// delete key that never existed deleted key
	msg = setup.defaultKeyDeleteMessage(2)
	msg.WalletId, err = random.Hash()
	require.NoError(t, err)

	deleteInstruction = setup.buildKeyDeleteInstruction(t, msg)

	_, _, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction, nil, nil, nil)
	require.Error(t, err)
}

func TestKeyDeleteEnd(t *testing.T) {
	setup := setupKeyDeleteTest(t)

	// check the nonce is zero
	nonce, err := setup.wStorage.Nonce(wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID})
	require.NoError(t, err)
	require.Equal(t, uint64(0), nonce)

	msg := setup.defaultKeyDeleteMessage(1)
	deleteInstruction := setup.buildKeyDeleteInstruction(t, msg)

	_, _, err = setup.processor.KeyDelete(types.End, deleteInstruction, nil, nil, nil)
	require.Error(t, err)

	_, _, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction, nil, nil, nil)
	require.NoError(t, err)

	_, _, err = setup.processor.KeyDelete(types.End, deleteInstruction, nil, nil, nil)
	require.NoError(t, err)

	// nonce not used
	msg = setup.defaultKeyDeleteMessage(2)
	deleteInstruction = setup.buildKeyDeleteInstruction(t, msg)

	_, _, err = setup.processor.KeyDelete(types.End, deleteInstruction, nil, nil, nil)
	require.Error(t, err)

	// nonexistent key
	msg.WalletId, err = random.Hash()
	require.NoError(t, err)

	deleteInstruction = setup.buildKeyDeleteInstruction(t, msg)
	_, _, err = setup.processor.KeyDelete(types.End, deleteInstruction, nil, nil, nil)
	require.Error(t, err)
}

func TestKeyDeleteInvalidNonce(t *testing.T) {
	setup := setupKeyDeleteTest(t)

	// Verify the initial nonce is 0
	idPair := wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID}
	nonce, err := setup.wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(0), nonce)

	// Try to delete with nonce 0 (same as current) - should fail
	msg := setup.defaultKeyDeleteMessage(0)
	deleteInstruction := setup.buildKeyDeleteInstruction(t, msg)

	_, _, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce too small")

	// Verify wallet still exists
	require.True(t, setup.wStorage.WalletExists(idPair))
}

func TestKeyDeleteNonceTooSmall(t *testing.T) {
	setup := setupKeyDeleteTest(t)

	// Verify nonce was updated to 1
	idPair := wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID}
	nonce, err := setup.wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(0), nonce)

	// Try to delete again with nonce 0 (same as current) - should fail
	msg2 := setup.defaultKeyDeleteMessage(0)
	deleteInstruction2 := setup.buildKeyDeleteInstruction(t, msg2)

	_, _, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction2, nil, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce too small")

	// Verify wallet still exists (wasn't deleted with invalid nonces)
	require.True(t, setup.wStorage.WalletExists(idPair))

	// Finally, delete with correct nonce 2 - should succeed
	msg4 := setup.defaultKeyDeleteMessage(2)
	deleteInstruction4 := setup.buildKeyDeleteInstruction(t, msg4)

	_, _, err = setup.processor.KeyDelete(types.Threshold, deleteInstruction4, nil, nil, nil)
	require.NoError(t, err)

	// Verify wallet is now deleted and nonce is updated
	require.False(t, setup.wStorage.WalletExists(idPair))
	nonce, err = setup.wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(2), nonce)
}

// * ========================== KEY DATA PROVIDER RESTORE ========================== *

// keyDataProviderRestoreTestSetup holds common test setup data for key data provider restore tests
type keyDataProviderRestoreTestSetup struct {
	testNode        *node.Node
	pStorage        *policy.Storage
	wStorage        *wallets.Storage
	walletID        common.Hash
	keyID           uint64
	teeID           common.Address
	epochID         uint32
	adminPrivKeys   []*ecdsa.PrivateKey
	voterPrivKeys   []*ecdsa.PrivateKey
	initialPolicy   *commonpolicy.SigningPolicy
	storedWallet    *wallets.Wallet
	walletBackup    *pkgbackup.WalletBackup
	weights         []uint16
	teePubKey       *ecdsa.PublicKey
	eciesPub        *ecies.PublicKey
	processor       walletutils.Processor
	nonce           uint64
	numAdmins       int
	adminThreshold  int
	providerPubKeys []*ecdsa.PublicKey
}

func setupAdminsAndProviders(
	t *testing.T,
	numAdmins int,
	pStorage *policy.Storage,
	numVoters int,
	randSeed int64,
	epochID uint32,
) (*commonpolicy.SigningPolicy, []*ecdsa.PrivateKey, []*ecdsa.PrivateKey) {
	t.Helper()

	initialPolicy, _, voterPrivKeys := testutils.GenerateAndSetInitialPolicy(t, pStorage, numVoters, randSeed, epochID)
	adminPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	var err error
	for i := range adminPrivKeys {
		adminPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
	}

	return initialPolicy, adminPrivKeys, voterPrivKeys
}

func setupKeyDataProviderRestoreTest(t *testing.T) *keyDataProviderRestoreTestSetup {
	t.Helper()

	testNode, pStorage, wStorage := testutils.Setup(t)

	const (
		numVoters = 6
		randSeed  = int64(4242)
		epochID   = uint32(11)
	)

	numAdmins := 3
	initialPolicy, adminPrivKeys, voterPrivKeys := setupAdminsAndProviders(t, numAdmins, pStorage, numVoters, randSeed, epochID)

	return setupKeyDataProviderRestoreTestWithAdminsAndProviders(t, numAdmins, adminPrivKeys, voterPrivKeys, testNode, pStorage, wStorage, epochID, initialPolicy)
}

// setupKeyDataProviderRestoreTest creates a standard test environment for key data provider restore tests
func setupKeyDataProviderRestoreTestWithAdminsAndProviders(
	t *testing.T,
	numAdmins int,
	adminPrivKeys []*ecdsa.PrivateKey,
	voterPrivKeys []*ecdsa.PrivateKey,
	testNode *node.Node,
	pStorage *policy.Storage,
	wStorage *wallets.Storage,
	epochID uint32,
	initialPolicy *commonpolicy.SigningPolicy,
) *keyDataProviderRestoreTestSetup {
	t.Helper()

	walletID := common.HexToHash("0xbeadfeed")
	var keyID uint64 = 3

	// Create wallet with all admins and one cosigner
	storedWalletProof := testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, epochID, adminPrivKeys, []*ecdsa.PrivateKey{voterPrivKeys[0]})
	_ = storedWalletProof

	idPair := wallets.KeyIDPair{WalletID: walletID, KeyID: keyID}
	storedWallet, err := wStorage.Get(idPair)
	require.NoError(t, err)

	// Simulate wallet removal prior to restore
	wStorage.Remove(idPair)

	providerPubKeys := make([]*ecdsa.PublicKey, len(voterPrivKeys))
	weights := make([]uint16, len(voterPrivKeys))
	for i := range voterPrivKeys {
		providerPubKeys[i] = &voterPrivKeys[i].PublicKey
		weights[i] = initialPolicy.Voters.VoterWeight(i)
	}

	walletBackup, err := backup.BackupWallet(
		storedWallet,
		providerPubKeys,
		weights,
		initialPolicy.RewardEpochID,
		testNode.TeeID(),
		backup.NormalizationConstant,
		backup.DataProvidersThreshold,
	)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(testNode.Info().PublicKey)
	require.NoError(t, err)
	eciesPub := ecies.ImportECDSAPublic(teePubKey)

	return &keyDataProviderRestoreTestSetup{
		testNode:        testNode,
		pStorage:        pStorage,
		wStorage:        wStorage,
		walletID:        walletID,
		keyID:           keyID,
		teeID:           testNode.TeeID(),
		epochID:         epochID,
		adminPrivKeys:   adminPrivKeys,
		voterPrivKeys:   voterPrivKeys,
		initialPolicy:   initialPolicy,
		storedWallet:    storedWallet,
		walletBackup:    walletBackup,
		weights:         weights,
		teePubKey:       teePubKey,
		eciesPub:        eciesPub,
		processor:       walletutils.NewProcessor(testNode, pStorage, wStorage),
		nonce:           2,
		numAdmins:       numAdmins,
		adminThreshold:  numAdmins,
		providerPubKeys: providerPubKeys,
	}
}

// buildVariableMessages creates encrypted key split messages from provider and admin shares
func (s *keyDataProviderRestoreTestSetup) buildVariableMessages(
	t *testing.T,
	numProviders int,
	numAdmins int,
) ([]hexutil.Bytes, []common.Address) {
	t.Helper()

	require.LessOrEqual(t, numProviders, len(s.voterPrivKeys), "numProviders exceeds available voters")
	require.LessOrEqual(t, numAdmins, len(s.adminPrivKeys), "numAdmins exceeds available admins")

	isAdminAndProvider := make([]bool, len(s.adminPrivKeys)+len(s.voterPrivKeys))
	return s.buildVariableMessagesWithAdmins(t, numProviders, numAdmins, isAdminAndProvider)
}

// buildVariableMessages creates encrypted key split messages from provider and admin shares
func (s *keyDataProviderRestoreTestSetup) buildVariableMessagesWithAdmins(
	t *testing.T,
	numProviders int,
	numAdmins int,
	isAdminAndProvider []bool,
) ([]hexutil.Bytes, []common.Address) {
	t.Helper()

	require.LessOrEqual(t, numProviders, len(s.voterPrivKeys), "numProviders exceeds available voters")
	require.LessOrEqual(t, numAdmins, len(s.adminPrivKeys), "numAdmins exceeds available admins")

	variableMessages := make([]hexutil.Bytes, 0, numAdmins+numProviders)
	signers := make([]common.Address, 0, numAdmins+numProviders)

	// Add provider shares
	for i := range numProviders {
		if isAdminAndProvider[i] {
			continue
		}
		share, err := pkgbackup.DecryptSplit(s.walletBackup.ProviderEncryptedParts.Splits[i], s.voterPrivKeys[i])
		require.NoError(t, err)

		var shareBytes []byte
		shareBytes, err = json.Marshal(share)
		require.NoError(t, err)
		cipher, err := ecies.Encrypt(rand.Reader, s.eciesPub, shareBytes, nil, nil)
		require.NoError(t, err)
		variableMessages = append(variableMessages, cipher)
		signers = append(signers, crypto.PubkeyToAddress(s.voterPrivKeys[i].PublicKey))
	}

	// Add admin shares
	for i := range numAdmins {
		if isAdminAndProvider[i] {
			continue
		}
		adminShare, err := pkgbackup.DecryptSplit(s.walletBackup.AdminEncryptedParts.Splits[i], s.adminPrivKeys[i])
		require.NoError(t, err)
		adminShareBytes, err := json.Marshal(adminShare)
		require.NoError(t, err)
		cipher, err := ecies.Encrypt(rand.Reader, s.eciesPub, adminShareBytes, nil, nil)
		require.NoError(t, err)
		variableMessages = append(variableMessages, cipher)
		signers = append(signers, crypto.PubkeyToAddress(s.adminPrivKeys[i].PublicKey))
	}

	for i := range isAdminAndProvider {
		if !isAdminAndProvider[i] {
			continue
		}

		adminShare, err := pkgbackup.DecryptSplit(s.walletBackup.AdminEncryptedParts.Splits[i], s.adminPrivKeys[i])
		require.NoError(t, err)
		providerShare, err := pkgbackup.DecryptSplit(s.walletBackup.ProviderEncryptedParts.Splits[i], s.voterPrivKeys[i])
		require.NoError(t, err)

		bothShares, err := json.Marshal([2]*pkgbackup.KeySplit{adminShare, providerShare})
		require.NoError(t, err)
		cipher, err := ecies.Encrypt(rand.Reader, s.eciesPub, bothShares, nil, nil)
		require.NoError(t, err)
		variableMessages = append(variableMessages, cipher)
		signers = append(signers, crypto.PubkeyToAddress(s.adminPrivKeys[i].PublicKey))
		signers = append(signers, crypto.PubkeyToAddress(s.voterPrivKeys[i].PublicKey))
	}

	return variableMessages, signers
}

// buildDefaultRestoreRequest creates a standard restore request with default values
func (s *keyDataProviderRestoreTestSetup) buildDefaultRestoreRequest(nonce *big.Int) cwallet.ITeeWalletBackupManagerKeyDataProviderRestore {
	backupID := s.walletBackup.WalletBackupID
	return cwallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeePublicKey: cwallet.PublicKey{X: s.testNode.Info().PublicKey.X, Y: s.testNode.Info().PublicKey.Y},
		BackupId: cwallet.ITeeWalletBackupManagerBackupId{
			TeeId:         backupID.TeeID,
			WalletId:      backupID.WalletID,
			KeyId:         backupID.KeyID,
			KeyType:       backupID.KeyType,
			SigningAlgo:   backupID.SigningAlgo,
			PublicKey:     backupID.PublicKey,
			RewardEpochId: backupID.RewardEpochID,
			RandomNonce:   backupID.RandomNonce,
		},
		BackupUrl: "https://example.com/backup",
		Nonce:     nonce,
	}
}

func (s *keyDataProviderRestoreTestSetup) buildRestoreInstruction(
	t *testing.T,
	restoreReq cwallet.ITeeWalletBackupManagerKeyDataProviderRestore,
) *instruction.DataFixed {
	t.Helper()

	encodedRestoreReq, err := abi.Arguments{cwallet.MessageArguments[op.KeyDataProviderRestore]}.Pack(restoreReq)
	require.NoError(t, err)

	metadataBytes, err := json.Marshal(s.walletBackup.WalletBackupMetaData)
	require.NoError(t, err)

	instructionID, err := random.Hash()
	require.NoError(t, err)

	// Cosigners should be admin addresses (as checked by keyDataProviderRestoreCheck)
	adminAddresses := make([]common.Address, len(s.adminPrivKeys))
	for i, adminPrivKey := range s.adminPrivKeys {
		adminAddresses[i] = crypto.PubkeyToAddress(adminPrivKey.PublicKey)
	}

	return &instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  s.teeID,
		RewardEpochID:          s.epochID,
		OPType:                 op.Wallet.Hash(),
		OPCommand:              op.KeyDataProviderRestore.Hash(),
		OriginalMessage:        encodedRestoreReq,
		AdditionalFixedMessage: metadataBytes,
		Cosigners:              adminAddresses,
		CosignersThreshold:     s.walletBackup.AdminsThreshold,
	}
}

// buildVariableMessagesWithInvalidSignature creates messages with one invalid signature
func (s *keyDataProviderRestoreTestSetup) buildVariableMessagesWithInvalidSignature(
	t *testing.T,
	numProviders int,
	numAdmins int,
	invalidIndex int,
) ([]hexutil.Bytes, []common.Address) {
	t.Helper()

	variableMessages, signers := s.buildVariableMessages(t, numProviders, numAdmins)

	// Corrupt the signature of the share at invalidIndex
	if invalidIndex < len(variableMessages) {
		// Decrypt, corrupt signature, re-encrypt
		var share *pkgbackup.KeySplit

		if invalidIndex < numProviders {
			var err error
			share, err = pkgbackup.DecryptSplit(s.walletBackup.ProviderEncryptedParts.Splits[invalidIndex], s.voterPrivKeys[invalidIndex])
			require.NoError(t, err)
		} else {
			adminIndex := invalidIndex - numProviders
			var err error
			share, err = pkgbackup.DecryptSplit(s.walletBackup.AdminEncryptedParts.Splits[adminIndex], s.adminPrivKeys[adminIndex])
			require.NoError(t, err)
		}

		// Corrupt the signature
		share.Signature[0] ^= 0xFF
		share.Signature[1] ^= 0xFF

		shareBytes, err := json.Marshal(share)
		require.NoError(t, err)
		cipher, err := ecies.Encrypt(rand.Reader, s.eciesPub, shareBytes, nil, nil)
		require.NoError(t, err)
		variableMessages[invalidIndex] = cipher
	}

	return variableMessages, signers
}

func TestKeyDataProviderRestore(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	// Use all providers (6) and all admins (3)
	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))

	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	resp, status, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, status)

	proof, err := wallets.ExtractKeyExistence(resp, setup.teeID)
	require.NoError(t, err)
	require.Equal(t, [32]byte(setup.walletID), proof.WalletId)
	require.Equal(t, setup.keyID, proof.KeyId)
	require.True(t, proof.Restored)
	require.Equal(t, big.NewInt(int64(setup.nonce)).Uint64(), proof.Nonce.Uint64())

	var restoreStatus wallets.KeyDataProviderRestoreResultStatus
	require.NoError(t, json.Unmarshal(status, &restoreStatus))
	require.Empty(t, restoreStatus.ErrorLogs)
	require.Empty(t, restoreStatus.ErrorPositions)

	idPair := wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID}
	restoredWallet, err := setup.wStorage.Get(idPair)
	require.NoError(t, err)
	require.True(t, restoredWallet.Restored)
	nonce, err := setup.wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, setup.nonce, nonce)

	resp, endStatus, err := setup.processor.KeyDataProviderRestore(types.End, restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Equal(t, status, endStatus)
}

func TestKeyDataProviderRestoreAdminThresholdNotMet(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), setup.adminThreshold-1)

	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.True(t, err.Error() == "admin threshold not reached")
}

func TestKeyDataProviderRestoreProviderThresholdNotMet(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	weightAccum := 0
	numProvidersUnderThreshold := 0
	for i := range setup.weights {
		weightAccum += int(setup.weights[i])
		numProvidersUnderThreshold++
		if weightAccum >= int(backup.DataProvidersThreshold) {
			break
		}
	}

	// ? What if numProvidersUnderThreshold == 0 ?

	variableMessages, signers := setup.buildVariableMessages(t, numProvidersUnderThreshold, len(setup.adminPrivKeys))

	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "threshold of shares is not reached")
}

func TestKeyDataProviderRestoreWalletAlreadyExists(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	// First, restore the wallet successfully
	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))
	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)

	// Try to restore the same wallet again
	_, _, err = setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wallet with given wallet-key id already exists")
}

func TestKeyDataProviderRestoreWalletDoesNotExistEndPhase(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	// Build restore instruction but don't execute Threshold phase
	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))
	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	// Try to call End phase without having called Threshold phase first
	_, _, err := setup.processor.KeyDataProviderRestore(types.End, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "wallet does not exists")
}

func TestKeyDataProviderRestoreInvalidSignatureOnKeySplitEnoughValidShares(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	// Invlaidate the first provider's signature
	variableMessages, signers := setup.buildVariableMessagesWithInvalidSignature(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys), 0)

	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	resp, status, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)

	// The function should succeed, but should track the error in status
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, status)

	var restoreStatus wallets.KeyDataProviderRestoreResultStatus
	require.NoError(t, json.Unmarshal(status, &restoreStatus))
	// Should have exactly one error logged (for the invalid signature at position 0)
	require.Len(t, restoreStatus.ErrorLogs, 1)
	require.Len(t, restoreStatus.ErrorPositions, 1)
	require.Contains(t, restoreStatus.ErrorPositions, 0)
	// The error should be logged (could be signature verification or recovery failure)
	require.NotEmpty(t, restoreStatus.ErrorLogs[0])

	// Verify wallet was successfully restored
	idPair := wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID}
	restoredWallet, err := setup.wStorage.Get(idPair)
	require.NoError(t, err)
	require.True(t, restoredWallet.Restored)
}

func TestKeyDataProviderRestoreInvalidSignatureOnKeySplitNotEnoughValidShares(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	weightAccum := 0
	minProvidersNeeded := 0
	for i := range setup.weights {
		weightAccum += int(setup.weights[i])
		minProvidersNeeded++
		if weightAccum >= int(backup.DataProvidersThreshold) {
			break
		}
	}

	// Use minimum + 1 providers and all admins, then invalidate the LAST provider's signature
	// This ensures after removing the invalid one, we have SOME shares but NOT enough to meet threshold
	numProvidersToUse := min(minProvidersNeeded+1, len(setup.voterPrivKeys))

	// Invalidate the last provider (so we still have minProvidersNeeded-1 valid providers, which is below threshold)
	variableMessages, signers := setup.buildVariableMessagesWithInvalidSignature(t, numProvidersToUse, len(setup.adminPrivKeys), numProvidersToUse-1)

	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)

	// The function should fail because we don't have enough valid shares after removing the invalid one
	require.Error(t, err)
	require.True(t,
		strings.Contains(err.Error(), "threshold") ||
			strings.Contains(err.Error(), "shares"),
		"Expected threshold or shares error, got: %s", err.Error())

	// Verify wallet was NOT restored
	idPair := wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID}
	exists := setup.wStorage.WalletExists(idPair)
	require.False(t, exists)
}

func TestKeyDataProviderRestorePublicKeyMismatch(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	// Build messages first with valid backup
	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))

	// Now corrupt the public key in the backup metadata (after building messages)
	originalPublicKey := setup.walletBackup.PublicKey
	corruptedPublicKey := make([]byte, len(originalPublicKey))
	copy(corruptedPublicKey, originalPublicKey)
	// Flip some bits to corrupt it
	corruptedPublicKey[0] ^= 0xFF
	corruptedPublicKey[1] ^= 0xFF
	setup.walletBackup.PublicKey = corruptedPublicKey

	// Manually build instruction with corrupted metadata
	backupID := setup.walletBackup.WalletBackupID
	restoreReq := cwallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeePublicKey: cwallet.PublicKey{X: setup.testNode.Info().PublicKey.X, Y: setup.testNode.Info().PublicKey.Y},
		BackupId: cwallet.ITeeWalletBackupManagerBackupId{
			TeeId:         backupID.TeeID,
			WalletId:      backupID.WalletID,
			KeyId:         backupID.KeyID,
			KeyType:       [32]byte(backupID.KeyType),
			SigningAlgo:   [32]byte(backupID.SigningAlgo),
			PublicKey:     backupID.PublicKey,
			RewardEpochId: backupID.RewardEpochID,
			RandomNonce:   backupID.RandomNonce,
		},
		BackupUrl: "https://example.com/backup",
		Nonce:     big.NewInt(int64(setup.nonce)),
	}

	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	// Corrupting the metadata public key causes validation errors during key reconstruction
	// The error could be "shares should not be empty", "private key reconstruction error", or similar
	require.True(t,
		err.Error() == "shares should not be empty" ||
			err.Error() == "private key reconstruction error: final result does not match address" ||
			strings.Contains(err.Error(), "reconstruction") ||
			strings.Contains(err.Error(), "shares"),
		"Expected reconstruction or validation error, got: %s", err.Error())
}

func TestKeyDataProviderRestoreDuplicateKeySplits(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))

	// Duplicate the first provider's message
	variableMessages = append(variableMessages, variableMessages[0])
	signers = append(signers, signers[0])

	restoreReq := setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce)))
	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	// Should succeed but log an error about duplicate
	_, status, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)

	require.NotNil(t, status)
	var restoreStatus wallets.KeyDataProviderRestoreResultStatus
	require.NoError(t, json.Unmarshal(status, &restoreStatus))

	// Should have at least one error about duplicate
	require.NotEmpty(t, restoreStatus.ErrorLogs)
	require.NotEmpty(t, restoreStatus.ErrorPositions)

	// One of the errors should mention "duplicate"
	foundDuplicate := false
	for _, errLog := range restoreStatus.ErrorLogs {
		if strings.Contains(errLog, "duplicate") {
			foundDuplicate = true
			break
		}
	}

	require.True(t, foundDuplicate, "Expected duplicate error in logs")
}

func TestKeyDataProviderRestoreDecryptionFailure(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))
	// Corrupt the first provider's message
	for i := range 10 {
		variableMessages[0][i] ^= 0xFF
	}

	restoreReq := setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce)))
	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	_, status, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)

	require.NoError(t, err)

	// should track the decryption error
	require.NotNil(t, status)
	var restoreStatus wallets.KeyDataProviderRestoreResultStatus
	require.NoError(t, json.Unmarshal(status, &restoreStatus))
	require.NotEmpty(t, restoreStatus.ErrorLogs)
	require.NotEmpty(t, restoreStatus.ErrorPositions)
	require.Contains(t, restoreStatus.ErrorPositions, 0)
}

func TestKeyDataProviderRestoreUnauthorizedSigner(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	// Build normal admin messages
	_, adminSigners := setup.buildVariableMessages(t, 0, len(setup.adminPrivKeys))

	// Create unauthorized signers (not in voter set and not admins)
	unauthorizedPrivKeys := make([]*ecdsa.PrivateKey, 3)
	unauthorizedSigners := make([]common.Address, 3)
	variableMessages := make([]hexutil.Bytes, 3)

	for i := range 3 {
		var err error
		unauthorizedPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		unauthorizedSigners[i] = crypto.PubkeyToAddress(unauthorizedPrivKeys[i].PublicKey)

		// Create some dummy encrypted message
		dummyData := []byte("unauthorized data")
		cipher, err := ecies.Encrypt(rand.Reader, setup.eciesPub, dummyData, nil, nil)
		require.NoError(t, err)
		variableMessages[i] = cipher
	}

	// Add admin signers
	variableMessages = append(variableMessages, make([]hexutil.Bytes, len(adminSigners))...)
	copy(variableMessages[3:], make([]hexutil.Bytes, len(adminSigners)))
	unauthorizedSigners = append(unauthorizedSigners, adminSigners...)

	restoreReq := setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce)))
	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, unauthorizedSigners, nil)
	require.Error(t, err)
	require.Equal(t, err.Error(), "signed by an entity that is nether a provider nor an admin")
}

func TestKeyDataProviderRestoreInvalidBackupIdTeeID(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))

	// Create restore request with invalid TEE ID
	restoreReq := setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce)))
	restoreReq.BackupId.TeeId = common.HexToAddress("0x1234567890123456789012345678901234567890")

	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.Equal(t, err.Error(), "wallet ids do not match")
}

func TestKeyDataProviderRestoreInvalidTeeID(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))

	// Generator point (not the valid TEE Public Key)
	gx := secp256k1.S256().Gx.Bytes()
	gy := secp256k1.S256().Gy.Bytes()

	// Create restore request with invalid TEE ID
	backupID := setup.walletBackup.WalletBackupID
	restoreReq := cwallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeePublicKey: cwallet.PublicKey{X: [32]byte(gx), Y: [32]byte(gy)},
		BackupId: cwallet.ITeeWalletBackupManagerBackupId{
			TeeId:         backupID.TeeID,
			WalletId:      backupID.WalletID,
			KeyId:         backupID.KeyID,
			KeyType:       [32]byte(backupID.KeyType),
			SigningAlgo:   [32]byte(backupID.SigningAlgo),
			PublicKey:     backupID.PublicKey,
			RewardEpochId: backupID.RewardEpochID,
			RandomNonce:   backupID.RandomNonce,
		},
		BackupUrl: "https://example.com/backup",
		Nonce:     big.NewInt(int64(setup.nonce)),
	}

	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.Equal(t, err.Error(), "teeID does not match given public key")
}

func TestKeyDataProviderRestoreUnsupportedSigningAlgorithm(t *testing.T) {
	setup := setupKeyDataProviderRestoreTest(t)

	variableMessages, signers := setup.buildVariableMessages(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys))

	// Create restore request with unsupported signing algorithm
	restoreReq := setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce)))
	restoreReq.BackupId.SigningAlgo = utils.ToHash("BLS-12-381")

	restoreInstruction := setup.buildRestoreInstruction(t, restoreReq)

	_, _, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signing algorithm not supported")
}

func TestKeyDataProviderRestoreWithProviderAsAdmin(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	const (
		numVoters = 6
		randSeed  = int64(4242)
		epochID   = uint32(11)
	)

	numAdmins := 3
	initialPolicy, adminPrivKeys, voterPrivKeys := setupAdminsAndProviders(t, numAdmins, pStorage, numVoters, randSeed, epochID)

	// Make the first provider an admin
	adminPrivKeys[0] = voterPrivKeys[0]

	setup := setupKeyDataProviderRestoreTestWithAdminsAndProviders(t, numAdmins, adminPrivKeys, voterPrivKeys, testNode, pStorage, wStorage, epochID, initialPolicy)

	// Use all providers (6) and all admins (3)
	isAdminAndProvider := make([]bool, len(setup.voterPrivKeys))
	isAdminAndProvider[0] = true
	variableMessages, signers := setup.buildVariableMessagesWithAdmins(t, len(setup.voterPrivKeys), len(setup.adminPrivKeys), isAdminAndProvider)

	restoreInstruction := setup.buildRestoreInstruction(t, setup.buildDefaultRestoreRequest(big.NewInt(int64(setup.nonce))))

	resp, status, err := setup.processor.KeyDataProviderRestore(types.Threshold, restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, status)

	proof, err := wallets.ExtractKeyExistence(resp, setup.teeID)
	require.NoError(t, err)
	require.Equal(t, [32]byte(setup.walletID), proof.WalletId)
	require.Equal(t, setup.keyID, proof.KeyId)
	require.True(t, proof.Restored)
	require.Equal(t, big.NewInt(int64(setup.nonce)).Uint64(), proof.Nonce.Uint64())

	var restoreStatus wallets.KeyDataProviderRestoreResultStatus
	require.NoError(t, json.Unmarshal(status, &restoreStatus))
	require.Empty(t, restoreStatus.ErrorLogs)
	require.Empty(t, restoreStatus.ErrorPositions)

	idPair := wallets.KeyIDPair{WalletID: setup.walletID, KeyID: setup.keyID}
	restoredWallet, err := setup.wStorage.Get(idPair)
	require.NoError(t, err)
	require.True(t, restoredWallet.Restored)
	nonce, err := setup.wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, setup.nonce, nonce)

	resp, endStatus, err := setup.processor.KeyDataProviderRestore(types.End, restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Equal(t, status, endStatus)
}
