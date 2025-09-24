package walletutils_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/flare-foundation/tee-node/internal/processors/instructions/walletutils"
	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/internal/wallets/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
	"github.com/flare-foundation/tee-node/pkg/wallets"
	pkgbackup "github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/op"
	cwallet "github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/stretchr/testify/require"
)

func TestKeyGenerate(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)

	teeId := testNode.TeeID()
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

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, _, err = testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochId)
	require.NoError(t, err)

	originalMessage := cwallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:       teeId,
		WalletId:    walletId,
		KeyId:       keyId,
		KeyType:     wallets.XRPType,
		SigningAlgo: wallets.XRPAlgo,
		ConfigConstants: cwallet.ITeeWalletKeyManagerKeyConfigConstants{
			AdminsPublicKeys:   adminWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0),
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{cwallet.MessageArguments[op.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	instructionId, err := utils.GenerateRandom()
	require.NoError(t, err)
	instructionDataFixed := instruction.DataFixed{
		InstructionID:          instructionId,
		TeeID:                  teeId,
		RewardEpochID:          epochId,
		OPType:                 op.Wallet.Hash(),
		OPCommand:              op.KeyGenerate.Hash(),
		OriginalMessage:        originalMessageEncoded,
		AdditionalFixedMessage: nil,
	}

	p := walletutils.NewProcessor(
		testNode,
		pStorage,
		wStorage,
	)

	response, _, err := p.KeyGenerate(types.Threshold, &instructionDataFixed, nil, nil, nil)
	if err != nil {
		t.Fatalf("Failed to sign the payment transaction: %v", err)
	}

	walletExistenceProof, err := wallets.ExtractKeyExistence(response)
	require.NoError(t, err)

	require.Equal(t, teeId, walletExistenceProof.TeeId)
	require.Equal(t, [32]byte(walletId), walletExistenceProof.WalletId)
	require.Equal(t, keyId, walletExistenceProof.KeyId)
	// todo: check response

	allWallets := wStorage.GetWallets()
	require.Len(t, allWallets, 1)
}

func TestKeyDelete(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	walletID := common.HexToHash("0xdeadbeef")
	var keyID uint64 = 7

	numVoters, randSeed, epochID := 50, int64(6789), uint32(3)
	_, _, _, err := testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochID)
	require.NoError(t, err)

	adminPrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, epochID, []*ecdsa.PrivateKey{adminPrivKey}, nil)

	processor := walletutils.NewProcessor(testNode, pStorage, wStorage)

	deleteReq := cwallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    testNode.TeeID(),
		WalletId: walletID,
		KeyId:    keyID,
		Nonce:    big.NewInt(1),
	}

	encodedDeleteReq, err := abi.Arguments{cwallet.MessageArguments[op.KeyDelete]}.Pack(deleteReq)
	require.NoError(t, err)

	instructionID, err := utils.GenerateRandom()
	require.NoError(t, err)

	deleteInstruction := instruction.DataFixed{
		InstructionID:   instructionID,
		TeeID:           testNode.TeeID(),
		RewardEpochID:   epochID,
		OPType:          op.Wallet.Hash(),
		OPCommand:       op.KeyDelete.Hash(),
		OriginalMessage: encodedDeleteReq,
	}

	resp, status, err := processor.KeyDelete(types.Threshold, &deleteInstruction, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Nil(t, status)

	idPair := wallets.KeyIDPair{WalletID: walletID, KeyID: keyID}
	require.False(t, wStorage.WalletExists(idPair))

	nonce, err := wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(1), nonce)

	resp, status, err = processor.KeyDelete(types.End, &deleteInstruction, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Nil(t, status)
}

func TestKeyDataProviderRestore(t *testing.T) {
	testNode, pStorage, wStorage := testutils.Setup(t)

	const (
		numVoters = 6
		randSeed  = int64(4242)
		epochID   = uint32(11)
	)

	initialPolicy, _, voterPrivKeys, err := testutils.GenerateAndSetInitialPolicy(pStorage, numVoters, randSeed, epochID)
	require.NoError(t, err)

	adminPrivKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	walletID := common.HexToHash("0xbeadfeed")
	var keyID uint64 = 3

	storedWalletProof := testutils.CreateMockWallet(t, testNode, pStorage, wStorage, walletID, keyID, epochID, []*ecdsa.PrivateKey{adminPrivKey}, []*ecdsa.PrivateKey{voterPrivKeys[0]})

	idPair := wallets.KeyIDPair{WalletID: walletID, KeyID: keyID}
	storedWallet, err := wStorage.Get(idPair)
	require.NoError(t, err)

	// Simulate wallet removal prior to restore.
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

	weightAccum := 0
	variableMessages := make([]hexutil.Bytes, 0)
	signers := make([]common.Address, 0)

	for i := range voterPrivKeys {
		weightAccum += int(weights[i])
		share, decErr := pkgbackup.DecryptSplit(walletBackup.ProviderEncryptedParts.Splits[i], voterPrivKeys[i])
		require.NoError(t, decErr)
		shareBytes, marshalErr := json.Marshal(share)
		require.NoError(t, marshalErr)
		cipher, encErr := ecies.Encrypt(rand.Reader, eciesPub, shareBytes, nil, nil)
		require.NoError(t, encErr)
		variableMessages = append(variableMessages, cipher)
		signers = append(signers, crypto.PubkeyToAddress(voterPrivKeys[i].PublicKey))
	}
	require.GreaterOrEqual(t, weightAccum, int(backup.DataProvidersThreshold))

	adminShare, err := pkgbackup.DecryptSplit(walletBackup.AdminEncryptedParts.Splits[0], adminPrivKey)
	require.NoError(t, err)
	adminShareBytes, err := json.Marshal(adminShare)
	require.NoError(t, err)
	cipher, encErr := ecies.Encrypt(rand.Reader, eciesPub, adminShareBytes, nil, nil)
	require.NoError(t, encErr)
	variableMessages = append(variableMessages, cipher)
	adminAddress := crypto.PubkeyToAddress(adminPrivKey.PublicKey)
	signers = append(signers, adminAddress)

	metadataBytes, err := json.Marshal(walletBackup.WalletBackupMetaData)
	require.NoError(t, err)

	backupID := walletBackup.WalletBackupID
	pubKeyBytes := make([]byte, 64)
	copy(pubKeyBytes[:32], backupID.PublicKey.X[:])
	copy(pubKeyBytes[32:], backupID.PublicKey.Y[:])

	restoreReq := cwallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeePublicKey: cwallet.PublicKey{X: testNode.Info().PublicKey.X, Y: testNode.Info().PublicKey.Y},
		BackupId: cwallet.ITeeWalletBackupManagerBackupId{
			TeeId:         backupID.TeeID,
			WalletId:      backupID.WalletID,
			KeyId:         backupID.KeyID,
			KeyType:       [32]byte(backupID.KeyType),
			SigningAlgo:   [32]byte(backupID.SigningAlgo),
			PublicKey:     pubKeyBytes,
			RewardEpochId: new(big.Int).SetUint64(uint64(backupID.RewardEpochID)),
			RandomNonce:   new(big.Int).SetBytes(backupID.RandomNonce[:]),
		},
		BackupUrl: "https://example.com/backup",
		Nonce:     big.NewInt(2),
	}

	encodedRestoreReq, err := abi.Arguments{cwallet.MessageArguments[op.KeyDataProviderRestore]}.Pack(restoreReq)
	require.NoError(t, err)

	instructionID, err := utils.GenerateRandom()
	require.NoError(t, err)

	restoreInstruction := instruction.DataFixed{
		InstructionID:          instructionID,
		TeeID:                  testNode.TeeID(),
		RewardEpochID:          epochID,
		OPType:                 op.Wallet.Hash(),
		OPCommand:              op.KeyDataProviderRestore.Hash(),
		OriginalMessage:        encodedRestoreReq,
		AdditionalFixedMessage: hexutil.Bytes(metadataBytes),
		Cosigners:              []common.Address{adminAddress},
		CosignersThreshold:     1,
	}

	processor := walletutils.NewProcessor(testNode, pStorage, wStorage)

	resp, status, err := processor.KeyDataProviderRestore(types.Threshold, &restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, status)

	proof, err := wallets.ExtractKeyExistence(resp)
	require.NoError(t, err)
	require.Equal(t, [32]byte(walletID), proof.WalletId)
	require.Equal(t, keyID, proof.KeyId)
	require.True(t, proof.Restored)
	require.Equal(t, big.NewInt(2).Uint64(), proof.Nonce.Uint64())
	storedWalletProof.Restored = true
	storedWalletProof.Nonce = big.NewInt(2)
	require.Equal(t, storedWalletProof, *proof)

	var restoreStatus wallets.KeyDataProviderRestoreResultStatus
	require.NoError(t, json.Unmarshal(status, &restoreStatus))
	require.Empty(t, restoreStatus.ErrorLogs)
	require.Empty(t, restoreStatus.ErrorPositions)

	restoredWallet, err := wStorage.Get(idPair)
	require.NoError(t, err)
	require.True(t, restoredWallet.Restored)
	nonce, err := wStorage.Nonce(idPair)
	require.NoError(t, err)
	require.Equal(t, uint64(2), nonce)

	resp, endStatus, err := processor.KeyDataProviderRestore(types.End, &restoreInstruction, variableMessages, signers, nil)
	require.NoError(t, err)
	require.Nil(t, resp)
	require.Equal(t, status, endStatus)
}
