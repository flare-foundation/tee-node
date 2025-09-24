package backup

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"

	"github.com/flare-foundation/tee-node/pkg/wallets"
	"github.com/flare-foundation/tee-node/pkg/wallets/backup"

	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

const NormalizationConstant = 1000
const DataProvidersThreshold = uint64(666)

// BackupWallet packages the wallet state and encrypted key shares for admins
// and providers so it can be reconstructed later. The result is signed with the
// key that is split, but remains to be signed by the TEE.
func BackupWallet(wallet *wallets.Wallet, providerPubKeys []*ecdsa.PublicKey, signingPolicyWeights []uint16, rewardEpochId uint32, teeID common.Address, normalizationParam uint16, dataProviderThreshold uint64) (*backup.WalletBackup, error) {
	adminPubKeys := make([]types.PublicKey, len(wallet.AdminPublicKeys))
	for i, pubKey := range wallet.AdminPublicKeys {
		adminPubKeys[i] = types.PubKeyToStruct(pubKey)
	}
	normalizedWeights := weightsNormalization(signingPolicyWeights, normalizationParam)
	randomNonce, err := utils.GenerateRandom()
	if err != nil {
		return nil, err
	}

	metaData := backup.WalletBackupMetaData{
		WalletBackupID: wallets.WalletBackupID{
			TeeID:         teeID,
			WalletID:      wallet.WalletID,
			KeyID:         wallet.KeyID,
			PublicKey:     types.PubKeyToStruct(&wallet.PrivateKey.PublicKey),
			KeyType:       wallet.KeyType,
			SigningAlgo:   wallet.SigningAlgo,
			RewardEpochID: rewardEpochId,
			RandomNonce:   randomNonce,
		},
		AdminsPublicKeys:   adminPubKeys,
		AdminsThreshold:    wallet.AdminsThreshold,
		ProvidersThreshold: dataProviderThreshold,
		Cosigners:          make([]common.Address, len(wallet.Cosigners)),
		CosignersThreshold: wallet.CosignersThreshold,
	}
	copy(metaData.Cosigners, wallet.Cosigners)

	splitKey, err := SplitPrivateKey(wallet.PrivateKey, 2)
	if err != nil {
		return nil, err
	}

	weightsOne := utils.ConstantSlice(uint16(1), len(wallet.AdminPublicKeys))
	adminEncryptedParts, err := SplitAndEncrypt(splitKey[0], wallet.AdminPublicKeys, wallet.AdminsThreshold, weightsOne, metaData.WalletBackupID, wallet.PrivateKey, true)
	if err != nil {
		return nil, err
	}

	providerEncryptedParts, err := SplitAndEncrypt(splitKey[1], providerPubKeys, dataProviderThreshold, normalizedWeights, metaData.WalletBackupID, wallet.PrivateKey, false)
	if err != nil {
		return nil, err
	}

	walletBackup := &backup.WalletBackup{
		WalletBackupMetaData:   metaData,
		AdminEncryptedParts:    adminEncryptedParts,
		ProviderEncryptedParts: providerEncryptedParts,
	}

	hash, err := walletBackup.HashForSigning()
	if err != nil {
		return nil, err
	}
	walletBackup.Signature, err = utils.Sign(hash[:], wallet.PrivateKey)
	if err != nil {
		return nil, err
	}

	return walletBackup, nil
}

func weightsNormalization(weights []uint16, total uint16) []uint16 {
	sum := uint16(0)
	for _, weight := range weights {
		sum += weight
	}

	normalizedWeights := make([]uint16, len(weights))

	for i, weight := range weights {
		normalizedWeight := uint16((uint64(weight) * uint64(total) / uint64(sum)))
		sum -= weight
		total -= normalizedWeight
		normalizedWeights[i] = normalizedWeight
	}

	return normalizedWeights
}

// SplitAndEncrypt shards the provided private key, encrypts each share for its
// owner, and returns the encoded share bundle.
func SplitAndEncrypt(
	key *ecdsa.PrivateKey,
	encryptionPubKeys []*ecdsa.PublicKey,
	threshold uint64,
	weights []uint16,
	backupID wallets.WalletBackupID,
	sigPrivKey *ecdsa.PrivateKey,
	isAdmin bool,
) (*backup.EncryptedShares, error) {
	if len(encryptionPubKeys) != len(weights) {
		return nil, errors.New("number of encryption keys and weights do not match")
	}

	var numSplits = len(encryptionPubKeys)

	encryptionPubKeysApi := make([]types.PublicKey, numSplits)
	for i, pubKey := range encryptionPubKeys {
		encryptionPubKeysApi[i] = types.PubKeyToStruct(pubKey)
	}
	encryptedShares := backup.EncryptedShares{
		Splits:           make([]hexutil.Bytes, numSplits),
		OwnersPublicKeys: encryptionPubKeysApi,
		Threshold:        threshold,
		PublicKey:        types.PubKeyToStruct(&key.PublicKey),
		Weights:          make([]uint16, numSplits),
	}
	copy(encryptedShares.Weights, weights)

	numShares := uint64(utils.Sum(weights))
	shamirShares, err := SplitToShamirShares(key.D, numShares, threshold)
	if err != nil {
		return nil, err
	}

	weightCounter := 0
	partialBackupID := backup.PartialWalletBackupID{
		WalletBackupID: backupID, PartialPubKey: encryptedShares.PublicKey, IsAdmin: isAdmin,
	}
	for i := range numSplits {
		keySplitData := backup.KeySplitData{
			Shares:                shamirShares[weightCounter : weightCounter+int(weights[i])],
			PartialWalletBackupID: partialBackupID,
			OwnerPublicKey:        types.PubKeyToStruct(encryptionPubKeys[i]),
		}
		sig, err := keySplitData.Sign(sigPrivKey)
		if err != nil {
			return nil, err
		}

		keySplit := backup.KeySplit{KeySplitData: keySplitData, Signature: sig}

		plaintext, err := json.Marshal(keySplit)
		if err != nil {
			return nil, err
		}

		pubKey := ecies.ImportECDSAPublic(encryptionPubKeys[i])
		cipher, err := ecies.Encrypt(rand.Reader, pubKey, plaintext, nil, nil)
		if err != nil {
			return nil, err
		}

		encryptedShares.Splits[i] = cipher
		weightCounter += int(weights[i])
	}

	return &encryptedShares, nil
}

// RecoverWallet rebuilds a wallet from key shares and backup metadata.
func RecoverWallet(
	keyShares []*backup.KeySplit,
	backupMetaData *backup.WalletBackupMetaData,
) (*wallets.Wallet, error) {
	providerKeyShares := make([]*backup.KeySplit, 0)
	adminKeyShares := make([]*backup.KeySplit, 0)
	for _, keySplit := range keyShares {
		if keySplit.IsAdmin {
			adminKeyShares = append(adminKeyShares, keySplit)
		} else {
			providerKeyShares = append(providerKeyShares, keySplit)
		}
	}

	err := CheckKeyShares(adminKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	adminKey, err := JoinKeyShares(adminKeyShares, backupMetaData.AdminsThreshold)
	if err != nil {
		return nil, err
	}

	err = CheckKeyShares(providerKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	providerKey, err := JoinKeyShares(providerKeyShares, backupMetaData.ProvidersThreshold)
	if err != nil {
		return nil, err
	}

	key, err := JoinPrivateKeys([]*ecdsa.PrivateKey{adminKey, providerKey})
	if err != nil {
		return nil, err
	}

	if types.PubKeyToStruct(&key.PublicKey) != backupMetaData.PublicKey {
		return nil, errors.New("private key reconstruction error: final result does not match address")
	}

	adminsPubKeys := make([]*ecdsa.PublicKey, len(backupMetaData.AdminsPublicKeys))
	for i, pubKey := range backupMetaData.AdminsPublicKeys {
		adminsPubKeys[i], err = types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
	}

	return &wallets.Wallet{
		WalletID:    backupMetaData.WalletID,
		KeyID:       backupMetaData.KeyID,
		PrivateKey:  key,
		Address:     crypto.PubkeyToAddress(key.PublicKey),
		KeyType:     backupMetaData.KeyType,
		SigningAlgo: backupMetaData.SigningAlgo,
		Restored:    true,

		AdminPublicKeys:    adminsPubKeys,
		AdminsThreshold:    backupMetaData.AdminsThreshold,
		Cosigners:          backupMetaData.Cosigners,
		CosignersThreshold: backupMetaData.CosignersThreshold,

		SettingsVersion: common.Hash{},
		Settings:        hexutil.Bytes{},

		Status: &wallets.WalletStatus{Nonce: 0, StatusCode: 0},
	}, nil
}

// CheckKeyShares validates that the provided key shares belong to the expected
// wallet backup metadata and originate from authorized parties.
func CheckKeyShares(splits []*backup.KeySplit, backupMetaData *backup.WalletBackupMetaData) error {
	if len(splits) == 0 {
		return errors.New("shares should not be empty")
	}
	partialBackupId := splits[0].PartialWalletBackupID
	for _, split := range splits {
		if split.PartialWalletBackupID != partialBackupId {
			return errors.New("one of key split's ids does not match expected id")
		}

		if split.IsAdmin {
			if !slices.Contains(backupMetaData.AdminsPublicKeys, split.OwnerPublicKey) {
				return errors.New("one of admins public keys is not in the backup metadata")
			}
		}
	}

	if partialBackupId.WalletBackupID != backupMetaData.WalletBackupID {
		return errors.New("backup metadata's id does not match expected id")
	}

	return nil
}

// JoinKeyShares joins key shares in a private key. It assumes that all the
// splits have the same backup id and the signatures have been verified.
func JoinKeyShares(splits []*backup.KeySplit, threshold uint64) (*ecdsa.PrivateKey, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold should be positive")
	}

	shares := make([]backup.ShamirShare, 0)
	for _, split := range splits {
		shares = append(shares, split.Shares...)
	}

	if uint64(len(shares)) < threshold {
		return nil, errors.New("threshold of shares is not reached")
	}
	shares = shares[:threshold]

	privateKeyBigInt, err := CombineShamirShares(shares)
	if err != nil {
		return nil, err
	}
	privateKey := crypto.ToECDSAUnsafe(privateKeyBigInt.Bytes())
	expectedPartialPublicKey := splits[0].PartialPubKey // at this point splits is checked to not be empty
	if types.PubKeyToStruct(&privateKey.PublicKey) != expectedPartialPublicKey {
		return nil, err
	}

	return privateKey, nil
}
